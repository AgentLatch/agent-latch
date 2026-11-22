"""Optional connectors: send normalized runtime events to a destination the operator names.

A connector is a separate package that registers an entry point in the group
``agent_latch.connectors``. Nothing is discovered, imported or sent unless the operator selects
a connector with ``--connector`` (see ``docs/connectors.md``). This module is standard library
only. It holds the contract, the configuration rules and the per-connector delivery state, and it
imports no connector package.

The importer's existing ``--database`` store does not go through here.
"""

from __future__ import annotations

import copy
import json
import logging
import os
import re
import time
import tomllib
from collections import deque
from collections.abc import Callable, Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime
from importlib.metadata import EntryPoint, entry_points
from pathlib import Path
from typing import Any, Literal, Protocol

from agent_latch import __version__

log = logging.getLogger("agent_latch.runtime")

CONNECTOR_API = 1  # contract version a connector declares; breaking changes bump it
ENTRY_POINT_GROUP = "agent_latch.connectors"
BATCH_SCHEMA = "agentlatch.runtime.batch/1"
EVENT_SCHEMA = "agentlatch.runtime.event/1"

DEFAULT_MAX_BATCH_EVENTS = 500
DEFAULT_MAX_PENDING_BATCHES = 100
DEFAULT_TIMEOUT_SECONDS = 10.0
BACKOFF_START_SECONDS = 1.0
BACKOFF_MAX_SECONDS = 60.0

# Options the core reads itself. ``payloads``, ``max_batch_events`` and ``max_pending_batches`` are
# never passed on; ``timeout`` is validated here and passed on, because the connector enforces it.
CORE_OPTIONS = ("payloads", "max_batch_events", "max_pending_batches", "timeout")
_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9_-]{0,31}")
_ENV_PREFIX = "env:"
MASK = "***"

ConnectorKind = Literal["store", "exporter", "archive"]


class ConnectorConfigError(ValueError):
    """The connector can never work as configured. The importer exits 2 and shows the message."""


class ConnectorUnavailable(OSError):
    """A temporary failure (network, lock, rate limit, disk). The batch is kept and retried."""


class ConnectorRejected(Exception):
    """The destination refused this batch for good. It is saved locally and not retried."""


class ConnectorDisabled(Exception):
    """The connector must stop for the rest of the run, for a reason the operator should read."""


class ConnectorDeliveryError(OSError):
    """With ``--once``: some events were not delivered, were rejected or were dropped."""


@dataclass(frozen=True)
class ConnectorContext:
    """What AgentLatch tells a connector when it is created."""

    name: str  # the name the operator chose, for example "pg"
    log_dir: Path  # the runtime-logs folder, for any local state the connector needs
    agentlatch_version: str
    connector_api: int


@dataclass(frozen=True)
class EventBatch:
    """Events handed to ``write``. A retry sends an identical batch with the same ``batch_id``."""

    schema: str
    event_schema: str
    batch_id: str
    run_id: str
    created_at: str
    events: tuple[dict[str, Any], ...]

    def as_dict(self) -> dict[str, Any]:
        return {
            "schema": self.schema,
            "event_schema": self.event_schema,
            "batch_id": self.batch_id,
            "run_id": self.run_id,
            "created_at": self.created_at,
            "events": [dict(event) for event in self.events],
        }


class Connector(Protocol):
    """A destination for normalized events."""

    kind: ConnectorKind
    connector_api: int
    path: Path | None  # a local file it writes, or None (checked against the other outputs)
    accepts_payloads: bool  # set by the core from the operator's ``payloads`` option

    def open(self) -> None: ...

    def write(self, batch: EventBatch, /) -> int: ...

    def close(self) -> None: ...


ConnectorFactory = Callable[[Mapping[str, str], ConnectorContext], Connector]


# ---------------------------------------------------------------------------------------------
# Secrets: nothing the operator typed as an option value is ever printed.


def scrub(message: str, secrets: Iterable[str]) -> str:
    """Replace every secret value in ``message`` so a diagnostic cannot leak it."""
    for secret in sorted({s for s in secrets if s}, key=len, reverse=True):
        message = message.replace(secret, MASK)
    return message


def masked(options: Mapping[str, str]) -> str:
    """Option keys with every value hidden, for example ``dsn=***, table=***``."""
    return ", ".join(f"{key}={MASK}" for key in sorted(options)) or "(no options)"


# ---------------------------------------------------------------------------------------------
# Configuration: what the operator selected and set, from the command line or their own file.


@dataclass(frozen=True)
class ConnectorSettings:
    """One selected connector: its name, its type and its options as strings."""

    name: str
    type: str
    options: Mapping[str, str] = field(default_factory=dict, repr=False)  # may hold secrets


def _check_name(name: str, origin: str) -> str:
    if not _NAME.fullmatch(name):
        raise ConnectorConfigError(
            f"{origin}: connector name {name!r} is not valid; use letters, digits, '-' or '_'"
            " (at most 32 characters, starting with a letter or digit)"
        )
    return name


def parse_connector_settings(
    selections: Sequence[str],
    options: Sequence[str],
    config_file: Path | None = None,
) -> list[ConnectorSettings]:
    """Combine ``--connector``, ``--connector-option`` and ``--connector-config``.

    Every connector must be named: by ``--connector [NAME=]TYPE`` or by a ``[connectors.NAME]``
    table with a ``type`` in the file. Command-line options override the file. Error messages
    point at an argument by position and never repeat an option value.
    """
    table: dict[str, dict[str, str]] = {}  # name -> options (file first, then command line)
    types: dict[str, str] = {}
    order: list[str] = []

    if config_file is not None:
        for name, fields in _read_config_file(config_file).items():
            types[name] = fields.pop("type")
            table[name] = fields
            order.append(name)

    for index, selection in enumerate(selections, start=1):
        origin = f"--connector #{index}"
        name, sep, kind = selection.partition("=")
        if not sep:
            name, kind = selection, selection
        kind = kind.strip()
        if not kind:
            raise ConnectorConfigError(f"{origin}: expected [NAME=]TYPE, for example pg=postgres")
        name = _check_name(name.strip(), origin)
        if name not in types:
            order.append(name)
        types[name] = kind  # a command-line selection replaces the file's type for that name
        table.setdefault(name, {})

    for index, option in enumerate(options, start=1):
        origin = f"--connector-option #{index}"
        head, sep, value = option.partition("=")
        name, dot, key = head.partition(".")
        if not sep or not dot or not name or not key:
            raise ConnectorConfigError(f"{origin}: expected NAME.KEY=VALUE")
        if name not in types:
            raise ConnectorConfigError(
                f"{origin}: no connector named {name!r}; select it first with"
                f" --connector {name}=TYPE (or a [connectors.{name}] table in --connector-config)"
            )
        table[name][key] = value

    if not types:
        raise ConnectorConfigError(
            "no connector is selected; use --connector [NAME=]TYPE, or put [connectors.NAME]"
            " tables in --connector-config FILE"
        )
    return [ConnectorSettings(name, types[name], table[name]) for name in order]


def _read_config_file(path: Path) -> dict[str, dict[str, str]]:
    try:
        with path.open("rb") as handle:
            data = tomllib.load(handle)
    except FileNotFoundError:
        raise ConnectorConfigError(f"--connector-config: no file at {path}") from None
    except OSError as error:
        raise ConnectorConfigError(f"--connector-config: cannot read {path}: {error}") from error
    except tomllib.TOMLDecodeError as error:
        raise ConnectorConfigError(f"--connector-config: {path} is not valid TOML: {error}") from error
    section = data.get("connectors", {})
    if not isinstance(section, dict) or any(not isinstance(v, dict) for v in section.values()):
        raise ConnectorConfigError(
            f"--connector-config: {path} needs one table per connector, [connectors.NAME]"
        )
    result: dict[str, dict[str, str]] = {}
    for name, fields in section.items():
        _check_name(name, f"--connector-config {path}")
        if not isinstance(fields.get("type"), str) or not fields["type"].strip():
            raise ConnectorConfigError(
                f"--connector-config: [connectors.{name}] in {path} needs type = \"...\""
            )
        result[name] = {
            key: _as_text(value) for key, value in fields.items()
        }
        result[name]["type"] = fields["type"].strip()
    return result


def _as_text(value: Any) -> str:
    if isinstance(value, bool):
        return "true" if value else "false"
    return str(value)


@dataclass(frozen=True)
class ResolvedOptions:
    """The core's view of a connector's options after ``env:`` references are read."""

    options: dict[str, str]  # what the factory receives (secrets resolved)
    secrets: tuple[str, ...]  # every value that came from the environment, for scrubbing
    payloads: bool
    max_batch_events: int
    max_pending_batches: int


def resolve_options(settings: ConnectorSettings, environ: Mapping[str, str]) -> ResolvedOptions:
    """Read ``env:VAR`` values, split off the core's own options and validate them."""
    secrets: list[str] = []
    resolved: dict[str, str] = {}
    for key, value in settings.options.items():
        if value.startswith(_ENV_PREFIX):
            variable = value[len(_ENV_PREFIX):]
            if variable not in environ or environ[variable] == "":
                raise ConnectorConfigError(
                    f"connector {settings.name!r}: option {key!r} refers to the environment"
                    f" variable {variable!r}, which is not set; export it before starting"
                )
            value = environ[variable]
            secrets.append(value)
        resolved[key] = value

    def number(key: str, default: int) -> int:
        raw = resolved.pop(key, None)
        if raw is None:
            return default
        try:
            parsed = int(raw)
        except ValueError:
            parsed = 0
        if parsed < 1:
            raise ConnectorConfigError(
                f"connector {settings.name!r}: option {key!r} must be a whole number of at least 1"
            )
        return parsed

    payloads_raw = resolved.pop("payloads", "false").strip().lower()
    if payloads_raw not in ("true", "false"):
        raise ConnectorConfigError(
            f"connector {settings.name!r}: option 'payloads' must be true or false"
        )
    max_batch = number("max_batch_events", DEFAULT_MAX_BATCH_EVENTS)
    max_pending = number("max_pending_batches", DEFAULT_MAX_PENDING_BATCHES)
    if "timeout" in resolved:
        try:
            if float(resolved["timeout"]) <= 0:
                raise ValueError
        except ValueError:
            raise ConnectorConfigError(
                f"connector {settings.name!r}: option 'timeout' must be a number of seconds above 0"
            ) from None
    return ResolvedOptions(
        options=resolved,
        secrets=tuple(secrets),
        payloads=payloads_raw == "true",
        max_batch_events=max_batch,
        max_pending_batches=max_pending,
    )


# ---------------------------------------------------------------------------------------------
# Discovery: entry points are listed without being imported, and only selected ones are loaded.


@dataclass(frozen=True)
class InstalledConnector:
    type: str
    package: str
    version: str
    target: str  # "module:attribute", never imported by a listing


def _entry_points() -> list[EntryPoint]:
    return list(entry_points(group=ENTRY_POINT_GROUP))


def installed_connectors() -> list[InstalledConnector]:
    """List installed connector types without importing any of them. Two packages registering the
    same type is an error: the importer never picks one.
    """
    found: dict[str, InstalledConnector] = {}
    for entry in _entry_points():
        dist = getattr(entry, "dist", None)
        item = InstalledConnector(
            type=entry.name,
            package=getattr(dist, "name", None) or "unknown package",
            version=getattr(dist, "version", None) or "unknown",
            target=entry.value,
        )
        if entry.name in found:
            raise ConnectorConfigError(
                f"connector type {entry.name!r} is registered by two packages"
                f" ({found[entry.name].package} and {item.package}); uninstall one of them"
            )
        found[entry.name] = item
    return sorted(found.values(), key=lambda c: c.type)


def supported_api_versions() -> tuple[int, ...]:
    """The contract versions this core accepts: the current one and the one before it."""
    return tuple(v for v in (CONNECTOR_API - 1, CONNECTOR_API) if v >= 1)


@dataclass
class LoadedConnector:
    """A created connector plus the core's delivery settings for it."""

    name: str
    type: str
    connector: Connector
    max_batch_events: int = DEFAULT_MAX_BATCH_EVENTS
    max_pending_batches: int = DEFAULT_MAX_PENDING_BATCHES
    secrets: tuple[str, ...] = field(default=(), repr=False)


def load_connectors(
    settings: Sequence[ConnectorSettings],
    log_dir: Path,
    environ: Mapping[str, str] | None = None,
) -> list[LoadedConnector]:
    """Create every selected connector, or raise ``ConnectorConfigError`` before anything opens.

    This is the create step: the factory validates its options and does no input or output.
    """
    environ = os.environ if environ is None else environ
    installed = {item.type: item for item in installed_connectors()}
    entries = {entry.name: entry for entry in _entry_points()}
    loaded: list[LoadedConnector] = []
    for item in settings:
        found = entries.get(item.type)
        if found is None:
            available = ", ".join(sorted(installed)) or "none installed"
            raise ConnectorConfigError(
                f"connector {item.name!r}: no installed connector of type {item.type!r}"
                f" (installed: {available}). Install its package, or check the type with"
                " `agent-latch-runtime connectors`"
            )
        package = installed[item.type].package
        resolved = resolve_options(item, environ)
        try:
            factory = found.load()
        except Exception as error:  # noqa: BLE001 - a broken package is not a bug in AgentLatch
            raise ConnectorConfigError(
                f"connector {item.name!r}: package {package} could not be loaded"
                f" ({type(error).__name__}); reinstall or upgrade it"
            ) from None
        context = ConnectorContext(
            name=item.name,
            log_dir=log_dir,
            agentlatch_version=__version__,
            connector_api=CONNECTOR_API,
        )
        try:
            connector = factory(dict(resolved.options), context)
        except ConnectorConfigError as error:
            raise ConnectorConfigError(
                f"connector {item.name!r} ({item.type}): {scrub(str(error), resolved.secrets)}"
            ) from None
        except Exception as error:  # noqa: BLE001 - connector code is third party
            raise ConnectorConfigError(
                f"connector {item.name!r} ({item.type}) failed while it was created"
                f" ({type(error).__name__}); package {package}. Options given: "
                f"{masked(resolved.options)}"
            ) from None
        declared = getattr(connector, "connector_api", None)
        if declared not in supported_api_versions():
            side = "upgrade AgentLatch" if isinstance(declared, int) and declared > CONNECTOR_API \
                else f"upgrade {package}"
            raise ConnectorConfigError(
                f"connector {item.name!r} ({item.type}) was written for connector API {declared!r};"
                f" this AgentLatch supports {', '.join(map(str, supported_api_versions()))}."
                f" To fix it, {side}"
            )
        try:
            connector.accepts_payloads = resolved.payloads  # the operator's choice, never the package's
        except AttributeError:
            raise ConnectorConfigError(
                f"connector {item.name!r} ({item.type}) does not allow the 'payloads' setting to be"
                f" applied; upgrade {package}"
            ) from None
        loaded.append(
            LoadedConnector(
                name=item.name,
                type=item.type,
                connector=connector,
                max_batch_events=resolved.max_batch_events,
                max_pending_batches=resolved.max_pending_batches,
                secrets=resolved.secrets,
            )
        )
    return loaded


# ---------------------------------------------------------------------------------------------
# Delivery: one runner per connector, so one failing connector never holds back another.


def rejected_path_for(name: str, log_dir: Path) -> Path:
    """Where a connector's refused batches are saved. The importer includes it in its check that
    no two outputs are the same file.
    """
    return log_dir / f"{name}.rejected.jsonl"


def _now() -> str:
    stamp = datetime.now(UTC).isoformat(timespec="milliseconds")
    return stamp.replace("+00:00", "Z")


class ConnectorRunner:
    """Batches events for one connector and delivers them, keeping its own queue and backoff."""

    def __init__(self, loaded: LoadedConnector, log_dir: Path) -> None:
        self.loaded = loaded
        self.name = loaded.name
        self._connector = loaded.connector
        self._rejected_path = rejected_path_for(loaded.name, log_dir)
        # Optional: a connector that sets ``wants_seals = True`` receives each event only after the
        # store has sealed it, with an extra ``seal`` field ({seq, prev, digest}, or null).
        self.wants_seals = getattr(loaded.connector, "wants_seals", False) is True
        self._buffer: list[dict[str, Any]] = []  # events not yet in a batch
        self._queue: deque[EventBatch] = deque()  # frozen batches waiting for delivery
        self._open = False
        self._opened_once = False
        self._disabled = False
        self._failing = False
        self._attempts = 0
        self._next_attempt = 0.0
        self.delivered = 0
        self.rejected = 0
        self.dropped = 0
        self.close_failed = False

    # -- helpers ---------------------------------------------------------------------------
    def _warn(self, text: str) -> None:
        log.warning("agent-latch-runtime: connector %r: %s", self.name, scrub(text, self.loaded.secrets))

    @property
    def undelivered(self) -> int:
        return len(self._buffer) + sum(len(batch.events) for batch in self._queue)

    @property
    def has_problems(self) -> bool:
        return bool(self.undelivered or self.rejected or self.dropped or self.close_failed)

    # -- lifecycle -------------------------------------------------------------------------
    def open(self) -> None:
        """Open once. A configuration error stops the import; an unavailable one retries later."""
        if self._open or self._disabled:
            return
        try:
            self._connector.open()
        except ConnectorConfigError as error:
            raise ConnectorConfigError(
                f"connector {self.name!r}: {scrub(str(error), self.loaded.secrets)}"
            ) from None
        except ConnectorUnavailable as error:
            self._schedule_retry(time.monotonic())
            self._warn(f"not reachable yet ({error}); retrying")
            return
        except Exception as error:  # noqa: BLE001 - connector code is third party
            self._disable(f"failed to open ({type(error).__name__})")
            return
        self._open = self._opened_once = True
        self._attempts = 0

    def add(self, event: dict[str, Any]) -> None:
        """Take a private copy of an event. Payloads are removed unless the operator allowed them."""
        if self._disabled:
            self.dropped += 1  # never lost silently: --once reports it and exits 2
            return
        copied = copy.deepcopy(event)
        if not getattr(self._connector, "accepts_payloads", False):
            copied["payload"] = None
        self._buffer.append(copied)

    def deliver(self, *, final: bool) -> None:
        """Batch what has arrived, then write waiting batches. ``final`` ignores the backoff
        wait and tries each batch once.
        """
        self._make_batches()
        try:
            self._deliver(final=final)
        finally:
            self._enforce_cap()  # only what still has to wait after the write attempts

    def _deliver(self, *, final: bool) -> None:
        if self._disabled:
            return
        now = time.monotonic()
        if not self._open:
            if not (final or now >= self._next_attempt):
                return
            self.open()
            if not self._open:
                return
        while self._queue and (final or time.monotonic() >= self._next_attempt):
            batch = self._queue[0]
            try:
                self._connector.write(copy.deepcopy(batch))  # a retry must see an identical batch
            except ConnectorUnavailable as error:
                self._schedule_retry(time.monotonic())
                if not self._failing:
                    self._warn(f"{error}; retrying")
                    self._failing = True
                return
            except ConnectorRejected as error:
                if not self._reject(batch, str(error)):
                    return  # could not save it locally: the batch stays queued, undelivered
                continue
            except ConnectorDisabled as error:
                self._disable(str(error))
                return
            except Exception as error:  # noqa: BLE001 - connector code is third party
                self._disable(f"stopped after an unexpected error ({type(error).__name__})")
                return
            self._queue.popleft()
            self.delivered += len(batch.events)
            self._attempts = 0
            if self._failing:
                self._warn(f"reachable again; delivered {len(batch.events)} waiting event(s)")
                self._failing = False

    def close(self) -> None:
        """Close exactly once. A failure is a warning and counts as undelivered work."""
        try:
            self._connector.close()
        except Exception as error:  # noqa: BLE001 - connector code is third party
            if self._opened_once:
                self.close_failed = True
            self._warn(f"close failed ({type(error).__name__})")

    # -- internals -------------------------------------------------------------------------
    def _make_batches(self) -> None:
        if not self._buffer:
            return
        events, self._buffer = self._buffer, []
        by_run: dict[str, list[dict[str, Any]]] = {}
        for event in events:
            by_run.setdefault(str(event["run_id"]), []).append(event)
        for run_id, group in by_run.items():
            group.sort(key=lambda e: int(e["order"]))
            for start in range(0, len(group), self.loaded.max_batch_events):
                chunk = group[start : start + self.loaded.max_batch_events]
                self._queue.append(
                    EventBatch(
                        schema=BATCH_SCHEMA,
                        event_schema=EVENT_SCHEMA,
                        batch_id=f"{run_id}:{chunk[0]['order']}-{chunk[-1]['order']}",
                        run_id=run_id,
                        created_at=_now(),
                        events=tuple(chunk),
                    )
                )

    def _enforce_cap(self) -> None:
        """Drop the oldest waiting batches beyond ``max_pending_batches``, counting every event."""
        while len(self._queue) > self.loaded.max_pending_batches:
            dropped = self._queue.popleft()
            self.dropped += len(dropped.events)
            self._warn(
                f"waiting queue is full; dropped the oldest batch ({self.dropped} event(s) dropped"
                " so far). Run import-logs --once again once the destination is back"
            )

    def _schedule_retry(self, now: float) -> None:
        # The exponent is capped first: 2**1024 overflows a float long before min() could help.
        delay = min(BACKOFF_MAX_SECONDS, BACKOFF_START_SECONDS * (2 ** min(self._attempts, 16)))
        self._attempts = min(self._attempts + 1, 1_000)
        self._next_attempt = now + delay

    def _reject(self, batch: EventBatch, reason: str) -> bool:
        """Save a refused batch locally, then drop it from the queue. If it cannot be saved, keep
        it queued, stop this connector only, and let the final status report it as undelivered.
        """
        try:
            self._rejected_path.parent.mkdir(parents=True, exist_ok=True)
            fd = os.open(self._rejected_path, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
            with os.fdopen(fd, "a", encoding="utf-8") as handle:
                handle.write(json.dumps(batch.as_dict(), ensure_ascii=False) + "\n")
        except OSError as error:
            self._disable(
                f"the destination refused batch {batch.batch_id}, and it could not be saved to"
                f" {self._rejected_path} ({type(error).__name__})"
            )
            return False
        self._queue.popleft()
        self.rejected += len(batch.events)
        self._warn(
            f"destination refused batch {batch.batch_id} ({scrub(reason, self.loaded.secrets)});"
            f" saved to {self._rejected_path}"
        )
        return True

    def _disable(self, reason: str) -> None:
        self._disabled = True
        self._warn(f"{reason}; this connector is off for the rest of the run, other outputs continue")

    def summary(self) -> str:
        parts = [f"{self.delivered} delivered"]
        if self.undelivered:
            parts.append(f"{self.undelivered} undelivered")
        if self.rejected:
            parts.append(f"{self.rejected} rejected")
        if self.dropped:
            parts.append(f"{self.dropped} dropped")
        if self.close_failed:
            parts.append("close failed")
        return f"connector {self.name!r}: " + ", ".join(parts)


__all__ = [
    "BATCH_SCHEMA",
    "CONNECTOR_API",
    "ENTRY_POINT_GROUP",
    "EVENT_SCHEMA",
    "Connector",
    "ConnectorConfigError",
    "ConnectorContext",
    "ConnectorDeliveryError",
    "ConnectorDisabled",
    "ConnectorFactory",
    "ConnectorRejected",
    "ConnectorRunner",
    "ConnectorSettings",
    "ConnectorUnavailable",
    "EventBatch",
    "InstalledConnector",
    "LoadedConnector",
    "installed_connectors",
    "load_connectors",
    "masked",
    "parse_connector_settings",
    "rejected_path_for",
    "resolve_options",
    "scrub",
]
