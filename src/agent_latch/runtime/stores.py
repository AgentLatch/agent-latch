"""Optional event stores: keep the sealed events somewhere other than a local SQLite file.

A store package registers an entry point in the group ``agent_latch.stores``. Nothing is discovered,
imported or opened unless the operator names a store with ``--store TYPE`` on ``import-logs``,
``verify``, ``anchor`` or ``audit-tool``. This module is standard library only and imports no store
package. ``--database FILE`` (the built-in SQLite store) does not go through here and is unchanged.

A store is a drop-in replacement for ``--database``: the importer, ``verify``, ``anchor`` and
``audit-tool`` run the same code on it as on SQLite. That only works if the store keeps the same
promises, which ``docs/stores.md`` lists and ``tests/store_contract.py`` checks:

- the writer implements the importer's ``EventWriter`` (a key saved again keeps the first write),
  seals every row with ``ledger.event_seal.next_seal`` inside the save, and provides
  ``event_seal.SealedSource`` plus ``head``, ``as_stored``, ``seals_after`` and ``seal_digest_at``;
- the reader provides the same read methods and has no way to change the store.

A store that cannot be used as configured raises ``StoreConfigError`` (exit 2) from its factory,
or ``ValueError`` from ``open``. A store that cannot be reached raises ``OSError`` from ``save``,
so the importer keeps the events waiting and retries, exactly as it does for ``--database``.
"""

from __future__ import annotations

import os
import re
from collections.abc import Callable, Iterator, Mapping, Sequence
from dataclasses import dataclass, field
from importlib.metadata import EntryPoint, entry_points
from pathlib import Path
from typing import Any, Protocol

from agent_latch import __version__

STORE_API = 1  # contract version a store declares; breaking changes bump it
ENTRY_POINT_GROUP = "agent_latch.stores"
_ENV_PREFIX = "env:"
_KEY = re.compile(r"[A-Za-z][A-Za-z0-9_]{0,63}")
MASK = "***"


class StoreConfigError(ValueError):
    """The store can never work as configured. The command exits 2 and shows the message."""


@dataclass(frozen=True)
class StoreContext:
    """What AgentLatch tells a store when it is created."""

    type: str  # the type the operator chose, for example "postgres"
    log_dir: Path | None  # the runtime-logs folder (import-logs only), for local state
    agentlatch_version: str
    store_api: int


class StoreBackend(Protocol):
    """What a store package's factory returns. Creating it does no input or output."""

    store_api: int
    # A short name for messages and anchor points, without secrets or a "/" (for example
    # "postgres-agentlatch.events"). Shown to the operator; never holds a password.
    name: str

    def writer(self) -> Any: ...  # the sealed EventWriter, for import-logs only

    def reader(self) -> Any: ...  # the read-only view, for verify, anchor and audit-tool


StoreFactory = Callable[[Mapping[str, str], StoreContext], StoreBackend]


def scrub(message: str, secrets: Sequence[str]) -> str:
    """Replace every secret value in ``message`` so a diagnostic cannot leak it."""
    for secret in sorted({s for s in secrets if s}, key=len, reverse=True):
        message = message.replace(secret, MASK)
    return message


# ---------------------------------------------------------------------------------------------
# Options: --store-option KEY=VALUE, with secrets written as env:VAR.


@dataclass(frozen=True)
class StoreOptions:
    options: dict[str, str] = field(repr=False)  # what the factory receives (secrets resolved)
    secrets: tuple[str, ...] = field(default=(), repr=False)


def parse_store_options(
    items: Sequence[str], environ: Mapping[str, str] | None = None
) -> StoreOptions:
    """Read ``KEY=VALUE`` pairs and resolve ``env:VAR`` values. Messages never repeat a value."""
    environ = os.environ if environ is None else environ
    options: dict[str, str] = {}
    secrets: list[str] = []
    for index, item in enumerate(items, start=1):
        origin = f"--store-option #{index}"
        key, sep, value = item.partition("=")
        key = key.strip()
        if not sep or not _KEY.fullmatch(key):
            raise StoreConfigError(f"{origin}: expected KEY=VALUE, for example dsn=env:PG_DSN")
        if value.startswith(_ENV_PREFIX):
            variable = value[len(_ENV_PREFIX):]
            if variable not in environ or environ[variable] == "":
                raise StoreConfigError(
                    f"{origin}: option {key!r} refers to the environment variable {variable!r},"
                    " which is not set; export it before starting"
                )
            value = environ[variable]
            secrets.append(value)
        options[key] = value
    return StoreOptions(options=options, secrets=tuple(secrets))


# ---------------------------------------------------------------------------------------------
# Discovery: entry points are listed without being imported; only the named one is loaded.


@dataclass(frozen=True)
class InstalledStore:
    type: str
    package: str
    version: str
    target: str  # "module:attribute", never imported by a listing


def _entry_points() -> list[EntryPoint]:
    return list(entry_points(group=ENTRY_POINT_GROUP))


def installed_stores() -> list[InstalledStore]:
    """List installed store types without importing any. Two packages with one type is an error."""
    found: dict[str, InstalledStore] = {}
    for entry in _entry_points():
        dist = getattr(entry, "dist", None)
        item = InstalledStore(
            type=entry.name,
            package=getattr(dist, "name", None) or "unknown package",
            version=getattr(dist, "version", None) or "unknown",
            target=entry.value,
        )
        if entry.name in found:
            raise StoreConfigError(
                f"store type {entry.name!r} is registered by two packages"
                f" ({found[entry.name].package} and {item.package}); uninstall one of them"
            )
        found[entry.name] = item
    return sorted(found.values(), key=lambda s: s.type)


@dataclass
class LoadedStore:
    """A created store plus what the command needs to report on it safely."""

    type: str
    package: str
    backend: StoreBackend
    secrets: tuple[str, ...] = field(default=(), repr=False)

    @property
    def name(self) -> str:
        return safe_name(self.backend)

    def scrub(self, message: str) -> str:
        return scrub(message, self.secrets)


def safe_name(backend: Any) -> str:
    """The backend's display name, usable as a file name in an anchor point."""
    raw = getattr(backend, "name", None)
    text = raw if isinstance(raw, str) and raw.strip() else "store"
    return text.strip().replace("/", "_").replace("\\", "_")


def load_store(
    store_type: str,
    option_items: Sequence[str],
    *,
    log_dir: Path | None = None,
    environ: Mapping[str, str] | None = None,
) -> LoadedStore:
    """Create the named store, or raise ``StoreConfigError`` before anything opens."""
    store_type = store_type.strip()
    resolved = parse_store_options(option_items, environ)
    installed = {item.type: item for item in installed_stores()}
    entries = {entry.name: entry for entry in _entry_points()}
    found = entries.get(store_type)
    if found is None:
        available = ", ".join(sorted(installed)) or "none installed"
        raise StoreConfigError(
            f"no installed store of type {store_type!r} (installed: {available}). Install its"
            " package, or check the type with `agent-latch-runtime stores`"
        )
    package = installed[store_type].package
    try:
        factory = found.load()
    except Exception as error:  # noqa: BLE001 - a broken package is not a bug in AgentLatch
        raise StoreConfigError(
            f"store {store_type!r}: package {package} could not be loaded"
            f" ({type(error).__name__}); reinstall or upgrade it"
        ) from None
    context = StoreContext(
        type=store_type, log_dir=log_dir, agentlatch_version=__version__, store_api=STORE_API
    )
    try:
        backend = factory(dict(resolved.options), context)
    except StoreConfigError as error:
        raise StoreConfigError(
            f"store {store_type!r}: {scrub(str(error), resolved.secrets)}"
        ) from None
    except Exception as error:  # noqa: BLE001 - store code is third party
        raise StoreConfigError(
            f"store {store_type!r} failed while it was created ({type(error).__name__});"
            f" package {package}. Options given: "
            + (", ".join(f"{key}={MASK}" for key in sorted(resolved.options)) or "(no options)")
        ) from None
    declared = getattr(backend, "store_api", None)
    if declared != STORE_API:
        side = (
            "upgrade AgentLatch"
            if isinstance(declared, int) and declared > STORE_API
            else f"upgrade {package}"
        )
        raise StoreConfigError(
            f"store {store_type!r} was written for store API {declared!r}; this AgentLatch"
            f" supports {STORE_API}. To fix it, {side}"
        )
    return LoadedStore(
        type=store_type, package=package, backend=backend, secrets=resolved.secrets
    )


# ---------------------------------------------------------------------------------------------
# Readers without SQL: the newest events for audit-tool, from the sealed rows.


def recent_from_rows(rows: Iterator[Any], limit: int) -> list[dict[str, Any]]:
    """The newest ``limit`` rows as ``{timestamp, name, stage, seal_seq}``, newest first."""
    from collections import deque

    newest: deque[dict[str, Any]] = deque(maxlen=max(1, limit))
    for row in rows:
        event = row.event
        newest.append(
            {
                "timestamp": event.get("timestamp"),
                "name": event.get("name"),
                "stage": event.get("stage"),
                "seal_seq": row.seal.seq if row.seal is not None else None,
            }
        )
    return list(reversed(newest))


__all__ = [
    "ENTRY_POINT_GROUP",
    "STORE_API",
    "InstalledStore",
    "LoadedStore",
    "StoreBackend",
    "StoreConfigError",
    "StoreContext",
    "StoreFactory",
    "StoreOptions",
    "installed_stores",
    "load_store",
    "parse_store_options",
    "recent_from_rows",
    "safe_name",
    "scrub",
]
