# jsonl-archive: design notes

> **Status: design notes, not implemented yet.** This connector does not exist. These notes were
> moved out of `docs/connectors.md`, which is the contract every connector follows, so that the
> contract stays short. They become this connector's README when it is built (rollout step 3 in
> that document).

`jsonl-archive` is the first reference connector: an **archive** (`docs/connectors.md`, section 2)
that writes batches as write-once local files, using only the standard library.

## Write-once objects

The contract rules are in `docs/connectors.md`, section 4.1: each object is named
`<first_order>-<last_order>-<first 16 hex of sha256(batch_id)>-<sha256 of the object's bytes>`, and
a connector must never overwrite an existing object. This is how this connector does it for local
files:

- **Local files:** write the complete bytes to a temporary file in the same folder, flush and
  `fsync` it, then publish it with a create-only atomic step (`os.link` to the final name, which
  fails if the name exists), remove the temporary file, and then `fsync` the containing folder
  so the new name survives a crash. Only after that does `write` report success. A failed write
  therefore never leaves a partial object under the final name. On macOS, plain `fsync` does
  not force the drive's cache to permanent storage, so every sync above uses
  `fcntl(fd, F_FULLFSYNC)` there instead. A sync failure is handled by its cause:
  - **Not supported** (for example `ENOTSUP` or `EINVAL` from `F_FULLFSYNC` on a network or
    FUSE file system): this will never succeed, so it is never retried. The connector checks
    for it once in `open()` by running every sync step it will use later on a test file in the
    archive folder (the file sync, `F_FULLFSYNC` on macOS, and the folder sync), and raises
    `ConnectorConfigError` (exit `2`) unless the operator chose
    `--connector-option NAME.durability=best-effort`. In that mode the connector uses plain
    `fsync` (or no folder sync where none exists), logs once at open that objects may not
    survive a power loss, and reports success after the steps it can do. If a "not supported"
    error still appears later in `write` (for example the folder was remounted), the connector
    raises `ConnectorDisabled` there instead: the importer disables that connector for the rest
    of the run, shows the message, counts its waiting batches as undelivered, exits `2` with
    `--once`, and retries nothing in a loop (`docs/connectors.md`, section 5).
  - **Temporary** (for example `EINTR`, `EAGAIN`, `ENOSPC`, or an I/O error on a device that
    may come back): `write` does not report success; it raises `ConnectorUnavailable` and the
    batch is retried with the usual backoff.

  Platforms that cannot sync a folder at all, such as Windows, need `durability=best-effort`,
  and the connector's documentation says so.
- **Object stores:** use a conditional put ("only if absent").
- **Name already exists:** read the existing object and check that its SHA-256 matches the name
  and the intended bytes, and (for local files) sync the containing folder as above, since an
  earlier attempt may have failed at exactly that step. Only then is the write a no-op success.
  If that sync fails, the write raises `ConnectorUnavailable` and is retried. A hash mismatch
  means the existing object is damaged: it is left untouched and the batch is reported as
  `ConnectorRejected`, so `--once` exits `2`.
