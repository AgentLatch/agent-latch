# Container images

AgentLatch ships as two container images, built from the [`Dockerfile`](../Dockerfile) in the repository root:

| Image | Command inside | Use it for |
|---|---|---|
| `ghcr.io/agentlatch/agent-latch` | `agent-latch` | Static scans of a project, locally or in any CI system |
| `ghcr.io/agentlatch/agent-latch-runtime` | `agent-latch-runtime` | The MCP runtime proxy (preview), `import-logs`, `verify`, `anchor` and `demo` |

Replace `<version>` below with a release number. Images are published from GitHub releases, starting with v0.5.1. To try an unreleased commit, build the images yourself (next section).

New to Docker? [Setting up the container images](docker-setup.md) walks through installing Docker, getting the images, a first scan and connecting Claude Desktop, step by step.

How the images are built:

- **Pinned inputs.** The Python base image is pinned by digest. Python packages come from hash-pinned locks ([`docker/requirements-scanner.txt`](../docker/requirements-scanner.txt) and [`docker/requirements-runtime.txt`](../docker/requirements-runtime.txt)), installed as prebuilt wheels only, so no package's setup code runs during the build.
- **Small.** No compiler, no source tree, no git and no Node.js. The build stage that packages AgentLatch is thrown away.
- **Non-root.** Both images run as user `10001` (`latch`).
- **Verifiable.** Published images carry a signed build-provenance attestation and an SBOM (a list of every package inside).
- **No telemetry.** As with the Python package, scans stay local. The only network use is the opt-in `--dependencies` audit, and the proxy's connection to the MCP server you point it at.

## Build them yourself

```sh
docker build --target scanner -t agent-latch .
docker build --target runtime -t agent-latch-runtime .
```

The `.dockerignore` file is an allow-list: only `pyproject.toml`, `README.md`, `LICENSE`, `src/` and `docker/` go into the build. Recorded traffic in `runtime-logs/`, `.env` files and event databases can never end up in an image.

## Static scanner image

Mount the project read-only at `/src`. The scanned project is untrusted, so the container gets no write access to it:

```sh
docker run --rm -v "$PWD:/src:ro" ghcr.io/agentlatch/agent-latch:<version> scan . --fail-on high
```

To write a report, mount a second folder and run as your own user so you own the file:

```sh
docker run --rm --user "$(id -u):$(id -g)" -v "$PWD:/src:ro" -v "$PWD/out:/out" ghcr.io/agentlatch/agent-latch:<version> scan . --format sarif --output /out/agent-latch.sarif
```

Every `agent-latch` option works as usual (see [Getting started](getting-started.md)), and the exit codes are the same: `0` passed, `1` findings at or above `--fail-on`, `2` a scan or configuration error. `--project-ignores` still applies only when you pass it.

## Runtime image

The runtime image keeps its files in `/data`. Mount a folder or a named volume there, or the logs disappear with the container. Files are created with mode `0600`, as outside a container.

Try it without an app first. This records a synthetic MCP session through the proxy and imports it:

```sh
docker run --rm -v agentlatch-data:/data ghcr.io/agentlatch/agent-latch-runtime:<version> demo
```

### Connect an app (stdio)

The app starts the container as its MCP server. Messages travel over the container's standard input and output, which is why `-i` is required. The proxy never writes to standard output, so only MCP messages travel there. Its own notes go to standard error and the log files.

Example for a remote MCP server, in the app's MCP configuration:

```json
{
  "mcpServers": {
    "tools": {
      "command": "docker",
      "args": [
        "run", "-i", "--rm",
        "-v", "/home/me/agentlatch-data:/data",
        "ghcr.io/agentlatch/agent-latch-runtime:<version>",
        "proxy", "--name", "tools",
        "--trace", "/data/trace.jsonl", "--ledger", "/data/trace.ledger.jsonl",
        "--upstream-url", "https://tools.example.com/mcp"
      ]
    }
  }
}
```

| Part | What it does |
|---|---|
| `-i` | Keeps the container's input open; the app sends MCP messages through it |
| `--rm` | Removes the container when the app closes it |
| `-v /home/me/agentlatch-data:/data` | Keeps the logs on your machine after the container is removed |
| `proxy ... --upstream-url URL` | Passes every message to the real server and records it |

Then read the logs with a second container. `import-logs` only reads the proxy's files, so it never slows down or changes the traffic:

```sh
docker run --rm -v /home/me/agentlatch-data:/data ghcr.io/agentlatch/agent-latch-runtime:<version> import-logs --dir /data
docker run --rm -v /home/me/agentlatch-data:/data ghcr.io/agentlatch/agent-latch-runtime:<version> verify /data/trace.ledger.jsonl
```

`docker stop` ends a following `import-logs` cleanly: the images stop with `SIGINT`, which AgentLatch handles.

If the folder on your machine is not writable by user `10001`, add `--user "$(id -u):$(id -g)"` to the `docker run` arguments. Docker passes no environment variables from your machine into the container unless you name them with `-e NAME`.

### Keep the audit store out of the agent's reach

A sealed store detects a change; only keeping the agent away from the file prevents one. The
recommended picture is three separate places:

1. **The agent's container.** It holds the agent and nothing of AgentLatch: no store, no anchor, no
   Docker socket. Run it as a normal user: `--user 10001:10001 --cap-drop=ALL --security-opt
   no-new-privileges --read-only --tmpfs /tmp --pids-limit 256`. Never use `--privileged`, never mount
   `/var/run/docker.sock`, never mount the store's volume into it, and keep `sudo` out of the image.
2. **The AgentLatch container.** The proxy, `import-logs`, the ledger and the store, with `/data` in its
   own **named volume**, which lives inside Docker's storage where the agent has no path to it. The
   anchor goes in a **second** volume, so a container that mounts only the store cannot reach it. A new
   volume is owned by root, so give the anchor volume to the image's user once:

   ```sh
   docker volume create agentlatch-data && docker volume create agentlatch-anchor
   docker run --rm -u root --entrypoint chown -v agentlatch-anchor:/anchor \
     ghcr.io/agentlatch/agent-latch-runtime:<version> 10001:10001 /anchor
   docker run --rm -v agentlatch-data:/data -v agentlatch-anchor:/anchor \
     ghcr.io/agentlatch/agent-latch-runtime:<version> \
     import-logs --dir runtime-logs/demo --database /data/audit.db \
     --anchor /anchor/store-anchors.jsonl --once --quiet
   docker run --rm -v agentlatch-data:/data:ro -v agentlatch-anchor:/anchor:ro \
     ghcr.io/agentlatch/agent-latch-runtime:<version> \
     verify --database /data/audit.db --anchor /anchor/store-anchors.jsonl
   ```

   Both files are then owned by user `10001` with mode `0600`. The test in
   `docs/audit-trail-dev/06-docker-test.md` checks that user `10002` is denied read, write, `chmod` and
   delete access, even with both volumes mounted read-write. To rely on these permissions, do not give
   another container user `10001` or privileges that bypass file permissions: a root container with
   enough capabilities can change the files.

   **Give the agent a tool, not a path.** `agent-latch-runtime audit-tool --database /data/audit.db` is an
   MCP server (stdio) with two tools, `query_audit_log` and `recent_events`, that holds only a read-only
   reader. Start it in its own container with the store mounted read-only and nothing else:

   ```sh
   docker run -i --rm --network none --read-only --cap-drop=ALL --security-opt no-new-privileges \
     -v agentlatch-data:/data:ro ghcr.io/agentlatch/agent-latch-runtime:<version> \
     audit-tool --database /data/audit.db
   ```

   The agent's app launches that command as its MCP server (`-i` is required). Every write the agent
   tries through it, even raw SQL, is refused.

   **Never give the agent Docker.** An agent that can run `docker` can mount the volume as root. The
   seals and the anchor detect what it changes only while the anchor is out of its reach: if it can
   also rewrite the anchor, nothing detects it, and nothing stops it changing the store. Keep the
   anchor off that machine or in write-once storage. Do not mount
   `/var/run/docker.sock` into the agent's container, and do not give a shell tool to an agent whose
   host user can use Docker.

   **A protected anchor does not vouch for rows it has not covered yet.** The importer rebuilds rows
   past the newest anchor point from the trace and payload files and keeps them if they match, so an
   agent that can change the store *and* those files can get a forged row accepted. Keep the trace
   and payload files out of the agent's reach too, not only the store.

3. **The anchor.** Outside both: another host, a mounted share the agent cannot write, or write-once
   storage. An agent that can also write the anchor makes tampering undetectable.

Three settings need care:

- Keep `/data` in a **named volume** (`-v agentlatch-data:/data`). A host folder mounted there can show
  up as owned by the person running the agent, and then the agent can change it. Whether Docker Desktop
  does this is not something the tests prove (CI runs on Linux): check it by hand with `ls -ln` on the
  mounted folder and with a second user.
- Do **not** add `--user "$(id -u):$(id -g)"` to the store's container: that runs it as the agent's own user.
- `--http` is not how an agent connects across containers, because it accepts only a loopback address.
  Use stdio (`docker run -i`), or a sidecar that shares the agent's network (`--network container:<agent>`).

Containers share the host kernel; for very sensitive data a separate machine or VM is stronger. Without
containers, run the agent as a separate non-administrator OS user.

### Limits

**The upstream server must be reachable from inside the container.** With `--upstream-url`, the proxy connects over the network, and this works for any server. With `proxy -- COMMAND`, the proxy starts the server *inside the container*, so the command must exist there:

- The image holds Python and AgentLatch only. It contains **no Node.js**, so `npx` servers cannot start in it. This is deliberate: every extra runtime adds code that needs security updates, and a security tool's image should hold as little as possible.
- Python servers installed into the image would share AgentLatch's packages and can clash with FastMCP, the same reason [runtime.md](runtime.md#install) says to keep servers out of AgentLatch's environment.

For a local server (Node.js or anything else), use one of these:

1. **Run the server in its own container** that serves MCP over HTTP, and point the proxy at it with `--upstream-url`. Each piece keeps its own dependencies. This is the recommended setup.
2. **Build your own image on top of ours** that adds what the server needs. You then own the updates for what you added:

   ```dockerfile
   FROM ghcr.io/agentlatch/agent-latch-runtime:<version>
   USER root
   RUN apt-get update && apt-get install -y --no-install-recommends nodejs npm \
    && rm -rf /var/lib/apt/lists/*
   USER 10001:10001
   ```

   Pin the server version in the app's arguments, for example `npx -y @scope/server@1.2.3`, never `@latest`.

**HTTP mode is limited to the container itself.** `proxy --http HOST:PORT` accepts only a loopback address such as `127.0.0.1`, because the preview listener has no authentication. Inside a container, loopback means the container itself, so publishing the port with `-p` does not reach it. To use HTTP mode, run the proxy next to the agent in the same network namespace: the same Kubernetes pod (a sidecar), or `docker run --network container:<agent-container>`. Do not work around the check; anyone who could reach the port could use your tools.

**The proxy records only, as outside a container.** It never blocks a call. See [runtime.md](runtime.md#limits).

## Use the scanner image in CI

Any CI system that runs containers can use the scanner image. A GitLab CI example:

```yaml
agent-latch:
  image:
    name: ghcr.io/agentlatch/agent-latch:<version>
    entrypoint: [""]
  script:
    - agent-latch scan --fail-on high --plain
    - agent-latch scan --format sarif --output agent-latch.sarif
  artifacts:
    when: always
    paths: [agent-latch.sarif]
```

On GitHub, the [GitHub Action](ci.md#github-actions) remains the simplest option: it also uploads results to code scanning and writes a job summary.

## Verify an image

Published images are attested by this repository's release workflow. With the GitHub CLI:

```sh
gh attestation verify oci://ghcr.io/agentlatch/agent-latch:<version> --owner AgentLatch
```

For a fixed deployment, refer to the image by digest (`ghcr.io/agentlatch/agent-latch@sha256:...`) rather than by tag.

## Publishing (maintainers)

[`.github/workflows/images.yml`](../.github/workflows/images.yml) builds and smoke-tests both images on every pull request that can affect them. Publishing to GHCR runs on a published GitHub release (tags `X.Y.Z`, `X.Y` and `latest`), or on a manual run (tag `sha-<commit>`; pick a release tag as the ref to publish that version). It builds `linux/amd64` and `linux/arm64`, reuses the layers the test job already built and tested (amd64), runs each pushed image by digest on both platforms before attesting it, and checks that the release tag matches both version files, as the PyPI workflow does. After the first publish, make each package public in the organization's package settings.

The dependency locks are regenerated with [uv](https://docs.astral.sh/uv/):

```sh
scripts/update-docker-locks.sh
```

Run it after changing dependencies in `pyproject.toml`. Dependabot proposes weekly updates for the base image digest, the workflow actions and the locked packages.
