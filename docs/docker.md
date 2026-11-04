# Container images

AgentLatch ships as two container images, built from the [`Dockerfile`](../Dockerfile) in the repository root:

| Image | Command inside | Use it for |
|---|---|---|
| `ghcr.io/agentlatch/agent-latch` | `agent-latch` | Static scans of a project, locally or in any CI system |
| `ghcr.io/agentlatch/agent-latch-runtime` | `agent-latch-runtime` | The MCP runtime proxy (preview), `import-logs`, `verify`, `anchor` and `demo` |

Replace `<version>` below with a release number. Images are published from GitHub releases, starting after v0.5.0. Until the first one is published, build them yourself (next section).

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

[`.github/workflows/images.yml`](../.github/workflows/images.yml) builds and smoke-tests both images on every pull request that can affect them. Publishing to GHCR runs on a published GitHub release (tags `X.Y.Z`, `X.Y` and `latest`), or on a manual run (tag `sha-<commit>`; pick a release tag as the ref to publish that version). It builds `linux/amd64` and `linux/arm64`, and checks that the release tag matches both version files, as the PyPI workflow does. After the first publish, make each package public in the organization's package settings.

The dependency locks are regenerated with [uv](https://docs.astral.sh/uv/):

```sh
scripts/update-docker-locks.sh
```

Run it after changing dependencies in `pyproject.toml`. Dependabot proposes weekly updates for the base image digest, the workflow actions and the locked packages.
