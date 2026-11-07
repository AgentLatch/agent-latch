# Setting up the container images

This is the hands-on guide: from a machine without Docker to a scanned project and a recorded MCP
session in Claude Desktop, in about fifteen minutes. For the full reference (every option, the
limits, CI and publishing), see [Container images](docker.md).

You do not need Python. Everything runs inside the two images:

| Image | Command inside | What it does |
|---|---|---|
| `agent-latch` | `agent-latch` | Static scan of an agent project |
| `agent-latch-runtime` | `agent-latch-runtime` | Records the MCP traffic between an app and its tools (preview) |

## Before you start

| You need | Why |
|---|---|
| Docker Desktop (macOS, Windows) or Docker Engine (Linux) | Runs the images |
| About 1 GB of free disk space | The images are about 270 MB and 340 MB, and building them also keeps a build cache |
| `git`, only if you build the images yourself | Images are published from GitHub releases, starting with v0.5.1. You only build them yourself for an unreleased commit (Step 2) |

## Step 1 — Install Docker

**macOS**

1. Check which chip your Mac has: run `uname -m`. `arm64` means Apple Silicon (M1 and later), `x86_64` means Intel.
2. Download Docker Desktop for that chip from [docker.com](https://www.docker.com/products/docker-desktop/).
3. Open the downloaded `Docker.dmg` and drag **Docker** into **Applications**.
4. Open Docker from Applications. Accept the agreement and finish the setup screens. The recommended settings ask for your Mac password once.
5. Wait until the whale icon in the menu bar stops moving. Docker is then running.

**Windows:** install Docker Desktop with the WSL 2 backend, following [Docker's guide](https://docs.docker.com/desktop/setup/install/windows-install/).

**Linux:** install Docker Engine for your distribution, following [Docker's guide](https://docs.docker.com/engine/install/). To run `docker` without `sudo`, follow the post-install steps there.

Docker Desktop is free for personal use, education and small businesses. Larger organizations need a paid Docker subscription; check Docker's terms. Docker Engine on Linux is free.

Check that Docker works. Open a **new** terminal window first: the installer changes your `PATH`, and terminals that were already open do not see the change.

```sh
docker version --format '{{.Server.Version}}'
```

Expect a version number, such as `29.9.2`.

If you see `docker: command not found` on a Mac, Docker Desktop may have put its commands in
`~/.docker/bin`, which is not on your `PATH`. Add it and open a new terminal:

```sh
echo 'export PATH="$PATH:$HOME/.docker/bin"' >> ~/.zprofile
```

If you see `Cannot connect to the Docker daemon`, Docker Desktop is not running. Open it and wait for the whale icon to stop moving.

## Step 2 — Get the images

Pick one option. Both end with images named `agent-latch` and `agent-latch-runtime`, which the rest
of this guide uses.

**Option A: build them from this repository.** Use this until images are published.

```sh
git clone https://github.com/AgentLatch/agent-latch.git
cd agent-latch
docker build --target scanner -t agent-latch .
docker build --target runtime -t agent-latch-runtime .
```

The first build downloads the Python base image and takes a few minutes. Later builds reuse it.
Docker builds for your own machine: `arm64` on Apple Silicon, `amd64` on most other computers.

**Option B: download a published release.** Replace `<version>` with a release number, such as `0.6.0`:

```sh
docker pull ghcr.io/agentlatch/agent-latch:<version>
docker pull ghcr.io/agentlatch/agent-latch-runtime:<version>
docker tag ghcr.io/agentlatch/agent-latch:<version> agent-latch
docker tag ghcr.io/agentlatch/agent-latch-runtime:<version> agent-latch-runtime
```

`docker tag` only gives the downloaded images the short names; nothing is copied. To check that an
image really came from this repository's release workflow, see [Verify an image](docker.md#verify-an-image).

Check both images:

```sh
docker run --rm agent-latch --version
docker run --rm agent-latch-runtime --version
```

Expect `agent-latch` and `agent-latch-runtime`, each followed by the same version number.

## Step 3 — Scan a project

Go to the folder of the project you want to scan, then run:

```sh
docker run --rm -v "$PWD:/src:ro" agent-latch scan . --fail-on high
```

| Part | What it does |
|---|---|
| `--rm` | Removes the container when the scan ends |
| `-v "$PWD:/src:ro"` | Shows the current folder to the scanner at `/src`, **read-only**: the scanner cannot change your project |
| `scan . --fail-on high` | Scans `/src` and exits `1` if there is a finding of high severity or above |

The exit code tells a script or CI job what happened: `0` passed, `1` findings at or above
`--fail-on`, `2` a scan or configuration error.

To see findings without a project of your own, scan the deliberately insecure demo from the
`agent-latch` folder. It reports findings and exits `1`:

```sh
docker run --rm -v "$PWD/examples/vulnerable-agent:/src:ro" agent-latch scan . --fail-on high
```

To save a report, mount a second, writable folder at `/out`. `--user` makes the file yours instead
of the container user's:

```sh
mkdir -p out
docker run --rm --user "$(id -u):$(id -g)" -v "$PWD:/src:ro" -v "$PWD/out:/out" agent-latch scan . --format sarif --output /out/agent-latch.sarif
```

On Windows, write `${PWD}` instead of `$PWD` in PowerShell, or `%cd%` in Command Prompt, and leave
out the `--user` part.

Every `agent-latch` option works in the container. See [Getting started](getting-started.md).

## Step 4 — Try the runtime proxy

This runs a synthetic MCP session through the proxy and checks it, with no app and no setup:

```sh
docker run --rm -v agentlatch-data:/data agent-latch-runtime demo
```

Expect about ten lines such as `#2 demo-server: tools/call get_weather (city)`, ending with
`demo: files in runtime-logs/demo: trace.jsonl, payloads.jsonl, ...`.

`-v agentlatch-data:/data` keeps the files in a Docker volume named `agentlatch-data`. Without a
volume or folder at `/data`, they disappear with the container.

## Step 5 — Connect Claude Desktop

Claude Desktop starts the runtime image as one of its MCP servers. The proxy passes every message
to the real server and records it. This step uses the synthetic demo server from Step 4, so you can
see it work before you put a real server behind the proxy. Other MCP apps take the same `command`
and `args`.

1. Find the full path of `docker`. Apps opened from the Dock or Start menu do not read your
   terminal's `PATH`, so the bare word `docker` may not be found:

   ```sh
   which docker
   ```

   On Windows, use `where docker`.

2. Make a folder for the logs:

   ```sh
   mkdir -p ~/agentlatch-data
   ```

3. In Claude Desktop, open **Settings → Developer → Edit Config**. This opens
   `claude_desktop_config.json` (on macOS, in `~/Library/Application Support/Claude/`; on Windows,
   in `%APPDATA%\Claude\`).

4. Add this server. If the file already has an `mcpServers` section, add only the
   `"agentlatch-demo"` entry inside it. Replace `/usr/local/bin/docker` with the path from item 1,
   and `/Users/you` with your home folder:

   ```json
   {
     "mcpServers": {
       "agentlatch-demo": {
         "command": "/usr/local/bin/docker",
         "args": [
           "run", "-i", "--rm",
           "-v", "/Users/you/agentlatch-data:/data",
           "agent-latch-runtime",
           "proxy", "--name", "agentlatch-demo",
           "--trace", "/data/trace.jsonl",
           "--ledger", "/data/trace.ledger.jsonl",
           "--payloads", "/data/payloads.jsonl",
           "--", "python", "-m", "agent_latch.runtime.demo_server"
         ]
       }
     }
   }
   ```

   | Part | What it does |
   |---|---|
   | `-i` | Keeps the container's input open. Claude Desktop sends MCP messages through it, so it is required |
   | `-v /Users/you/agentlatch-data:/data` | Keeps the logs in your folder after the container is removed |
   | `--trace`, `--ledger` | Record every message, and seal the records so edits and deletions can be detected |
   | `--payloads` | Also record the arguments, results and tool definitions, so the checks can read them. This file holds what your tools send and receive; treat it as sensitive |
   | `-- python -m ...demo_server` | The server behind the proxy. Here, the synthetic demo server inside the image |

5. Quit Claude Desktop completely and open it again.

6. In a new chat, ask *"What is the weather in Paris?"*. Claude calls the demo server's
   `get_weather` tool through the proxy. The demo server also has tools that misbehave on purpose,
   so the checks have something to find. Do not give it real data.

7. Read what was recorded. `--once` processes the files and exits:

   ```sh
   docker run --rm -v "$HOME/agentlatch-data:/data" agent-latch-runtime import-logs --dir /data --once
   docker run --rm -v "$HOME/agentlatch-data:/data" agent-latch-runtime verify /data/trace.ledger.jsonl
   ```

   `import-logs` prints one line per message and what the checks found. `verify` prints
   `AUDIT TRAIL UNANCHORED — N record(s) verify locally` and exits `0`: the records are intact,
   and nothing outside your machine has been set up to prove it yet. To add that proof, see
   [Setting up the audit ledger](ledger-setup.md).

**Put a real server behind the proxy.** For a remote server, replace `"--"` and everything after it
with `"--upstream-url", "https://your-server/mcp"`, and rename `agentlatch-demo` in both places.
A server command after `"--"` runs inside the container, and the image contains Python and
AgentLatch only, **no Node.js**, so `npx` servers cannot start there. For those, see
[Limits](docker.md#limits).

## Step 6 — Update or remove

To update, build again (Option A, after `git pull`) or pull and tag a newer release (Option B).

To remove everything this guide created:

```sh
docker rmi agent-latch agent-latch-runtime
docker volume rm agentlatch-data
```

Then delete `~/agentlatch-data` and remove the `"agentlatch-demo"` entry from Claude Desktop's
configuration.

## Troubleshooting

| Symptom | Cause | Fix |
|---|---|---|
| `docker: command not found` | The terminal was open before the install, or Docker's commands are in `~/.docker/bin` | Open a new terminal. On a Mac, add `~/.docker/bin` to your `PATH` (Step 1) |
| `Cannot connect to the Docker daemon` | Docker Desktop is not running | Open it and wait for the whale icon to stop moving |
| `Unable to find image 'agent-latch:latest' locally` | The image has no short name yet | Do Step 2 |
| `permission denied` when writing a report to `/out` | The container user cannot write that folder | Add `--user "$(id -u):$(id -g)"` (Step 3) |
| `Read-only file system` | The project is mounted read-only on purpose | Write reports to a second mount, such as `/out` |
| Exit code `2` | A scan or configuration error, such as a mistyped option | Read the message; `docker run --rm agent-latch scan --help` lists the options |
| Claude Desktop shows the server as failed, or no tools | Wrong `docker` path, image not built or tagged, or `-i` missing | Check `which docker` and `docker image ls agent-latch-runtime`. Claude Desktop's MCP logs are in `~/Library/Logs/Claude/` on macOS and `%APPDATA%\Claude\logs\` on Windows |
| `npx: not found`, or a Node.js server does not start | The image has no Node.js, on purpose | Use `--upstream-url`, or see [Limits](docker.md#limits) |
| `--http must use a loopback address` | HTTP mode accepts only a loopback address, because it has no authentication | See [Limits](docker.md#limits) |
| The image is `amd64` on an Apple Silicon Mac | It was pulled or built for the wrong platform | Check with `docker image inspect agent-latch --format '{{.Architecture}}'`, then build again (Option A) |
