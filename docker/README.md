# docker/

The dependency locks the two container images install from. To run the images, start with
[Setting up the container images](../docs/docker-setup.md); the full reference is
[Container images](../docs/docker.md).

| File | Image | What it pins |
|---|---|---|
| `requirements-scanner.txt` | scanner (`agent-latch`) | The base dependencies plus the `[audit]` extra (`pip-audit`, for `--dependencies`) |
| `requirements-runtime.txt` | runtime (`agent-latch-runtime`) | The base dependencies plus the `[runtime]` extra (FastMCP) |

Both files are generated. Do not edit them by hand: run the script below instead.

## How the images are built

The [`Dockerfile`](../Dockerfile) in the repository root has four stages:

| Stage | What it does |
|---|---|
| `build` | Packages AgentLatch from `src/` as a wheel. Thrown away after the build |
| `base` | Shared by both images: the Python base image (pinned by digest), user `10001` (`latch`), `STOPSIGNAL SIGINT` so `docker stop` ends the commands cleanly |
| `scanner` | Installs `requirements-scanner.txt`, then the AgentLatch wheel. Runs `agent-latch` in `/src` |
| `runtime` | Installs `requirements-runtime.txt`, then the AgentLatch wheel. Runs `agent-latch-runtime` in `/data` |

Every package is installed with `pip install --require-hashes --only-binary=:all:`: each file must
match a hash in the lock, and only prebuilt wheels are accepted, so no package's setup code runs
during the build. The final images hold no compiler, no source tree, no git and no Node.js.

The [`.dockerignore`](../.dockerignore) is an allow-list. Only `pyproject.toml`, `README.md`,
`LICENSE`, `src/` and this folder enter the build, so `runtime-logs/`, `.env` files and event
databases can never end up in an image.

## Updating the locks

Update them when you change dependencies in `pyproject.toml`, or to pick up a dependency fix. You
need [uv](https://docs.astral.sh/uv/). From the repository root:

```sh
scripts/update-docker-locks.sh
```

Commit both lock files in the same change as the `pyproject.toml` edit. Otherwise the images keep
the old dependencies.

Dependabot opens a weekly pull request that updates these locks, the base image digest and the
workflow actions ([`.github/dependabot.yml`](../.github/dependabot.yml)).

## Changing the Python version

The base image is pinned by digest in the two `FROM` lines of the `Dockerfile`, which Dependabot updates together.
The locks are resolved for the same Python version (`--python-version 3.13` in
[`scripts/update-docker-locks.sh`](../scripts/update-docker-locks.sh)). Change both together, then
run the script.

## Checking a change locally

Build both images and run the checks that CI runs on every pull request
([`.github/workflows/images.yml`](../.github/workflows/images.yml)):

```sh
docker build --target scanner -t agent-latch:test .
docker build --target runtime -t agent-latch-runtime:test .
docker run --rm agent-latch:test --version
docker run --rm --entrypoint id agent-latch:test -u
docker run --rm -v "$PWD/examples/vulnerable-agent:/src:ro" agent-latch:test scan . --plain --fail-on high
docker run --rm agent-latch-runtime:test demo
```

Expect the version, `10001`, a scan that reports findings and exits `1` (the demo project is
insecure on purpose), and the demo's event lines.

Publishing to GHCR is described in [Publishing (maintainers)](../docs/docker.md#publishing-maintainers).
