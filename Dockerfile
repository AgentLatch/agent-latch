# syntax=docker/dockerfile:1
#
# AgentLatch container images. One file, two images:
#
#   docker build --target scanner -t agent-latch .          static scanner     (agent-latch)
#   docker build --target runtime -t agent-latch-runtime .  MCP runtime proxy  (agent-latch-runtime)
#
# How they are hardened:
# - The Python base image is pinned by digest, so a build cannot silently pick up a changed image.
# - Dependencies come from hash-pinned locks (docker/requirements-*.txt, made by
#   scripts/update-docker-locks.sh) as prebuilt wheels only: no package's setup code runs at build.
# - The final images hold no compiler, no source tree and no Node.js, and run as a non-root user.
# docs/docker.md explains how to run them.

ARG PYTHON_IMAGE=python:3.13-slim@sha256:ae14d4ce8771606477a81446e7ef429edd6762305fc50c84507c1041fa8285d1

# ---- build: package AgentLatch itself as a wheel. Thrown away after the build. ---------------
FROM ${PYTHON_IMAGE} AS build
ENV PIP_NO_CACHE_DIR=1 PIP_DISABLE_PIP_VERSION_CHECK=1
WORKDIR /build
COPY pyproject.toml README.md LICENSE ./
COPY src ./src
RUN pip wheel --no-deps --wheel-dir /wheels .

# ---- base: what both images share ------------------------------------------------------------
FROM ${PYTHON_IMAGE} AS base
LABEL org.opencontainers.image.source="https://github.com/AgentLatch/agent-latch" \
      org.opencontainers.image.licenses="MIT" \
      org.opencontainers.image.vendor="AgentLatch"
# Caches (pip-audit's, for example) go to /tmp, which any --user can write.
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    XDG_CACHE_HOME=/tmp/.cache
RUN groupadd --gid 10001 latch \
 && useradd --uid 10001 --gid latch --no-create-home --home-dir /nonexistent \
      --shell /usr/sbin/nologin latch
# Python turns SIGINT into KeyboardInterrupt, which both CLIs handle, so `docker stop` ends
# them cleanly even though Python runs as PID 1.
STOPSIGNAL SIGINT

# ---- scanner: agent-latch scan --------------------------------------------------------------
FROM base AS scanner
LABEL org.opencontainers.image.title="agent-latch" \
      org.opencontainers.image.description="AgentLatch static scanner for AI-agent projects"
COPY docker/requirements-scanner.txt /tmp/requirements.txt
RUN --mount=type=bind,from=build,source=/wheels,target=/wheels \
    pip install --require-hashes --only-binary=:all: -r /tmp/requirements.txt \
 && pip install --no-deps --no-index /wheels/*.whl \
 && rm /tmp/requirements.txt
USER 10001:10001
# Mount the project to scan here, read-only: docker run -v "$PWD:/src:ro" ...
WORKDIR /src
ENTRYPOINT ["agent-latch"]
CMD ["scan", "."]

# ---- runtime: agent-latch-runtime proxy / import-logs / verify / anchor / demo ---------------
FROM base AS runtime
LABEL org.opencontainers.image.title="agent-latch-runtime" \
      org.opencontainers.image.description="AgentLatch runtime monitor for MCP tool traffic (preview)"
COPY docker/requirements-runtime.txt /tmp/requirements.txt
RUN --mount=type=bind,from=build,source=/wheels,target=/wheels \
    pip install --require-hashes --only-binary=:all: -r /tmp/requirements.txt \
 && pip install --no-deps --no-index /wheels/*.whl \
 && rm /tmp/requirements.txt \
 && mkdir /data && chown 10001:10001 /data
USER 10001:10001
# Logs, ledgers and the event database go here. Mount a folder or a volume to keep them.
WORKDIR /data
ENTRYPOINT ["agent-latch-runtime"]
CMD ["--help"]
