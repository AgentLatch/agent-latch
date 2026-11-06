#!/usr/bin/env sh
# Regenerate the hash-pinned dependency locks that the container images install from.
#
#   docker/requirements-scanner.txt  dependencies of the static scanner image (base + [audit])
#   docker/requirements-runtime.txt  dependencies of the runtime image (base + [runtime])
#
# Run it after changing dependencies in pyproject.toml, or to pick up dependency fixes.
# Needs uv (https://docs.astral.sh/uv/). The image's Python version is set in the Dockerfile.
set -eu
cd "$(dirname "$0")/.."

for spec in scanner:audit runtime:runtime; do
  image=${spec%%:*}
  extra=${spec##*:}
  uv pip compile pyproject.toml \
    --extra "$extra" \
    --universal \
    --python-version 3.13 \
    --generate-hashes \
    --custom-compile-command "scripts/update-docker-locks.sh" \
    --quiet \
    --output-file "docker/requirements-$image.txt"
done
echo "Updated docker/requirements-scanner.txt and docker/requirements-runtime.txt"
