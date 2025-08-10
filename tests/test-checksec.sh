#!/usr/bin/env bash
# Build Linux checksec, bake into a Docker image, then inside the container
# build test binaries and run hardening checks.

set -euo pipefail
set -x

SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd)
REPO_ROOT=$(cd "${SCRIPT_DIR}/.." && pwd)

# Use amd64 by default to ensure gcc-multilib works and matches test expectations
DOCKER_PLATFORM=${DOCKER_PLATFORM:-linux/amd64}

# 1) Build Linux checksec binary on the host (cross-compile)
(
  cd "${REPO_ROOT}"
  env CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o checksec .
)

# 2) Build a Docker image that contains toolchains and the repository (incl. checksec)
docker build \
  --platform "${DOCKER_PLATFORM}" \
  -f "${REPO_ROOT}/Dockerfile.ubuntu" \
  -t checksec-test:local \
  "${REPO_ROOT}"

# 3) Run container: build test binaries and execute all checks inside
docker run --rm \
  --platform "${DOCKER_PLATFORM}" \
  -w /root \
  checksec-test:local \
  bash -lc "set -euo pipefail; cd tests/binaries && ./build_binaries.sh && cd .. && ./xml-checks.sh && ./json-checks.sh && ./hardening-checks.sh"

echo "Containerized XML, JSON, and hardening checks completed successfully"
