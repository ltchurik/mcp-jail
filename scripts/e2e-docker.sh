#!/usr/bin/env bash
# Run the Linux e2e (including the bubblewrap jail) in a privileged container.
# For developers on macOS; CI runs scripts/e2e.sh natively on ubuntu.
set -euo pipefail
cd "$(dirname "$0")/.."
IMG=mcp-jail-e2e
docker build -q -t "$IMG" - <<'DOCKERFILE'
FROM golang:1.27-bookworm
RUN apt-get update && apt-get install -y --no-install-recommends bubblewrap python3 && rm -rf /var/lib/apt/lists/*
RUN useradd -m -u 1001 dev
USER dev
ENV GOFLAGS=-buildvcs=false GOCACHE=/tmp/gocache GOPATH=/tmp/gopath GOTOOLCHAIN=auto
DOCKERFILE
# bubblewrap needs user namespaces; --privileged is the simplest way to get them
# past Docker's default seccomp/apparmor profiles.
docker run --rm --privileged -v "$PWD":/src -w /src "$IMG" \
  bash -c 'go test -race ./... && go build -o /tmp/mcp-jail ./cmd/mcp-jail && BIN=/tmp/mcp-jail ./scripts/e2e.sh'
