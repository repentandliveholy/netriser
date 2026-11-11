#!/usr/bin/env bash
# Build the five supported NetRiser release targets (pure Go, no CGO).
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

BIN_DIR="${BIN_DIR:-${SCRIPT_DIR}/bin}"
mkdir -p "$BIN_DIR"
VERSION="${VERSION:-1.2.2}"
COMMIT="${COMMIT:-$(git rev-parse --short HEAD 2>/dev/null || echo unknown)}"
BUILD_TIME="${BUILD_TIME:-$(date -u +"%Y-%m-%dT%H:%M:%SZ")}"
LDFLAGS="-s -w -X main.Version=${VERSION} -X main.Commit=${COMMIT} -X main.BuildTime=${BUILD_TIME}"
MAIN="./cmd/netriser"

targets=(
  "linux/amd64/netriser-linux-amd64"
  "linux/arm64/netriser-linux-arm64"
  "windows/amd64/netriser-windows-amd64.exe"
  "darwin/arm64/netriser-darwin-arm64"
  "darwin/amd64/netriser-darwin-amd64"
)

echo "Building NetRiser ${VERSION} (${COMMIT}, ${BUILD_TIME})"
for target in "${targets[@]}"; do
  IFS=/ read -r GOOS GOARCH OUTNAME <<< "$target"
  printf '[BUILD] %-7s %-7s -> %s\n' "$GOOS" "$GOARCH" "$BIN_DIR/$OUTNAME"
  CGO_ENABLED=0 GOOS="$GOOS" GOARCH="$GOARCH" go build \
    -ldflags="$LDFLAGS" -trimpath -o "$BIN_DIR/$OUTNAME" "$MAIN"
done
echo "Build complete: $BIN_DIR"
