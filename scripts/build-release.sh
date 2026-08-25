#!/usr/bin/env bash
# ============================================================================
# scripts/build-release.sh <version> [outdir]
#
# Build the release artefacts for every supported target.
#
# Produces one archive per platform plus a single SHA256SUMS file, which is
# what install.sh verifies against. Nothing here is CI-specific: running it
# locally produces byte-identical output for the same version and source, so a
# release can be reproduced without GitHub.
# ============================================================================
set -euo pipefail
cd "$(dirname "$0")/.."

VERSION="${1:?usage: build-release.sh <version> [outdir]}"
OUTDIR="${2:-dist}"
BINARY="albauth"

TARGETS=(
  "darwin/arm64"
  "darwin/amd64"
  "linux/amd64"
  "linux/arm64"
  "windows/amd64"
)

rm -rf "$OUTDIR"
mkdir -p "$OUTDIR"

for target in "${TARGETS[@]}"; do
  GOOS="${target%/*}"
  GOARCH="${target#*/}"
  stage="$OUTDIR/stage/${BINARY}_${GOOS}_${GOARCH}"
  mkdir -p "$stage"

  exe="$BINARY"
  [ "$GOOS" = "windows" ] && exe="${BINARY}.exe"

  echo "building ${GOOS}/${GOARCH}…"
  # -trimpath and a fixed version string keep the output reproducible; a static
  # binary means one artefact runs on any host of that platform.
  CGO_ENABLED=0 GOOS="$GOOS" GOARCH="$GOARCH" go build \
    -trimpath \
    -ldflags "-s -w -X main.version=${VERSION}" \
    -o "$stage/$exe" \
    ./cmd/albauth

  cp README.md LICENSE config.example.toml "$stage/"

  archive="${BINARY}_${VERSION}_${GOOS}_${GOARCH}"
  if [ "$GOOS" = "windows" ]; then
    (cd "$OUTDIR/stage" && zip -q -r "../${archive}.zip" "$(basename "$stage")")
  else
    tar -czf "$OUTDIR/${archive}.tar.gz" -C "$OUTDIR/stage" "$(basename "$stage")"
  fi
done

rm -rf "$OUTDIR/stage"

# One checksum file covering every archive. install.sh fetches this and refuses
# to install an archive whose hash does not match.
(cd "$OUTDIR" && shasum -a 256 ./* > SHA256SUMS 2>/dev/null \
  || sha256sum ./* > SHA256SUMS)

echo
echo "artefacts in $OUTDIR:"
ls -1 "$OUTDIR"
