#!/usr/bin/env bash
# ============================================================================
# scripts/homebrew-formula.sh <version> <SHA256SUMS>
#
# Print the Homebrew formula for a release to stdout.
#
# The hashes come from the SHA256SUMS that build-release.sh writes, so the
# formula pins exactly the archives attached to the release. The release
# workflow commits the output to dhanesh/homebrew-tap as Formula/albauth.rb;
# running it locally against a downloaded SHA256SUMS reproduces that file.
# ============================================================================
set -euo pipefail

VERSION="${1:?usage: homebrew-formula.sh <version> <SHA256SUMS>}"
SUMS="${2:?usage: homebrew-formula.sh <version> <SHA256SUMS>}"
BASE="https://github.com/dhanesh/albauth/releases/download/${VERSION}"

# Hash of one platform's archive. A missing entry is fatal: a formula with an
# empty sha256 would publish an install that can never succeed.
sha() {
  local name="albauth_${VERSION}_$1.tar.gz" hash
  hash=$(awk -v n="$name" '{ f = $2; sub(/^\*?\.\//, "", f) } f == n { print $1 }' "$SUMS")
  [ -n "$hash" ] || { echo "no checksum for $name in $SUMS" >&2; exit 1; }
  echo "$hash"
}

DARWIN_ARM64=$(sha darwin_arm64)
DARWIN_AMD64=$(sha darwin_amd64)
LINUX_ARM64=$(sha linux_arm64)
LINUX_AMD64=$(sha linux_amd64)

cat <<EOF
class Albauth < Formula
  desc "MCP server for calling HTTP APIs behind an OIDC login proxy"
  homepage "https://dhanesh.github.io/albauth/"
  license "MIT"

  on_macos do
    on_arm do
      url "${BASE}/albauth_${VERSION}_darwin_arm64.tar.gz"
      sha256 "${DARWIN_ARM64}"
    end
    on_intel do
      url "${BASE}/albauth_${VERSION}_darwin_amd64.tar.gz"
      sha256 "${DARWIN_AMD64}"
    end
  end

  on_linux do
    on_arm do
      url "${BASE}/albauth_${VERSION}_linux_arm64.tar.gz"
      sha256 "${LINUX_ARM64}"
    end
    on_intel do
      url "${BASE}/albauth_${VERSION}_linux_amd64.tar.gz"
      sha256 "${LINUX_AMD64}"
    end
  end

  def install
    bin.install "albauth"
    pkgshare.install "config.example.toml"
  end

  test do
    assert_match "v#{version}", shell_output("#{bin}/albauth version")
    assert_match "config.toml", shell_output("#{bin}/albauth --config #{testpath}/config.toml config path")
  end
end
EOF
