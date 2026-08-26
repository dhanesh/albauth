#!/usr/bin/env sh
# ============================================================================
# albauth installer
#
#   curl -fsSL https://raw.githubusercontent.com/dhanesh/albauth/main/install.sh | sh
#
# Downloads the release build for this machine, checks it against the published
# SHA256SUMS, and installs it. Nothing is executed from the archive before that
# check passes.
#
# Environment:
#   ALBAUTH_VERSION      version to install, e.g. v1.2.3   (default: latest)
#   ALBAUTH_INSTALL_DIR  where to put the binary           (default: see below)
#
# POSIX sh on purpose: this has to run on a minimal container as readily as on
# a laptop.
# ============================================================================
set -eu

REPO="dhanesh/albauth"
BINARY="albauth"

say()  { printf '%s\n' "$*"; }
warn() { printf '%s\n' "$*" >&2; }
die()  { printf 'install: %s\n' "$*" >&2; exit 1; }

need() { command -v "$1" >/dev/null 2>&1 || die "$1 is required but not installed"; }

# ------------------------------------------------------------ fetch helper
if command -v curl >/dev/null 2>&1; then
  fetch()      { curl -fsSL "$1"; }
  fetch_file() { curl -fsSL "$1" -o "$2"; }
elif command -v wget >/dev/null 2>&1; then
  fetch()      { wget -qO- "$1"; }
  fetch_file() { wget -qO "$2" "$1"; }
else
  die "either curl or wget is required"
fi

# ------------------------------------------------------- platform detection
os=$(uname -s | tr '[:upper:]' '[:lower:]')
arch=$(uname -m)

case "$os" in
  linux)  os=linux ;;
  darwin) os=darwin ;;
  *) die "unsupported operating system: $os
  albauth publishes builds for linux, darwin and windows.
  On Windows use the .zip from the releases page." ;;
esac

case "$arch" in
  x86_64|amd64)  arch=amd64 ;;
  arm64|aarch64) arch=arm64 ;;
  *) die "unsupported architecture: $arch" ;;
esac

# Published targets. darwin/arm64, darwin/amd64, linux/amd64, linux/arm64.
case "${os}_${arch}" in
  darwin_arm64|darwin_amd64|linux_amd64|linux_arm64) ;;
  *) die "no published build for ${os}/${arch}" ;;
esac

# ----------------------------------------------------------------- version
version="${ALBAUTH_VERSION:-}"
if [ -z "$version" ]; then
  say "looking up the latest release…"
  version=$(fetch "https://api.github.com/repos/${REPO}/releases/latest" \
    | sed -n 's/.*"tag_name"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' \
    | head -n 1)
  [ -n "$version" ] || die "could not determine the latest release.
  Set ALBAUTH_VERSION explicitly, or check https://github.com/${REPO}/releases"
fi

archive="${BINARY}_${version}_${os}_${arch}.tar.gz"
base="https://github.com/${REPO}/releases/download/${version}"

# ------------------------------------------------------------- install dir
if [ -n "${ALBAUTH_INSTALL_DIR:-}" ]; then
  install_dir="$ALBAUTH_INSTALL_DIR"
elif [ -w "/usr/local/bin" ] 2>/dev/null; then
  install_dir="/usr/local/bin"
else
  install_dir="${HOME}/.local/bin"
fi
mkdir -p "$install_dir" || die "cannot create $install_dir"
[ -w "$install_dir" ] || die "$install_dir is not writable.
  Set ALBAUTH_INSTALL_DIR to somewhere you can write, or re-run with sudo."

# ------------------------------------------------------------ download
need tar
tmp=$(mktemp -d 2>/dev/null || mktemp -d -t albauth)
trap 'rm -rf "$tmp"' EXIT INT TERM

say "downloading ${BINARY} ${version} for ${os}/${arch}…"
fetch_file "${base}/${archive}" "${tmp}/${archive}" \
  || die "could not download ${base}/${archive}
  Check that ${version} exists at https://github.com/${REPO}/releases"

# ------------------------------------------------------------ verify
say "verifying the checksum…"
if fetch_file "${base}/SHA256SUMS" "${tmp}/SHA256SUMS" 2>/dev/null; then
  expected=$(sed -n "s|^\([0-9a-f]\{64\}\)[[:space:]]*\.\{0,1\}/\{0,1\}${archive}\$|\1|p" \
    "${tmp}/SHA256SUMS" | head -n 1)
  if [ -z "$expected" ]; then
    die "SHA256SUMS has no entry for ${archive}; refusing to install"
  fi

  if command -v sha256sum >/dev/null 2>&1; then
    actual=$(sha256sum "${tmp}/${archive}" | cut -d' ' -f1)
  elif command -v shasum >/dev/null 2>&1; then
    actual=$(shasum -a 256 "${tmp}/${archive}" | cut -d' ' -f1)
  else
    die "neither sha256sum nor shasum is available; cannot verify the download"
  fi

  [ "$actual" = "$expected" ] || die "checksum mismatch for ${archive}
  expected ${expected}
  got      ${actual}
  The download was corrupted or tampered with. Nothing has been installed."
  say "checksum ok"
else
  die "could not fetch SHA256SUMS; refusing to install an unverified binary"
fi

# ------------------------------------------------------------ install
tar -xzf "${tmp}/${archive}" -C "$tmp"
extracted="${tmp}/${BINARY}_${os}_${arch}/${BINARY}"
[ -f "$extracted" ] || die "the archive did not contain ${BINARY}"

chmod +x "$extracted"
mv "$extracted" "${install_dir}/${BINARY}"

say ""
say "installed ${BINARY} ${version} to ${install_dir}/${BINARY}"

case ":${PATH}:" in
  *":${install_dir}:"*) ;;
  *)
    say ""
    warn "${install_dir} is not on your PATH. Add it:"
    warn "    export PATH=\"${install_dir}:\$PATH\""
    ;;
esac

say ""
say "Next:"
say "  1. ${BINARY} config add-domain <name> --base-url <url>"
say "     (it probes the URL and works out the rest for you)"
say "  2. ${BINARY} auth login <name>      # one browser login"
say ""
say "Then point your MCP client at:  ${install_dir}/${BINARY} serve"
say "  Claude Code:  claude mcp add albauth -- ${install_dir}/${BINARY} serve"
say ""
say "Not sure what to do with it? Install the agent skill and ask:"
say "  npx skills add ${REPO} --global"
say "Docs: https://github.com/${REPO}"
