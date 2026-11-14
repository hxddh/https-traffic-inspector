#!/bin/sh
# Installs the latest httpmon release (or $HTTPMON_VERSION, e.g. v4.0.0) for
# Linux or macOS, verifying its SHA-256 checksum.
#
#   curl -fsSL https://github.com/hxddh/https-traffic-inspector/releases/latest/download/install.sh | sh
#
# Installs to $HTTPMON_INSTALL_DIR, else ~/.local/bin. $HTTPMON_DOWNLOAD_BASE
# points at a mirror of the release assets.
set -eu

repo="hxddh/https-traffic-inspector"
version="${HTTPMON_VERSION:-latest}"
dir="${HTTPMON_INSTALL_DIR:-$HOME/.local/bin}"

case "$(uname -s)" in
  Linux) os=linux ;;
  Darwin) os=macos ;;
  *) echo "httpmon install: unsupported system $(uname -s); on Windows use install.ps1" >&2; exit 1 ;;
esac
case "$(uname -m)" in
  x86_64 | amd64) arch=amd64 ;;
  arm64 | aarch64) arch=arm64 ;;
  *) echo "httpmon install: unsupported architecture $(uname -m)" >&2; exit 1 ;;
esac

if [ -n "${HTTPMON_DOWNLOAD_BASE:-}" ]; then
  base="$HTTPMON_DOWNLOAD_BASE" # a mirror of the release assets
elif [ "$version" = latest ]; then
  base="https://github.com/$repo/releases/latest/download"
else
  base="https://github.com/$repo/releases/download/$version"
fi
asset="httpmon-$os-$arch"

fetch() {
  if command -v curl >/dev/null 2>&1; then
    curl -fsSL -o "$2" "$1"
  elif command -v wget >/dev/null 2>&1; then
    wget -q -O "$2" "$1"
  else
    echo "httpmon install: need curl or wget" >&2
    exit 1
  fi
}

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT INT TERM
echo "Downloading $asset ($version)..."
fetch "$base/$asset" "$tmp/$asset"
fetch "$base/SHA256SUMS" "$tmp/SHA256SUMS"

want="$(awk -v f="$asset" '$2 == f { print $1 }' "$tmp/SHA256SUMS")"
if [ -z "$want" ]; then
  echo "httpmon install: $asset is not listed in SHA256SUMS" >&2
  exit 1
fi
if command -v sha256sum >/dev/null 2>&1; then
  got="$(sha256sum "$tmp/$asset" | awk '{ print $1 }')"
else
  got="$(shasum -a 256 "$tmp/$asset" | awk '{ print $1 }')"
fi
if [ "$got" != "$want" ]; then
  echo "httpmon install: checksum mismatch for $asset (got $got, want $want)" >&2
  exit 1
fi

mkdir -p "$dir"
chmod 0755 "$tmp/$asset"
mv "$tmp/$asset" "$dir/httpmon"
# A downloaded binary is quarantined on macOS; this release is not notarized.
if [ "$os" = macos ]; then
  xattr -d com.apple.quarantine "$dir/httpmon" 2>/dev/null || true
fi
echo "Installed $("$dir/httpmon" --version) to $dir/httpmon"
case ":$PATH:" in
  *":$dir:"*) ;;
  *) echo "Add $dir to your PATH to run it as httpmon." ;;
esac
