#!/usr/bin/env bash
# Install bpf-ninja from GitHub Releases.
#
# Usage:
#   curl -fsSL https://raw.githubusercontent.com/takehaya/bpf-ninja/main/scripts/install.sh | sudo bash
#   curl -fsSL ... | sudo bash -s -- --version v0.1.0
set -euo pipefail

REPO="takehaya/bpf-ninja"
BIN_DIR="/usr/local/bin"

# BPF_NINJA_VERSION selects a release; the pre-rename XDP_NINJA_VERSION
# is still honored so existing automation keeps working.
VERSION="${BPF_NINJA_VERSION:-${XDP_NINJA_VERSION:-}}"
if [ "${1:-}" = "--version" ] && [ -n "${2:-}" ]; then
  VERSION="$2"
  shift 2
fi

case "$(uname -s)" in
  Linux) OS="linux" ;;
  *) echo "Unsupported OS: $(uname -s). bpf-ninja only runs on Linux." >&2; exit 1 ;;
esac

case "$(uname -m)" in
  x86_64|amd64) ARCH="x86_64" ;;
  *) echo "Unsupported arch: $(uname -m)" >&2; exit 1 ;;
esac

if [ -z "$VERSION" ] || [ "$VERSION" = "latest" ]; then
  META_URL="https://api.github.com/repos/$REPO/releases/latest"
else
  META_URL="https://api.github.com/repos/$REPO/releases/tags/$VERSION"
fi

JSON="$(curl -fsSL "$META_URL")"
TAG_NAME="$(echo "$JSON" | jq -r '.tag_name // empty')"
[ -n "$TAG_NAME" ] || { echo "Failed to fetch release info" >&2; exit 1; }

ASSET_URL="$(echo "$JSON" | jq -r --arg os "$OS" --arg arch "$ARCH" '
  .assets[].browser_download_url
  | select(test("_" + $os + "_" + $arch + "\\.tar\\.gz$"))
' | head -n1)"
[ -n "$ASSET_URL" ] || { echo "No asset found for ${OS}_${ARCH}" >&2; exit 1; }

TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

echo "Downloading bpf-ninja $TAG_NAME..."
curl -fsSL "$ASSET_URL" -o "$TMP/bpf-ninja.tar.gz"
tar xzf "$TMP/bpf-ninja.tar.gz" -C "$TMP"
install -m 0755 "$TMP/bpf-ninja" "$BIN_DIR/bpf-ninja"

echo "Installed bpf-ninja $TAG_NAME to $BIN_DIR/bpf-ninja"
