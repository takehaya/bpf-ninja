#!/bin/bash
set -euo pipefail

echo "Installing lint tools required by lefthook..."

if ! command -v apt-get >/dev/null 2>&1; then
    echo "Error: This script requires apt-get (Debian-based systems only)"
    exit 1
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/libs/install_utils.sh"

mkdir -p "${HOME}/.local/bin"

echo "Updating package list..."
sudo apt-get update -qq

install_tool "lefthook" "go install github.com/evilmartians/lefthook@latest"
install_tool "yamllint" "sudo apt-get install -y yamllint"
install_tool "jq" "sudo apt-get install -y jq"
install_tool "dos2unix" "sudo apt-get install -y dos2unix"
install_tool "clang-format" "sudo apt-get install -y clang-format"
install_tool "golangci-lint" "go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest"

echo ""
echo "All lint tools have been installed."
echo "Run 'lefthook install' to set up the git hooks."
