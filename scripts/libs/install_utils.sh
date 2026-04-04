#!/usr/bin/env bash
# Library of installer helpers for lint tools

command_exists() {
    command -v "$1" >/dev/null 2>&1
}

install_tool() {
    local tool="$1"
    local install_cmd="$2"

    if command_exists "$tool"; then
        echo "  $tool is already installed"
        return 0
    fi

    echo "Installing $tool..."
    eval ${install_cmd}
    if command_exists "$tool"; then
        echo "  $tool installed successfully"
        return 0
    fi

    echo "  Failed to install $tool"
    return 1
}

if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
    exit 0
fi
