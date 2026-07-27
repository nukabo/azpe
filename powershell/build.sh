#!/usr/bin/env bash
set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"

# Find pwsh executable
if command -v pwsh >/dev/null 2>&1; then
    PWSH_BIN="pwsh"
elif [ -x "$ROOT_DIR/.gopath/powershell/pwsh" ]; then
    PWSH_BIN="$ROOT_DIR/.gopath/powershell/pwsh"
else
    echo "Warning: pwsh not found. Skipping PowerShell package build."
    exit 0
fi

export HOME="${ROOT_DIR}/.gopath/home"
export XDG_CONFIG_HOME="${ROOT_DIR}/.gopath/home/.config"
export XDG_DATA_HOME="${ROOT_DIR}/.gopath/home/.local/share"
export PSModulePath="${ROOT_DIR}/.gopath/Modules"

"$PWSH_BIN" -NoProfile -File "$SCRIPT_DIR/build.ps1" -SkipTests
