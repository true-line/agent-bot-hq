#!/bin/bash
# Compile the production entry for Apple Silicon on macOS 15 or newer. Release
# signing and qualification are separate. The build does not access Keychain.
set -euo pipefail
if [[ "$(uname -s)" != Darwin || $# != 1 || -e "$1" || -L "$1" ]]; then
  echo 'usage (macOS): build-macos-standalone-signer.sh NEW_OUTPUT' >&2
  exit 2
fi
src="$(cd "$(dirname "$0")/../helpers/macos-enclave" && pwd)"
build="$(mktemp -d "$(dirname "$1")/.hq-signer-build.XXXXXXXX")"
trap 'rm -rf "$build"' EXIT
/usr/bin/xcrun --sdk macosx swiftc -O -target arm64-apple-macosx15.0 \
  -swift-version 5 -module-name AgentBotHQSigner \
  "$src/Signer.swift" "$src/RoleStore.swift" "$src/MachineInstallation.swift" \
  "$src/Standalone.swift" "$src/main.swift" -o "$build/hq-signer"
# Keep a stable linker identity regardless of the output name. Never replace
# an existing output, including one a concurrent build just published.
ln "$build/hq-signer" "$1"
