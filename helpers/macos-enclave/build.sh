#!/bin/sh
# Build the native signer and its release inputs before Developer ID provisioning.
set -eu
if [ "$#" -ne 1 ] || [ -z "$1" ]; then
    echo 'usage: build.sh NEW_OUTPUT_DIRECTORY' >&2
    exit 2
fi
src=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd -P)
case "$1" in /*) out=$1 ;; *) out=$PWD/$1 ;; esac
umask 022
mkdir -m 0700 "$out"
app="$out/AgentBotHQSigner.app"
# Only remove build paths inside the directory exclusively created above.
cleanup() {
    rm -rf "$app" "$out/HQSigner.entitlements.in"
    rmdir "$out"
}
trap cleanup EXIT
trap 'exit 1' HUP INT TERM
mkdir -p "$app/Contents/MacOS"
install -m 0644 "$src/Info.plist" "$app/Contents/Info.plist"
install -m 0644 "$src/HQSigner.entitlements.in" "$out/HQSigner.entitlements.in"
# A fixed module name and source working directory keep the binary independent
# of the checkout and output paths. Both hosted and pilot builds target arm64.
(cd "$src" && /usr/bin/xcrun --sdk macosx swiftc -target arm64-apple-macosx15.0 -swift-version 5 \
    -module-name AgentBotHQSigner -O -whole-module-optimization \
    RoleStore.swift Signer.swift main.swift -o "$app/Contents/MacOS/agent-bot-hq-signer")
trap - EXIT HUP INT TERM
