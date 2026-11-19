#!/usr/bin/env bash
# Create a temporary role account only on a fresh hosted macOS test VM.
set -euo pipefail
[[ "${GITHUB_ACTIONS:-}" == true && "${RUNNER_ENVIRONMENT:-}" == github-hosted && "$(uname -s)" == Darwin ]]
archive="${1:?macOS target tar required}"
if [[ "$archive" == --socket-parent-comparison ]]; then
  [[ "${GITHUB_REPOSITORY:-}" == true-line/agent-bot-hq && "$(uname -m)" == arm64 && "$(sw_vers -productVersion)" == 27.* ]]
fi
name=_agent-bot-hq
account="/Users/$name"
group="/Groups/$name"
home=/private/var/agent-bot-hq
if dscl . -read "$account" >/dev/null 2>&1 || dscl . -read "$group" >/dev/null 2>&1 || [[ -e "$home" ]]; then
  echo 'an existing HQ installation occupies this runner'; exit 1
fi
users="$(dscl . -list /Users UniqueID)"
groups="$(dscl . -list /Groups PrimaryGroupID)"
for number in {300..399}; do
  if ! awk -v n="$number" '$NF == n { used=1 } END { exit !used }' <<<"$users
$groups"; then role_id="$number"; break; fi
done
: "${role_id:?no unused service ID}"
stage="$(sudo mktemp -d /private/tmp/hq-artifact.XXXXXXXX)"
cleanup() {
  sudo dscl . -delete "$account" >/dev/null 2>&1 || true
  sudo dscl . -delete "$group" >/dev/null 2>&1 || true
  sudo rm -rf "$stage" "$home"
}
trap cleanup EXIT
sudo dscl . -create "$group"
sudo dscl . -create "$group" PrimaryGroupID "$role_id"
sudo dscl . -create "$group" Password '*'
sudo dscl . -create "$account"
sudo dscl . -create "$account" UniqueID "$role_id"
sudo dscl . -create "$account" PrimaryGroupID "$role_id"
sudo dscl . -create "$account" NFSHomeDirectory "$home"
sudo dscl . -create "$account" UserShell /usr/bin/false
sudo dscl . -create "$account" Password '*'
sudo dscl . -create "$account" IsHidden 1
sudo install -d -m 0700 -o "$name" -g "$name" "$home"
sudo chmod 0755 "$stage"
if [[ "$archive" == --socket-parent-comparison ]]; then
  sudo install -m 0644 helpers/darwin-owner.rb tests/darwin-socket-parent-probe.rb "$stage/"
  /usr/bin/python3 -I tests/darwin-socket-parents.py "$stage"
  exit
fi
sudo tar -xf "$archive" -C "$stage"
# Keep the installed executable next to its native runtime libraries.
node_bin="$(node -p 'process.execPath')"
sudo -n -H -u "$name" -- "$node_bin" --version
if [[ "${2:?compiled enclave probe or --launchd-only required}" != --launchd-only ]]; then
  bash tests/darwin-enclave-launchd.sh "$2" "$stage" "$name" "$home"
  bash tests/darwin-enclave-restart.sh "$stage" "$name" "$home"
fi
cd "$stage/hq"
sudo -n -H -u "$name" -- /bin/bash tests/dedicated-hq-account.sh "$node_bin" --disposable-machine-role
bash tests/darwin-launchd-owner-control.sh "$node_bin"
