#!/usr/bin/env bash
# Run from the unpacked HQ archive after the native CI job creates the role account.
set -euo pipefail
[[ "${GITHUB_ACTIONS:-}" == true && "${RUNNER_ENVIRONMENT:-}" == github-hosted && "$(uname -s)" == Darwin ]]
label=ai.true-line.agent-bot-hq
plist="/Library/LaunchDaemons/$label.plist"
socket=/private/var/run/agent-bot-hq-control.sock
role=_agent-bot-hq
state=/var/agent-bot-hq/.agent-bot-hq
owner="$(id -un)"
archive="$(pwd -P)"
entry="$archive/hq/main.mjs"
helper="$archive/helpers/darwin-owner.rb"
system_node="${1:?node executable required}"

[[ "$(id -u)" != 0 && "$(id -u)" != "$(id -u "$role")" ]]
[[ ! -e "$plist" && ! -L "$plist" && ! -e "$socket" && ! -L "$socket" ]]
if sudo launchctl print "system/$label" >/dev/null 2>&1; then
  echo "a system HQ job already exists" >&2
  exit 1
fi
work="$(sudo mktemp -d /Library/hq-owner-ci.XXXXXXXX)"
cleanup() {
  sudo launchctl bootout "system/$label" >/dev/null 2>&1 || true
  sudo rm -f "$plist"
  if [[ -S "$socket" ]]; then sudo rm -f "$socket"; fi
  sudo rm -rf "$work"
}
trap cleanup EXIT
sudo chmod 0755 "$work"
# This test runner keeps its Node next to its native runtime libraries.
sudo install -m 0600 -o "$role" -g "$role" /dev/null "$work/launchd.stderr"
sudo -n -H -u "$role" "$system_node" --version
"$system_node" "$entry" check-owner-control | jq -e '.capability == "darwin-owner-control/v1"' >/dev/null

# Generate typed launchd properties with the same service, socket and CLI
# arguments that Machine installs. launchd owns the listener.
python3 - "$label" "$role" "$socket" "$system_node" "$entry" "$helper" "$state" "$owner" "$work/launchd.stderr" <<'PY' | sudo tee "$work/launch.plist" >/dev/null
import plistlib
import sys

label, role, socket, node, entry, helper, state, owner, stderr = sys.argv[1:]
plistlib.dump({
    "Label": label,
    "UserName": role, "GroupName": role,
    "ProgramArguments": ["/usr/bin/ruby", "--disable-gems", helper, "launch",
                         node, entry, "run", "--home", state, "--owner-account", owner],
    "Sockets": {"owner-control": {"SockPathName": socket, "SockPathMode": 0o666,
                                  "SockType": "stream"}},
    "StandardErrorPath": stderr,
}, sys.stdout.buffer)
PY
sudo install -d -m 0700 -o "$role" -g "$role" "$state"
sudo install -m 0644 -o root -g wheel "$work/launch.plist" "$plist"
plutil -lint "$plist"
sudo launchctl bootstrap system "$plist"

# Only the manager runs as root. This normal CLI runs as the designated owner.
stat -f '%N uid=%u gid=%g mode=%Lp type=%HT' /private /private/var /private/var/run "$socket"
diagnose() {
  sudo cat "$work/launchd.stderr" >&2
  sudo launchctl print "system/$label" | awk '/state =|last exit code =|pid =/ { print }' >&2
  exit 1
}
python3 - "$system_node" "$entry" "$owner" "$socket" <<'PY' || diagnose
import json
import os
import stat
import subprocess
import sys

node, entry, owner, path = sys.argv[1:]
sock = os.lstat(path)
assert stat.S_ISSOCK(sock.st_mode) and sock.st_uid == 0 and stat.S_IMODE(sock.st_mode) == 0o666
result = subprocess.run([node, entry, "status", "--owner-control", "--json"],
                        check=True, stdout=subprocess.PIPE, text=True, timeout=45)
status = json.loads(result.stdout)
control = status["hq"]["sockets"]["ownerControl"]
assert control["path"] == path and control["peer_check"] == "getpeereid"
assert control["uid"] == os.getuid() and control["account"] == owner
assert status["hq"]["account"] == "_agent-bot-hq" and status["profile"] == "managed-cooperative"
PY
pid="$(sudo launchctl print "system/$label" | awk '$1 == "pid" && $2 == "=" { print $3 }')"
[[ "$pid" =~ ^[1-9][0-9]*$ ]]
[[ "$(ps -o uid= -p "$pid" | tr -d ' ')" == "$(id -u "$role")" ]]
echo "The owner CLI reached the launchd service running as $role with getpeereid authentication."
