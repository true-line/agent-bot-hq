#!/usr/bin/env bash
# Run from the unpacked HQ archive after the native CI job creates the role account.
set -euo pipefail
[[ "${GITHUB_ACTIONS:-}" == true && "${RUNNER_ENVIRONMENT:-}" == github-hosted && "$(uname -s)" == Darwin ]]
label=ai.true-line.agent-bot-hq
plist="/Library/LaunchDaemons/$label.plist"
runtime='/Library/Application Support/ai.true-line.agent-bot-hq'
socket="$runtime/owner-control.sock"
role=_agent-bot-hq
state=/var/agent-bot-hq/.agent-bot-hq
owner="$(id -un)"
archive="$(pwd -P)"
entry="$archive/hq/main.mjs"
helper="$archive/helpers/darwin-owner.rb"
system_node="${1:?node executable required}"

[[ "$(id -u)" != 0 && "$(id -u)" != "$(id -u "$role")" ]]
[[ ! -e "$plist" && ! -L "$plist" && ! -e "$runtime" && ! -L "$runtime" ]]
if sudo launchctl print "system/$label" >/dev/null 2>&1; then
  echo "a system HQ job already exists" >&2
  exit 1
fi
work="$(sudo mktemp -d /Library/hq-owner-ci.XXXXXXXX)"
runtime_created=false
cleanup() {
  sudo launchctl bootout "system/$label" >/dev/null 2>&1 || true
  sudo rm -f "$plist"
  if [[ "$runtime_created" == true ]]; then
    if [[ -S "$socket" ]]; then sudo rm -f "$socket"; fi
    sudo rmdir "$runtime"
  fi
  sudo rm -rf "$work"
}
trap cleanup EXIT
sudo mkdir -m 0755 "$runtime"
runtime_created=true
sudo chown root:wheel "$runtime"
sudo chmod 0755 "$work"
# This test runner keeps its Node next to its native runtime libraries.
sudo install -m 0600 -o "$role" -g "$role" /dev/null "$work/launchd.stderr"
sudo -n -H -u "$role" "$system_node" --version
"$system_node" --test tests/hq-owner-control.test.mjs
capability="$(jq -er '.owner_control_capability | select(. == "darwin-owner-control/v2")' "$archive/governance/interim-release.json")"
"$system_node" "$entry" check-owner-control | jq -e --arg expected "$capability" \
  '.capability == $expected and .launch_diagnostics == "darwin-hq-launch-exits/v2"' >/dev/null

# Generate typed launchd properties with the same service, socket and CLI
# arguments that Machine installs. launchd owns the listener.
python3 - "$label" "$role" "$socket" "$system_node" "$entry" "$helper" "$state" "$owner" "$work/launchd.stderr" <<'PY' | sudo tee "$work/launch.plist" >/dev/null
import plistlib
import sys

label, role, socket, node, entry, helper, state, owner, stderr = sys.argv[1:]
plistlib.dump({
    "Label": label,
    "UserName": role, "GroupName": role, "Umask": 0o077,
    "ProgramArguments": ["/usr/bin/ruby", "--disable-gems", helper, "launch",
                         node, entry, "run", "--home", state, "--owner-account", owner],
    "Sockets": {"owner-control": {"SockPathName": socket, "SockPathMode": 0o666,
                                  "SockType": "stream"}},
    "StandardErrorPath": stderr,
}, sys.stdout.buffer)
PY
# A first install provides an empty role home. HQ creates its own private state.
sudo -n -u "$role" test ! -e "$state"
sudo install -m 0644 -o root -g wheel "$work/launch.plist" "$plist"
plutil -lint "$plist"
sudo launchctl bootstrap system "$plist"

# Only the manager runs as root. This normal CLI runs as the designated owner.
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
import time

node, entry, owner, path = sys.argv[1:]
deadline = time.monotonic() + 3
while True:
    try:
        sock = os.lstat(path)
        break
    except FileNotFoundError:
        if time.monotonic() >= deadline:
            raise
        time.sleep(0.05)
assert stat.S_ISSOCK(sock.st_mode) and sock.st_uid == 0 and stat.S_IMODE(sock.st_mode) == 0o666
# Machine apply runs as root with this small environment and invokes the
# CLI as the approved owner. Hosted CI itself starts as the ordinary owner.
result = subprocess.run(["/usr/bin/sudo", "-n", "/usr/bin/env", "-i",
                         "PATH=/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL=C",
                         "/usr/bin/sudo", "-n", "-H", "-u", owner, "--",
                         node, entry, "status", "--owner-control", "--json"],
                        check=True, stdout=subprocess.PIPE, text=True, timeout=30)
status = json.loads(result.stdout)
control = status["hq"]["sockets"]["ownerControl"]
assert control["path"] == path and control["peer_check"] == "getpeereid"
assert control["uid"] == os.getuid() and control["account"] == owner
assert status["hq"]["account"] == "_agent-bot-hq" and status["profile"] == "managed-cooperative"
PY
[[ "$(sudo stat -f '%u:%Lp' "$state")" == "$(id -u "$role"):700" ]]
pid="$(sudo launchctl print "system/$label" | awk '$1 == "pid" && $2 == "=" { print $3 }')"
[[ "$pid" =~ ^[1-9][0-9]*$ ]]
[[ "$(ps -o uid= -p "$pid" | tr -d ' ')" == "$(id -u "$role")" ]]
echo "The owner CLI reached the launchd service running as $role with getpeereid authentication."

# launchd retains the listening socket while restarting HQ. Queue a normal
# request from the designated owner while the dedicated CI service is paused.
python3 - "$label" "$pid" "$socket" "$owner" <<'PY' || diagnose
import json
import os
import socket
import subprocess
import sys
import time

label, pid, path, owner = sys.argv[1:]
service = "system/" + label
before = os.lstat(path)
subprocess.run(["/usr/bin/sudo", "-n", "/bin/launchctl", "kill", "SIGSTOP", service], check=True)
deadline = time.monotonic() + 5
while "T" not in subprocess.check_output(["/bin/ps", "-o", "state=", "-p", pid], text=True):
    if time.monotonic() >= deadline:
        raise RuntimeError("CI HQ process did not pause")
    time.sleep(0.05)
with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as pending:
    pending.settimeout(40)
    pending.connect(path)
    pending.sendall(b'{"id":37,"op":"status"}\n')
    subprocess.run(["/usr/bin/sudo", "-n", "/bin/launchctl", "kill", "SIGKILL", service], check=True)
    with pending.makefile("rb") as reply:
        response = json.loads(reply.readline(1024 * 1024))
assert response["id"] == 37 and response["ok"] is True
report = response["result"]["hq"]
assert report["account"] == "_agent-bot-hq"
control = report["sockets"]["ownerControl"]
assert control["uid"] == os.getuid() and control["account"] == owner and control["peer_check"] == "getpeereid"
after = os.lstat(path)
assert (before.st_dev, before.st_ino) == (after.st_dev, after.st_ino)
PY
restarted_pid="$(sudo launchctl print "system/$label" | awk '$1 == "pid" && $2 == "=" { print $3 }')"
[[ "$restarted_pid" =~ ^[1-9][0-9]*$ && "$restarted_pid" != "$pid" ]]
echo "A pending owner status request reached the restarted HQ through the same launchd socket."
