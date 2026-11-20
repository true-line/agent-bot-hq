#!/usr/bin/env bash
# Run from the unpacked HQ archive after the native CI job creates the role account.
set -euo pipefail
source "$(dirname "$0")/fixtures/darwin-hosted.sh"
require_hosted_darwin || exit 1
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

owner_uid="$(id -u)"
role_uid="$(id -u "$role")"
[[ "$role_uid" =~ ^[1-9][0-9]*$ && "$owner_uid" != 0 && "$owner_uid" != "$role_uid" ]] || exit 1
[[ ! -e "$plist" && ! -L "$plist" && ! -e "$runtime" && ! -L "$runtime" ]] || exit 1
fixture_job_absent "$label" || { echo 'HQ launchd job exists or cannot be inspected' >&2; exit 1; }
work="$(sudo mktemp -d /Library/hq-owner-ci.XXXXXXXX)"
work_id="$(fixture_inode "$work")"
runtime_id= socket_id= plist_created=false job_started=false
trap cleanup_hq_fixture EXIT
sudo mkdir -m 0755 "$runtime"
runtime_id="$(fixture_inode "$runtime")"
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
sudo chown root:wheel "$work/launch.plist"
sudo chmod 0644 "$work/launch.plist"
# Publish exclusively, retaining the original inode for cleanup.
sudo -n /usr/bin/python3 -I -c 'import os,sys; os.link(sys.argv[1], sys.argv[2])' "$work/launch.plist" "$plist"
plist_created=true
plutil -lint "$plist"
sudo launchctl bootstrap system "$plist"
job_started=true

job_pid() {
  sudo launchctl print "system/$label" | awk '$1 == "pid" && $2 == "=" { print $3 }'
}
check_console_profile() {
  local profile
  profile="$("$system_node" "$entry" status --owner-control | awk '/^profile:/ { print }')" || return 1
  test "$profile" = 'profile: managed-cooperative'
}
# Read only the fixture role's private store. A length and digest carry the
# verified receipt prefix across the restart without exposing receipt contents.
receipt_checkpoint() {
  sudo -n -H -u "$role" "$system_node" --input-type=module - "$state/store.json" "$@" <<'JS'
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { setTimeout } from 'node:timers/promises';

const [file, previous] = process.argv.slice(2);
const [length, digest] = previous ? previous.split(':') : ['0'];
const start = Number(length);
const hash = (rows) => createHash('sha256').update(JSON.stringify(rows)).digest('hex');
const deadline = performance.now() + 5000;
for (;;) {
  let rows;
  try { rows = JSON.parse(readFileSync(file, 'utf8')).receipts; }
  catch (err) { if (err.code !== 'ENOENT' || previous) throw err; }
  if (rows) {
    assert.ok(Array.isArray(rows) && rows.length >= start, 'missing receipt history');
    if (previous) assert.equal(hash(rows.slice(0, start)), digest, 'receipt history changed');
    const added = rows.slice(start);
    for (const [index, row] of added.entries()) {
      assert.equal(row.seq, start + index + 1, 'unexpected receipt sequence');
      assert.equal(row.profile, 'managed-cooperative', 'incorrect receipt profile');
    }
    const starts = added.filter((row) => row.plugin === 'hq' && row.kind === 'hq.started');
    assert.ok(starts.length <= 1, 'more than one HQ start in this observation');
    if (starts.length === 1) {
      console.log(rows.length + ':' + hash(rows));
      break;
    }
  }
  // An owner status call may finish just before hq.started reaches disk.
  assert.ok(performance.now() < deadline, 'HQ startup receipt did not reach disk');
  await setTimeout(50);
}
JS
}
# Only the manager runs as root. This normal CLI runs as the designated owner.
diagnose() {
  sudo cat "$work/launchd.stderr" >&2
  sudo launchctl print "system/$label" | awk '/state =|last exit code =|pid =/ { print }' >&2
  exit 1
}
socket_id="$(python3 - "$socket" <<'PY'
import os
import stat
import sys
import time

path = sys.argv[1]
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
print(f"{sock.st_dev}:{sock.st_ino}")
PY
)" || diagnose
python3 - "$system_node" "$entry" "$owner" "$socket" <<'PY' || diagnose
import json
import os
import subprocess
import sys

node, entry, owner, path = sys.argv[1:]
# Machine apply runs as root with this small environment and invokes the
# CLI as the approved owner. Hosted CI itself starts as the ordinary owner.
result = subprocess.run(["/usr/bin/sudo", "-n", "/usr/bin/env", "-i",
                         "PATH=/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL=C",
                         "/usr/bin/sudo", "-n", "-H", "-u", owner, "--",
                         node, entry, "status", "--owner-control", "--json"],
                        check=True, stdout=subprocess.PIPE, text=True, timeout=30)
status = json.loads(result.stdout)
# The normal launchd command supplies no --plugins override. Match the actual
# host's load report to the independently reviewed source policy in its archive.
with open(os.path.join(os.path.dirname(os.path.dirname(entry)), "governance", "darwin-broker.json")) as manifest:
    broker = json.load(manifest)
loaded = [p for p in status["hq"]["pluginLoad"] if p["name"] == broker["name"]]
assert len(loaded) == 1 and loaded[0]["state"] == "loaded" and not loaded[0].get("dev")
assert (loaded[0]["version"], loaded[0]["digest"]) == (broker["version"], broker["sha256"])

control = status["hq"]["sockets"]["ownerControl"]
assert control["path"] == path and control["peer_check"] == "getpeereid"
assert control["uid"] == os.getuid() and control["account"] == owner
assert status["hq"]["account"] == "_agent-bot-hq" and status["profile"] == "managed-cooperative"
PY
[[ "$(sudo stat -f '%u:%Lp' "$state")" == "$(id -u "$role"):700" ]] || exit 1
pid="$(sudo launchctl print "system/$label" | awk '$1 == "pid" && $2 == "=" { print $3 }')"
[[ "$pid" =~ ^[1-9][0-9]*$ ]] || exit 1
[[ "$(ps -o uid= -p "$pid" | tr -d ' ')" == "$(id -u "$role")" ]] || exit 1
echo "The owner CLI reached the launchd service running as $role with getpeereid authentication."
check_console_profile || exit 1
first_receipts="$(receipt_checkpoint)" || exit 1
[[ "$(job_pid)" == "$pid" ]] || exit 1

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
assert response["result"]["profile"] == "managed-cooperative"
report = response["result"]["hq"]
assert report["account"] == "_agent-bot-hq"
control = report["sockets"]["ownerControl"]
assert control["uid"] == os.getuid() and control["account"] == owner and control["peer_check"] == "getpeereid"
after = os.lstat(path)
assert (before.st_dev, before.st_ino) == (after.st_dev, after.st_ino)
PY
restarted_pid="$(sudo launchctl print "system/$label" | awk '$1 == "pid" && $2 == "=" { print $3 }')"
[[ "$restarted_pid" =~ ^[1-9][0-9]*$ && "$restarted_pid" != "$pid" ]] || exit 1
echo "A pending owner status request reached the restarted HQ through the same launchd socket."
[[ "$(ps -o uid= -p "$restarted_pid" | tr -d ' ')" == "$(id -u "$role")" ]] || exit 1
check_console_profile || exit 1
receipt_checkpoint "$first_receipts" >/dev/null || exit 1
[[ "$(job_pid)" == "$restarted_pid" ]] || exit 1
echo "Both dedicated HQ processes reported managed-cooperative in the owner console and persisted receipts."
