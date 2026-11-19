#!/usr/bin/env bash
# Isolated GitHub-hosted VM only. Exercise the built artifact as a systemd
# service rather than simulating activation variables in the test process.
set -euo pipefail
[[ "${GITHUB_ACTIONS:-}" == true && "${RUNNER_ENVIRONMENT:-}" == github-hosted ]] || exit 1
artifact="${1:?built interim HQ artifact required}"
owner="$(id -un)"
node="$(command -v node)"
stage="$(mktemp -d /tmp/hq-owner-service.XXXXXXXX)"
unit=hq-owner-control-ci
runtime=/run/agent-bot-hq
getent passwd agent-bot-hq >/dev/null && { echo 'unexpected existing HQ account'; exit 1; }
[[ ! -e "$runtime" && ! -e "/run/systemd/system/$unit.socket" && ! -e "/run/systemd/system/$unit.service" ]]
sudo useradd --system --user-group --no-create-home --home-dir "$stage/state" --shell /usr/sbin/nologin agent-bot-hq
cleanup() {
  sudo systemctl stop "$unit.socket" "$unit.service" 2>/dev/null || true
  sudo rm -f "/run/systemd/system/$unit.socket" "/run/systemd/system/$unit.service"
  sudo systemctl daemon-reload
  sudo rm -rf "$stage"
  sudo rmdir "$runtime" 2>/dev/null || true
  sudo userdel agent-bot-hq
}
trap cleanup EXIT
sudo chown root:root "$stage"
sudo chmod 0755 "$stage"
sudo tar -xf "$artifact" -C "$stage"
sudo install -d -m 0700 -o agent-bot-hq -g agent-bot-hq "$stage/state"
sudo install -d -m 0755 -o root -g root "$runtime"
entry="$stage/hq/hq/main.mjs"
[[ "$("$node" "$entry" check-owner-control)" == '{"capability":"linux-owner-control/v1"}' ]]

sudo tee "/run/systemd/system/$unit.socket" >/dev/null <<EOF
[Socket]
ListenStream=$runtime/control.sock
FileDescriptorName=owner-control
SocketUser=$owner
SocketMode=0600
RemoveOnStop=true
EOF
sudo tee "/run/systemd/system/$unit.service" >/dev/null <<EOF
[Unit]
Requires=$unit.socket
After=$unit.socket
[Service]
User=agent-bot-hq
Group=agent-bot-hq
ExecStart="$node" "$entry" run --home "$stage/state" --owner-account "$owner"
EOF
sudo systemctl daemon-reload
sudo systemctl start "$unit.socket"
# Connecting as the regular runner account activates HQ under the service UID.
status="$(timeout 30 "$node" "$entry" status --owner-control --json)" || {
  sudo journalctl -u "$unit.service" --no-pager; exit 1;
}
jq -e --arg owner "$owner" --argjson uid "$(id -u)" '.hq.account == "agent-bot-hq" and .hq.sockets.ownerControl.account == $owner and .hq.sockets.ownerControl.uid == $uid and .hq.sockets.ownerControl.peer_check == "SO_PEERCRED"' <<<"$status" >/dev/null
sudo -u nobody /usr/bin/python3 -I -S - "$runtime/control.sock" <<'PY'
import socket
import sys

with socket.socket(socket.AF_UNIX) as client:
    try:
        client.connect(sys.argv[1])
    except PermissionError:
        pass
    else:
        sys.exit("another account could connect")
PY
if sudo -u agent-bot-hq -- "$node" "$entry" signer rekey --home "$stage/state" > /dev/null 2>"$RUNNER_TEMP/hq-rekey-check"; then
  echo "unexpected rekey while service was active"; exit 1
fi
grep -F 'administrator action in Machine/keyd' "$RUNNER_TEMP/hq-rekey-check" >/dev/null
first_pid="$(systemctl show "$unit.service" -p MainPID --value)"
[[ "$first_pid" != 0 ]]
sudo systemctl stop "$unit.service"
# The manager keeps the pathname and can activate HQ again after a stop.
test -S "$runtime/control.sock"
timeout 30 "$node" "$entry" status --owner-control --json >/dev/null
second_pid="$(systemctl show "$unit.service" -p MainPID --value)"
[[ "$second_pid" != 0 && "$second_pid" != "$first_pid" ]]
sudo systemctl stop "$unit.socket" "$unit.service"
sudo jq -e --arg owner "$owner" --argjson uid "$(id -u)" 'any(.tables[] | select(.[0] == "hq\u0000sessions") | .[1][] | .[1]; .account == $owner and .uid == $uid and .closed_at != null)' "$stage/state/store.json" >/dev/null
# Stopping both units still grants the HQ account no key-maintenance authority.
if sudo -u agent-bot-hq -- "$node" "$entry" signer rekey --home "$stage/state" 2>"$RUNNER_TEMP/hq-rekey-check"; then
  exit 1
fi
grep -F 'administrator action in Machine/keyd' "$RUNNER_TEMP/hq-rekey-check" >/dev/null
