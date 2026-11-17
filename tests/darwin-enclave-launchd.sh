#!/usr/bin/env bash
# The caller owns the disposable account and stage directory; this script
# owns just its one-shot job in the system launchd domain.
set -euo pipefail
[[ "${GITHUB_ACTIONS:-}" == true && "${RUNNER_ENVIRONMENT:-}" == github-hosted && "$(uname -s)" == Darwin ]]
probe="${1:?compiled probe required}"
stage="${2:?fixture stage required}"
role="${3:?fixture account required}"
home="${4:?fixture home required}"
[[ "$role" == _agent-bot-hq && "$home" == /private/var/agent-bot-hq ]]
uid="$(id -u "$role")"
[[ "$uid" != "$(id -u)" && "$uid" != 0 ]]
challenge="$(node -e 'console.log(require("node:crypto").randomBytes(32).toString("base64"))')"
label=ai.true-line.hq.ci-transient-enclave
plist="$stage/enclave.plist"
sudo install -o root -g wheel -m 0555 "$probe" "$stage/enclave-check"
sudo /usr/bin/tee "$plist" >/dev/null <<PLIST
<?xml version="1.0" encoding="UTF-8"?>
<plist version="1.0"><dict>
  <key>Label</key><string>$label</string>
  <key>UserName</key><string>$role</string>
  <key>GroupName</key><string>$role</string>
  <key>ProgramArguments</key><array><string>$stage/enclave-check</string><string>secure-enclave</string><string>$challenge</string></array>
  <key>WorkingDirectory</key><string>$home</string>
  <key>StandardOutPath</key><string>$home/enclave-observation.json</string>
  <key>StandardErrorPath</key><string>$home/enclave-check.err</string>
  <key>RunAtLoad</key><true/>
</dict></plist>
PLIST
sudo chmod 0644 "$plist"
plutil -lint "$plist"
sudo launchctl bootstrap system "$plist"
trap 'sudo launchctl bootout "system/$label"' EXIT
for _ in {1..30}; do
  status="$(sudo launchctl print "system/$label")"
  if [[ "$status" =~ last\ exit\ code\ =\ ([0-9]+) ]]; then
    if [[ "${BASH_REMATCH[1]}" != 0 ]]; then
      sudo cat "$home/enclave-check.err" >&2
      echo "Secure Enclave probe exited ${BASH_REMATCH[1]} in the system job" >&2
      exit 1
    fi
    sudo cat "$home/enclave-observation.json" | node tests/macos-enclave-observation.mjs "$uid" "$challenge"
    exit 0
  fi
  sleep 1
done
echo "Timed out waiting for the system Secure Enclave probe" >&2
exit 1
