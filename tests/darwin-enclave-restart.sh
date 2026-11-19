#!/usr/bin/env bash
# Called within the already provisioned disposable HQ fixture. The staged Node
# driver and native binary are root-owned; the role owns only the fixture data.
set -euo pipefail
[[ "${GITHUB_ACTIONS:-}" == true && "${RUNNER_ENVIRONMENT:-}" == github-hosted && "$(uname -s)" == Darwin ]]
stage="${1:?fixture stage}" role="${2:?fixture role}" home="${3:?fixture home}"
[[ "$role" == _agent-bot-hq && "$home" == /private/var/agent-bot-hq ]]
uid="$(id -u "$role")"
[[ "$uid" != 0 && "$uid" != "$(id -u)" ]]
node_bin="$(node -p 'process.execPath')"
probe="$RUNNER_TEMP/hq-fixture-signer"
installation=helpers/macos-enclave/MachineInstallation.swift
sources=(helpers/macos-enclave/Signer.swift helpers/macos-enclave/RoleStore.swift)
xcrun swiftc -parse-as-library "$installation" tests/fixtures/machine-installation/main.swift -o "$RUNNER_TEMP/hq-machine-presence-test"
"$RUNNER_TEMP/hq-machine-presence-test"
sudo install -o root -g wheel -m 0555 "$RUNNER_TEMP/hq-machine-presence-test" "$stage/presence-test"
reason="$(sudo -n -H -u "$role" "$stage/presence-test" standard-reason)"
xcrun swiftc "${sources[@]}" tests/fixtures/enclave-keychain/main.swift -o "$probe"
xcrun swiftc "${sources[@]}" "$installation" helpers/macos-enclave/main.swift -o "$RUNNER_TEMP/hq-release-signer"
sudo install -o root -g wheel -m 0555 "$RUNNER_TEMP/hq-release-signer" "$stage/release-signer"
if sudo -n -H -u "$role" "$stage/release-signer" status <<< '{}' >"$RUNNER_TEMP/hq-release-status" 2>"$RUNNER_TEMP/hq-release-error"; then
  echo 'Unprovisioned production helper accepted a signer operation' >&2; exit 1
fi
test ! -s "$RUNNER_TEMP/hq-release-status"
grep -Fxq -- "$reason" "$RUNNER_TEMP/hq-release-error"
sudo install -o root -g wheel -m 0555 "$probe" "$stage/fixture-signer"
if "$stage/fixture-signer" status <<< '{}' >"$RUNNER_TEMP/hq-foreign-status"; then
  echo 'A foreign UID was allowed to use the HQ signer' >&2; exit 1
fi
test ! -s "$RUNNER_TEMP/hq-foreign-status"
label=ai.true-line.hq.ci-restart-enclave
plist="$stage/enclave-restart.plist"
sudo /usr/bin/tee "$plist" >/dev/null <<PLIST
<?xml version="1.0" encoding="UTF-8"?>
<plist version="1.0"><dict>
  <key>Label</key><string>$label</string>
  <key>UserName</key><string>$role</string>
  <key>GroupName</key><string>$role</string>
  <key>ProgramArguments</key><array><string>$node_bin</string><string>$stage/hq/tests/macos-enclave-restart.mjs</string><string>$stage/fixture-signer</string><string>$home</string><string>$uid</string></array>
  <key>WorkingDirectory</key><string>$home</string>
  <key>StandardOutPath</key><string>$home/restart.out</string>
  <key>StandardErrorPath</key><string>$home/restart.err</string>
  <key>RunAtLoad</key><true/>
</dict></plist>
PLIST
sudo chmod 0644 "$plist"
plutil -lint "$plist"
# Boot out between runs to clear launchd's last exit code and terminate the
# service context. Only the scoped test Keychain, pin, and public evidence survive.
for iteration in 1 2; do
  sudo launchctl bootstrap system "$plist"
  trap 'sudo launchctl bootout "system/$label"' EXIT
  for _ in {1..45}; do
    status="$(sudo launchctl print "system/$label")"
    if [[ "$status" =~ last\ exit\ code\ =\ ([0-9]+) ]]; then break; fi
    sleep 1
  done
  if [[ ! "$status" =~ last\ exit\ code\ =\ 0($|[[:space:]]) ]]; then
    sudo cat "$home/restart.err" >&2
    echo "Secure Enclave restart fixture failed on run $iteration" >&2; exit 1
  fi
  sudo launchctl bootout "system/$label"
  trap - EXIT
done
sudo grep -F 'The restarted HQ job retained its enclave key' "$home/restart.out"
