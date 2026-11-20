#!/usr/bin/env bash
# Called within the already provisioned disposable HQ fixture. The staged Node
# driver and native binary are root-owned; the role owns only the fixture data.
set -euo pipefail
source "$(dirname "$0")/fixtures/darwin-hosted.sh"
require_hosted_darwin || exit 1
stage="${1:?fixture stage}" role="${2:?fixture role}" home="${3:?fixture home}"
[[ "$role" == _agent-bot-hq && "$home" == /private/var/agent-bot-hq ]] || exit 1
uid="$(id -u "$role")"
[[ "$uid" != 0 && "$uid" != "$(id -u)" ]] || exit 1
node_bin="$(node -p 'process.execPath')"
probe="$RUNNER_TEMP/hq-fixture-signer"
guard_sources=(helpers/macos-enclave/MachineInstallation.swift helpers/macos-enclave/Standalone.swift)
sources=(helpers/macos-enclave/Signer.swift helpers/macos-enclave/RoleStore.swift)
xcrun swiftc -parse-as-library "${guard_sources[@]}" tests/fixtures/machine-installation/main.swift -o "$RUNNER_TEMP/hq-machine-presence-test"
"$RUNNER_TEMP/hq-machine-presence-test"
xcrun swiftc "${sources[@]}" "${guard_sources[@]}" tests/fixtures/enclave-keychain/main.swift -o "$probe"
bash "$stage/hq/scripts/build-macos-standalone-signer.sh" "$RUNNER_TEMP/hq-release-signer"
sudo install -o root -g wheel -m 0555 "$RUNNER_TEMP/hq-release-signer" "$stage/release-signer"
if sudo -n -H -u "$role" "$stage/release-signer" standalone-v1-status <<< '{}' >"$RUNNER_TEMP/hq-release-status" 2>"$RUNNER_TEMP/hq-release-error"; then
  echo 'Unprovisioned production helper accepted a signer operation' >&2; exit 1
fi
test ! -s "$RUNNER_TEMP/hq-release-status"
grep -Fxq 'HQ Secure Enclave signer unavailable' "$RUNNER_TEMP/hq-release-error"
support="$stage/Application Support"
product="$support/ai.true-line.agent-bot-hq"
declaration="$product/standalone"
fixture="$declaration/hq-signer"
for dir in "$support" "$product" "$declaration"; do sudo install -d -m 0755 -o root -g wheel "$dir"; done
sudo install -o root -g wheel -m 0555 "$probe" "$fixture"
uuid="$(dscl . -read "/Users/$role" GeneratedUID | awk '{print toupper($2)}')"
[[ "$uuid" =~ ^[A-F0-9]{8}-([A-F0-9]{4}-){3}[A-F0-9]{12}$ ]]
printf 'agent-bot-hq/standalone-transition/v1\n' > "$RUNNER_TEMP/hq-transition"
sudo install -o root -g "$role" -m 0640 "$RUNNER_TEMP/hq-transition" "$declaration/transition-v1"
digest="$(shasum -a 256 "$probe" | awk '{print $1}')"
printf 'agent-bot-hq/standalone-signing/v1\nrole=_agent-bot-hq\nuid=%s\nuuid=%s\nno-custom-machine-installation=true\nhelper-sha256=%s\n' "$uid" "$uuid" "$digest" > "$RUNNER_TEMP/hq-declaration"
sudo install -o root -g wheel -m 0644 "$RUNNER_TEMP/hq-declaration" "$declaration/declaration-v1"
if "$fixture" standalone-v1-status <<< '{}' >"$RUNNER_TEMP/hq-foreign-status"; then
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
  <key>ProgramArguments</key><array><string>$node_bin</string><string>$stage/hq/tests/macos-enclave-restart.mjs</string><string>$fixture</string><string>$home</string><string>$uid</string></array>
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
  fixture_job_absent "$label" || exit 1
  sudo launchctl bootstrap system "$plist"
  trap cleanup_probe_fixture EXIT
  for _ in {1..45}; do
    status="$(sudo launchctl print "system/$label")"
    if [[ "$status" =~ last\ exit\ code\ =\ ([0-9]+) ]]; then break; fi
    sleep 1
  done
  if [[ ! "$status" =~ last\ exit\ code\ =\ 0($|[[:space:]]) ]]; then
    sudo cat "$home/restart.err" >&2
    echo "Secure Enclave restart fixture failed on run $iteration" >&2; exit 1
  fi
  fixture_stop_job "$label" "$plist"
  trap - EXIT
done
sudo grep -F 'The restarted HQ job retained its enclave key' "$home/restart.out"
# Retire only the scratch namespace after positive signing and restart.
sudo install -o root -g wheel -m 0644 /dev/null "$declaration/machine-retired-v1"
for op in status sign; do
  if sudo -n -H -u "$role" "$fixture" "standalone-v1-$op" <<< '{"message":"YQ"}' >"$RUNNER_TEMP/hq-retired-result"; then
    echo 'The retired installation still accepted a key operation' >&2; exit 1
  fi
  test ! -s "$RUNNER_TEMP/hq-retired-result"
done
