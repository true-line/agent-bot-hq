#!/usr/bin/env bash
# Create a temporary role account only on a fresh hosted macOS test VM.
if (( EUID == 0 )); then
  echo "requires an ordinary user on a disposable GitHub-hosted macOS runner" >&2
  exit 1
fi
set -euo pipefail
source "$(dirname "$0")/fixtures/darwin-hosted.sh"
require_hosted_darwin || exit 1
archive="${1:?macOS target tar required}"
name=_agent-bot-hq
account="/Users/$name"
group="/Groups/$name"
home=/private/var/agent-bot-hq
# A failed lookup is not evidence that a record is available.
users="$(dscl . -list /Users UniqueID)"
groups="$(dscl . -list /Groups PrimaryGroupID)"
all_users="$(dscl . -list /Users)"
all_groups="$(dscl . -list /Groups)"
if grep -Fxq "$name" <<<"$all_users" || grep -Fxq "$name" <<<"$all_groups" || [[ -e "$home" || -L "$home" ]]; then
  echo 'an existing HQ installation occupies this runner'; exit 1
fi
for number in {300..399}; do
  if ! awk -v n="$number" '$NF == n { used=1 } END { exit !used }' <<<"$users
$groups"; then role_id="$number"; break; fi
done
: "${role_id:?no unused service ID}"
stage="$(sudo mktemp -d /private/tmp/hq-artifact.XXXXXXXX)"
stage_id="$(fixture_inode "$stage")"
account_id="$(uuidgen)" group_id="$(uuidgen)"
account_created=false group_created=false home_id=
trap cleanup_account_fixture EXIT
sudo dscl . -create "$group" GeneratedUID "$group_id"
group_created=true
sudo dscl . -create "$group" PrimaryGroupID "$role_id"
sudo dscl . -create "$group" Password '*'
sudo dscl . -create "$account" GeneratedUID "$account_id"
account_created=true
sudo dscl . -create "$account" UniqueID "$role_id"
sudo dscl . -create "$account" PrimaryGroupID "$role_id"
sudo dscl . -create "$account" NFSHomeDirectory "$home"
sudo dscl . -create "$account" UserShell /usr/bin/false
sudo dscl . -create "$account" Password '*'
sudo dscl . -create "$account" IsHidden 1
sudo mkdir -m 0700 "$home"
home_id="$(fixture_inode "$home")"
sudo chown "$name:$name" "$home"
sudo chmod 0755 "$stage"
sudo tar -xf "$archive" -C "$stage"
# Keep the installed executable next to its native runtime libraries.
node_bin="$(node -p 'process.execPath')"
sudo -n -H -u "$name" -- "$node_bin" --version
if [[ "${2:?compiled enclave probe or --launchd-only required}" != --launchd-only ]]; then
  bash tests/darwin-enclave-launchd.sh "$2" "$stage" "$name" "$home"
  bash tests/darwin-enclave-restart.sh "$stage" "$name" "$home"
fi
cd "$stage/hq"
# Exercise the packaged HQ entry point as the runner's login account before
# switching to the dedicated role. Standalone custody must refuse at startup.
"$node_bin" --input-type=module - <<'JS'
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { existsSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { userInfo } from 'node:os';
import { join } from 'node:path';

assert.notEqual(userInfo().username, '_agent-bot-hq');
assert.notEqual(process.getuid(), 0);
const state = mkdtempSync('/private/tmp/hq-ordinary.');
try {
  writeFileSync(join(state, 'config.json'), JSON.stringify({ standalone: true, signer: { backend: 'secure-enclave' } }));
  const result = spawnSync(process.execPath, ['hq/main.mjs', 'run', '--home', state], {
    encoding: 'utf8', timeout: 10000, killSignal: 'SIGKILL',
  });
  if (result.error) throw result.error;
  assert.equal(result.status, 1);
  assert.ok(result.stdout === '', 'unexpected standalone response');
  const expected = 'standalone Secure Enclave signing requires a verified dedicated-account installation without Agent Machine';
  assert.ok(result.stderr.trim() === expected, 'unexpected standalone refusal');
  for (const file of ['signer/pin.json', 'signer/device-key.pem', 'control.sock']) {
    assert.equal(existsSync(join(state, file)), false, file);
  }
} finally {
  rmSync(state, { recursive: true, force: true });
}
JS
sudo -n -H -u "$name" -- /bin/bash tests/dedicated-hq-account.sh "$node_bin" --disposable-machine-role
bash tests/darwin-launchd-owner-control.sh "$node_bin"
python3 -I tests/packaged-darwin-harness-accounts.py "$stage/hq" "$node_bin"
