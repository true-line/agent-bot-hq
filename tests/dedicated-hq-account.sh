#!/usr/bin/env bash
# Run from the unpacked, offline artifact as the CI-created service account.
set -euo pipefail
node_bin="${1:?pass the Node executable}"
test "$(id -un)" = agent-bot-hq
uid="$(id -u)"
test "$uid" -ne 0
test "$(stat -c '%u:%a' "$HOME")" = "$uid:700"
umask 077
state="$(mktemp -d "$HOME/hq-state.XXXXXXXX")"
"$node_bin" hq/main.mjs run --home "$state" >"$state/run.log" 2>&1 &
hq_pid=$!
cleanup() {
  kill "$hq_pid" 2>/dev/null || true
  wait "$hq_pid" 2>/dev/null || true
  rm -rf "$state"
}
trap cleanup EXIT

ready=false
for _ in {1..100}; do
  if ! kill -0 "$hq_pid" 2>/dev/null; then cat "$state/run.log" >&2; exit 1; fi
  if [[ -S "$state/control.sock" ]] && "$node_bin" hq/main.mjs status --home "$state" --json >"$state/status.json" 2>"$state/status.err"; then
    ready=true
    break
  fi
  sleep 0.1
done
if [[ "$ready" != true ]]; then
  cat "$state/run.log" >&2
  echo 'HQ did not answer status on the control socket' >&2
  exit 1
fi
test "$(stat -c '%u' "/proc/$hq_pid")" = "$uid"
"$node_bin" --input-type=module - "$state" <<'JS'
import assert from 'node:assert/strict';
import { readFileSync, statSync } from 'node:fs';
import { join } from 'node:path';

const state = process.argv[2];
const status = JSON.parse(readFileSync(join(state, 'status.json'), 'utf8'));
assert.equal(status.hq.account, 'agent-bot-hq');
assert.equal(status.hq.sockets.control, join(state, 'control.sock'));
assert.equal(status.mode, 'safe');
assert.equal(status.admissions, false);
assert.equal(status.profile, 'managed-cooperative');
for (const [name, mode] of [['.', 0o700], ['control.sock', 0o600], ['store.json', 0o600]]) {
  const entry = statSync(join(state, name));
  assert.equal(entry.uid, process.getuid(), name);
  assert.equal(entry.mode & 0o777, mode, name);
}
console.log('HQ served status as agent-bot-hq with private state, store and control socket.');
JS
