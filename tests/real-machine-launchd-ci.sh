#!/usr/bin/env bash
set -euo pipefail
[[ "$RUNNER_ENVIRONMENT" == github-hosted && "$(uname -s)" == Darwin ]]
sw_vers; uname -m
owner="$(id -un)"
expected_src=806f952cd0389e2af9fbb00390e335d760e19d81
[[ "$(git -C machine rev-parse HEAD)" == "$expected_src" ]]
HQ_DIGEST=45c43c574bffc4966481e60d555dca992cd1cc571285dce2b10766f14572efb7
stage="$(sudo mktemp -d /private/var/hq-integration.XXXXXX)"
plist=/Library/LaunchDaemons/ai.true-line.agent-bot-hq.plist
sock=/private/var/agent-bot-hq-control.sock
[[ ! -e "$plist" && ! -L "$plist" && ! -e "$sock" && ! -L "$sock" ]]
! sudo launchctl print system/ai.true-line.agent-bot-hq >/dev/null 2>&1 || exit 1
cleanup(){
    sudo launchctl bootout system/ai.true-line.agent-bot-hq 2>/dev/null || true
    sudo rm -f "$plist" "$sock"
    sudo rm -rf "$stage"
}
trap cleanup EXIT
sudo chmod 0755 "$stage"
cd machine
go build -o "$RUNNER_TEMP/mm" ./cmd/managed-machine
cd ..
gzip -dc validation/tests/fixtures/hq-integration-input.tar.gz > "$RUNNER_TEMP/hq.tar"
printf '%s  %s\n' "$HQ_DIGEST" "$RUNNER_TEMP/hq.tar" | shasum -a 256 --check
sudo install -o root -g wheel -m 0644 "$RUNNER_TEMP/hq.tar" "$stage/approved.tar"
sudo tar -xf "$stage/approved.tar" -C "$stage"
jq -e '.target_platform=="darwin" and .hq_commit=="ad66284e258175f89f08e7a4a095c78f36f47aa9"' "$stage/hq/governance/interim-release.json"
nv=v22.14.0
name="node-$nv-darwin-arm64.tar.gz"
( cd "$RUNNER_TEMP"
  u="https://nodejs.org/dist/$nv"
  curl -fsSLO "$u/$name"
  curl -fsSL "$u/SHASUMS256.txt" | awk -v n="$name" '$2==n' > SHA256.expected
  test -s SHA256.expected
  shasum -a 256 --check SHA256.expected
  tar -xf "$name" "node-$nv-darwin-arm64/bin/node"
)
sudo install -o root -g wheel -m 0755 "$RUNNER_TEMP/node-$nv-darwin-arm64/bin/node" "$stage/node"
n="$(shasum -a 256 "$stage/node" | awk '{print $1}')"
"$stage/node" --version
otool -L "$stage/node"
printf 'HQ source=%s tar=%s Machine=%s Node=%s\n' ad66284e258175f89f08e7a4a095c78f36f47aa9 "$HQ_DIGEST" "$expected_src" "$n"
record="$RUNNER_TEMP/service.json"
jq -n --arg root "$stage" --arg a "$HQ_DIGEST" --arg n "$n" '{archive:($root+"/approved.tar"),release_dir:($root+"/hq"),artifact_sha256:$a,node:($root+"/node"),node_sha256:$n}' > "$record"
da="$owner"
for prefix in /opt/homebrew /usr/local/Homebrew; do
    if [ -e "$prefix" ]; then da="$(stat -f %Su "$prefix")"; break; fi
done
dh="$(dscl . -read "/Users/$da" NFSHomeDirectory | sed 's/^NFSHomeDirectory: //')"
approvals="$dh/.config/agent-machine/members/approvals"
d(){ if [[ "$da" == "$owner" ]]; then "$@"; else sudo -u "$da" "$@"; fi; }
for attempt in 1 2; do
    plan="$("$RUNNER_TEMP/mm" members plan --hq-service "$record")"
    summary="${plan%%$'\n'*}"
    id="$(jq -r .plan_id <<<"$summary")"
    digest="$(jq -r .plan_digest <<<"$summary")"
    if [[ "$attempt" == 2 ]]; then [[ "$(jq -r .changes <<<"$summary")" == 0 ]]; fi
    # Use the same synthetic approval-record boundary as Machine's disposable
    # account CI. The real root command consumes it and writes its own receipt.
    d mkdir -p "$approvals"
    d chmod 700 "$dh/.config/agent-machine" "$dh/.config/agent-machine/members" "$approvals"
    jq -n --arg id "$id" --arg dig "$digest" --arg now "$(date -u +%FT%TZ)" --arg exp "$(date -u -v+10M +%FT%TZ)" '{plan_id:$id,plan_digest:$dig,approved_at:$now,expires_at:$exp}' > "$RUNNER_TEMP/approval"
    chmod 644 "$RUNNER_TEMP/approval"
    d cp "$RUNNER_TEMP/approval" "$approvals/$id.json"; d chmod 600 "$approvals/$id.json"
    sudo "$RUNNER_TEMP/mm" members apply "$id"
    sudo jq -e '.result=="applied"' "/var/db/managed-machine/members/receipts/$id.json"
    "$stage/node" "$stage/hq/hq/main.mjs" status --owner-control --json > "$RUNNER_TEMP/status"
    jq -e --arg owner "$owner" --argjson uid "$(id -u)" '.hq.account=="_agent-bot-hq" and .profile=="managed-cooperative" and .hq.sockets.ownerControl.peer_check=="getpeereid" and .hq.sockets.ownerControl.account==$owner and .hq.sockets.ownerControl.uid==$uid' "$RUNNER_TEMP/status"
    pid="$(sudo launchctl print system/ai.true-line.agent-bot-hq | awk '$1=="pid" && $2=="="{print $3}')"
    [[ "$(ps -o uid= -p "$pid" | tr -d ' ')" == "$(id -u _agent-bot-hq)" ]]
    if [[ "$attempt" == 2 ]]; then [[ "$pid" == "$original_pid" ]]; fi
    original_pid="$pid"
    echo "attempt=$attempt approved plan $id receipt applied, live owner status and launchd pid $pid verified"
done
