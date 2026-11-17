#!/usr/bin/env bash
set -euo pipefail
[[ "$RUNNER_ENVIRONMENT" == github-hosted && "$(uname -s)" == Darwin ]]
sw_vers; uname -m
owner="$(id -un)"
expected_src=15fcb704ee842fb865fd037afd32c1eaacbfac7e
[[ "$(git -C machine rev-parse HEAD)" == "$expected_src" ]]
[[ "$(git -C identity rev-parse HEAD)" == "2a6edfe6f52733a7c83bddb738fc3eb420ad41b3" ]]
HQ_DIGEST=45c43c574bffc4966481e60d555dca992cd1cc571285dce2b10766f14572efb7
stage="$(sudo mktemp -d /private/var/hq-integration.XXXXXX)"
plist=/Library/LaunchDaemons/ai.true-line.agent-bot-hq.plist
sock=/private/var/agent-bot-hq-control.sock
[[ ! -e "$plist" && ! -L "$plist" && ! -e "$sock" && ! -L "$sock" ]]
! sudo launchctl print system/ai.true-line.agent-bot-hq >/dev/null 2>&1 || exit 1
daemon_pid=
cleanup(){
    if [[ -n "$daemon_pid" ]]; then
        kill "$daemon_pid" 2>/dev/null || true
        wait "$daemon_pid" 2>/dev/null || true
    fi
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
# Use the ordinary Homebrew owner, registered home and shared ARM64 channel.
[[ "$(stat -f %Su /opt/homebrew)" == "$owner" ]]
channel=/opt/homebrew/var/agent-machine
state="$HOME/.config/agent-machine"
approvals="$state/members/approvals"
[[ ! -e "$state" && ! -L "$state" && ! -e "$channel" && ! -L "$channel" ]]
client_home="$(mktemp -d "$RUNNER_TEMP/machine-owner.XXXXXX")"
"$RUNNER_TEMP/mm" daemon run > "$RUNNER_TEMP/mm-daemon.log" 2>&1 &
daemon_pid=$!
for _ in {1..60}; do
    [[ ! -S "$channel/daemon.sock" || ! -f "$channel/daemon.pub" ]] || break
    if ! kill -0 "$daemon_pid" 2>/dev/null; then cat "$RUNNER_TEMP/mm-daemon.log"; exit 1; fi
    sleep 1
done
[[ -S "$channel/daemon.sock" && -f "$channel/daemon.pub" ]] || { cat "$RUNNER_TEMP/mm-daemon.log"; exit 1; }
paired_client(){ "$stage/node" validation/tests/paired-machine-approval-ci.mjs "$client_home" "$channel" "$@"; }
key="$(paired_client prepare)"
pub="$(jq -er .public <<<"$key")"
fingerprint="$(jq -er .fingerprint <<<"$key")"
"$RUNNER_TEMP/mm" daemon pair --enroll "$pub" --fingerprint "$fingerprint" --client agent-daemon --user "$owner" --json |
    jq -e --arg uid "$(id -u)" '.state=="paired" and .client=="agent-daemon" and (.uid|tostring)==$uid'
for attempt in 1 2; do
    plan="$("$RUNNER_TEMP/mm" members plan --hq-service "$record")"
    summary="${plan%%$'\n'*}"
    id="$(jq -r .plan_id <<<"$summary")"
    digest="$(jq -r .plan_digest <<<"$summary")"
    if [[ "$attempt" == 2 ]]; then [[ "$(jq -r .changes <<<"$summary")" == 0 ]]; fi
    [[ ! -e "$approvals/$id.json" ]]
    paired_client approve "$id" "$digest" > "$RUNNER_TEMP/verified-approval.json"
    jq -e --slurp 'length==2 and .[0]==.[1]' "$RUNNER_TEMP/verified-approval.json" "$approvals/$id.json"
    sudo "$RUNNER_TEMP/mm" members apply "$id"
    sudo jq -e --arg id "$id" --arg digest "$digest" '.result=="applied" and .plan_id==$id and .plan_digest==$digest' "/var/db/managed-machine/members/receipts/$id.json"
    "$stage/node" "$stage/hq/hq/main.mjs" status --owner-control --json > "$RUNNER_TEMP/status"
    jq -e --arg owner "$owner" --argjson uid "$(id -u)" '.hq.account=="_agent-bot-hq" and .profile=="managed-cooperative" and .hq.sockets.ownerControl.peer_check=="getpeereid" and .hq.sockets.ownerControl.account==$owner and .hq.sockets.ownerControl.uid==$uid' "$RUNNER_TEMP/status"
    pid="$(sudo launchctl print system/ai.true-line.agent-bot-hq | awk '$1=="pid" && $2=="="{print $3}')"
    [[ "$(ps -o uid= -p "$pid" | tr -d ' ')" == "$(id -u _agent-bot-hq)" ]]
    if [[ "$attempt" == 2 ]]; then [[ "$pid" == "$original_pid" ]]; fi
    original_pid="$pid"
    echo "attempt=$attempt approved plan $id receipt applied, live owner status and launchd pid $pid verified"
done
