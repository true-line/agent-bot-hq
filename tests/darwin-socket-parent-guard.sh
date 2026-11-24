#!/bin/bash
# Exercise only refusals. A call to a host account or job tool fails the test.
set -eu
if (( EUID == 0 )); then echo 'requires an ordinary test process' >&2; exit 1; fi
here="$(cd "$(dirname "$0")" && pwd -P)"
work="$(mktemp -d)"
trap '/bin/rm -rf "$work"' EXIT
cat > "$work/commands" <<'COMMANDS'
uname() { if [[ "$1" == -s ]]; then echo "$system"; else echo "$arch"; fi; }
sw_vers() { echo "$version"; }
refuse_host_access() { echo touched >> "$trace"; exit 79; }
dscl() { refuse_host_access; }
sudo() { refuse_host_access; }
launchctl() { refuse_host_access; }
COMMANDS
expect_refusal() {
  local mode="$1" invalid="$2" reason="$3"
  if env -i PATH=/usr/bin:/bin HOME="$work" BASH_ENV="$work/commands" trace="$work/trace" \
      GITHUB_ACTIONS=true RUNNER_ENVIRONMENT=github-hosted GITHUB_REPOSITORY=true-line/agent-bot-hq \
      system=Darwin arch=arm64 version=27.0 "$invalid" \
      /bin/bash "$here/darwin-artifact-service-account.sh" "$mode" >"$work/out" 2>&1; then
    exit 1
  else
    test "$?" -eq 1
  fi
  test ! -e "$work/trace"
  grep -Fxq "$reason" "$work/out"
}
for invalid in GITHUB_ACTIONS=false RUNNER_ENVIRONMENT=self-hosted system=Linux; do
  for mode in archive.tar --socket-parent-comparison; do
    expect_refusal "$mode" "$invalid" 'requires a disposable GitHub-hosted macOS runner'
  done
done
for invalid in GITHUB_REPOSITORY=other/repo arch=x86_64 version=15.7; do
  expect_refusal --socket-parent-comparison "$invalid" 'requires the ordinary hosted macOS 27 arm64 socket comparison runner'
done

# A pending comparison keeps the outer fixture's account, stage and home.
(
  source "$here/fixtures/darwin-hosted.sh"
  source "$here/fixtures/darwin-socket-parent.sh"
  stage="$work/retained"
  mkdir "$stage"
  stage_id="$(fixture_inode "$stage")"
  touch "$stage/socket-parent.plist"
  sudo() { echo touched >> "$work/trace"; exit 79; }
  cleanup_socket_parent_fixture
) >"$work/out" 2>&1 && exit 1
test ! -e "$work/trace"
grep -Fxq 'retaining fixture account and files after unconfirmed socket comparison cleanup' "$work/out"
# After a confirmed trial, perform the ordinary cleanup and preserve errors.
source "$here/fixtures/darwin-hosted.sh"
source "$here/fixtures/darwin-socket-parent.sh"
stage="$work/cleared"
mkdir "$stage"
stage_id="$(fixture_inode "$stage")"
cleanup_account_fixture() { echo called >> "$work/calls"; exit "$cleanup_result"; }
for pair in 0:0 9:0 0:1; do
  prior=${pair%:*}
  cleanup_result=${pair#*:}
  result=0
  ( trap cleanup_socket_parent_fixture EXIT; exit "$prior" ) || result=$?
  if (( prior != 0 )); then test "$result" -eq "$prior"; else test "$result" -eq "$cleanup_result"; fi
done
test "$(wc -l < "$work/calls")" -eq 3
/usr/bin/python3 -IB "$here/darwin-socket-parent-cleanup.py"
