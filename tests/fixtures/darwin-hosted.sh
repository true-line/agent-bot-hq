# Shared by the disposable macOS archive fixtures. Bash 3.2 can continue
# after a false compound [[ ]] with errexit, so guards return explicitly.
require_hosted_darwin() {
  if [[ ${GITHUB_ACTIONS:-} != true || ${RUNNER_ENVIRONMENT:-} != github-hosted || "$(uname -s)" != Darwin ]]; then
    echo 'requires a disposable GitHub-hosted macOS runner' >&2
    return 1
  fi
}

# launchctl's absent-service status is 113. Other errors do not establish absence.
fixture_job_absent() {
  local rc
  if sudo -n launchctl print "system/$1" >/dev/null 2>&1; then return 1; else rc=$?; fi
  test "$rc" -eq 113
}

# Only unload a job that launchd identifies by our exact protected plist.
fixture_stop_job() {
  local job="$1" expected="$2" info rc i
  if info="$(sudo -n launchctl print "system/$job" 2>/dev/null)"; then
    if ! awk -v want="$expected" '
      /^\tpath = / { count++; if ($0 == "\tpath = " want) matches++ }
      END { exit !(count == 1 && matches == 1) }
    ' <<<"$info"; then
      echo 'retaining job with an unexpected launchd definition' >&2
      return 1
    fi
  else
    rc=$?
    test "$rc" -eq 113
    return
  fi
  sudo -n launchctl bootout "system/$job" || return 1
  for i in {1..100}; do
    if fixture_job_absent "$job"; then return 0; fi
    sleep 0.05
  done
  echo 'fixture job removal could not be confirmed' >&2
  return 1
}

cleanup_probe_fixture() {
  local rc=$? failed=0
  trap - EXIT
  fixture_stop_job "$label" "$plist" || failed=1
  if (( rc != 0 )); then exit "$rc"; fi
  exit "$failed"
}

fixture_inode() { stat -f '%d:%i' "$1"; }

fixture_same_inode() {
  [[ -n "$2" && ! -L "$1" && "$(fixture_inode "$1")" == "$2" ]] || return 1
}

fixture_record_matches() {
  local record="$1" uuid="$2" observed
  observed="$(sudo -n dscl . -read "$record" GeneratedUID)" || return 1
  if [[ "$observed" != "GeneratedUID: $uuid" ]]; then
    echo 'retaining replaced Directory Services record' >&2
    return 1
  fi
}

fixture_remove_record() {
  fixture_record_matches "$1" "$2" || return 1
  sudo -n dscl . -delete "$1"
}

cleanup_hq_fixture() {
  local rc=$? failed=0
  trap - EXIT
  if "$job_started"; then
    if [[ ! -L "$plist" && "$plist" -ef "$work/launch.plist" ]] && fixture_stop_job "$label" "$plist"; then :
    else
      echo 'retaining fixture state after unverified teardown' >&2
      if (( rc != 0 )); then exit "$rc"; else exit 1; fi
    fi
  elif "$plist_created" && ! fixture_job_absent "$label"; then
    echo 'retaining fixture state after uncertain bootstrap' >&2
    if (( rc != 0 )); then exit "$rc"; else exit 1; fi
  fi
  if "$plist_created"; then
    if [[ ! -L "$plist" && "$plist" -ef "$work/launch.plist" ]]; then sudo rm "$plist" || failed=1
    else failed=1; fi
  fi
  if [[ -n "$runtime_id" ]]; then
    if fixture_same_inode "$runtime" "$runtime_id"; then
      if [[ -S "$socket" ]] && fixture_same_inode "$socket" "$socket_id"; then sudo rm "$socket" || failed=1; fi
      sudo rmdir "$runtime" || failed=1
    else failed=1; fi
  fi
  if fixture_same_inode "$work" "$work_id"; then sudo rm -rf "$work" || failed=1; else failed=1; fi
  if (( rc != 0 )); then exit "$rc"; fi
  exit "$failed"
}

cleanup_account_fixture() {
  local rc=$? failed=0
  trap - EXIT
  for label in ai.true-line.agent-bot-hq ai.true-line.hq.ci-transient-enclave ai.true-line.hq.ci-restart-enclave; do
    if ! fixture_job_absent "$label"; then
      echo 'retaining fixture state while a job is present or unknown' >&2
      if (( rc != 0 )); then exit "$rc"; else exit 1; fi
    fi
  done
  if { "$account_created" && ! fixture_record_matches "$account" "$account_id"; } ||
     { "$group_created" && ! fixture_record_matches "$group" "$group_id"; }; then
    echo 'retaining replaced fixture account or group and its home' >&2
    if (( rc != 0 )); then exit "$rc"; else exit 1; fi
  fi
  if [[ -n "$home_id" ]]; then
    if fixture_same_inode "$home" "$home_id"; then sudo rm -rf "$home" || failed=1; else failed=1; fi
  fi
  if "$account_created"; then fixture_remove_record "$account" "$account_id" || failed=1; fi
  if "$group_created"; then fixture_remove_record "$group" "$group_id" || failed=1; fi
  if fixture_same_inode "$stage" "$stage_id"; then sudo rm -rf "$stage" || failed=1; else failed=1; fi
  if (( rc != 0 )); then exit "$rc"; fi
  exit "$failed"
}
