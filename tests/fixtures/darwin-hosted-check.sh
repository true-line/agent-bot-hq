#!/bin/bash
# Only inert command models and files created in this private scratch directory.
set -eu
here="$(cd "$(dirname "$0")" && pwd -P)"
source "$here/darwin-hosted.sh"
base="$(mktemp -d /private/tmp/hqgc.XXXXXXXX)"
trap '/bin/rm -rf "$base"' EXIT
export trace="$base/calls"
cat >"$base/commands" <<'COMMANDS'
sudo() { echo sudo >>"$trace"; return 91; }
dscl() { echo dscl >>"$trace"; return 92; }
launchctl() { echo launchctl >>"$trace"; return 93; }
xcrun() { echo xcrun >>"$trace"; return 94; }
COMMANDS
for script in darwin-artifact-service-account darwin-enclave-launchd darwin-enclave-restart darwin-launchd-owner-control; do
  for host in self-hosted github-hosted; do
    actions=false
    if [[ "$host" == self-hosted ]]; then actions=true; fi
    if GITHUB_ACTIONS="$actions" RUNNER_ENVIRONMENT="$host" BASH_ENV="$base/commands" /bin/bash "$here/../$script.sh" >"$base/out" 2>&1; then
      exit 1
    else
      test "$?" -eq 1
    fi
    grep -Fxq 'requires a disposable GitHub-hosted macOS runner' "$base/out"
    test ! -e "$trace"
  done
done

sudo() {
  if [[ "$1" == -n ]]; then shift; fi
  case "$1:$2" in
    launchctl:print)
      if [[ -e "$base/unobservable" ]]; then return 77; fi
      test -f "$base/job" || return 113
      printf 'system/disposable = {\n'
      cat "$base/job"
      printf '}\n' ;;
    launchctl:bootout) : >"$base/stopped"; /bin/rm "$base/job" ;;
    dscl:.)
      case "$3" in
        -read) cat "$base/records/${4##*/}" ;;
        -delete) /bin/rm "$base/records/${4##*/}" ;;
        *) return 98 ;;
      esac ;;
    rm:*|rmdir:*)
      local dest="${!#}"
      case "$dest" in "$base"/*) "/bin/$1" "${@:2}" ;; *) return 97 ;; esac ;;
    *) return 99 ;;
  esac
}
socket_file() { /usr/bin/python3 -I -c 'import socket,sys;s=socket.socket(socket.AF_UNIX);s.bind(sys.argv[1]);s.close()' "$1"; }
model_hq() {
  local dir="$base/$1"
  mkdir "$dir"
  work="$dir/work" runtime="$dir/runtime" plist="$dir/service.plist"
  mkdir "$work" "$runtime"
  work_id="$(fixture_inode "$work")" runtime_id="$(fixture_inode "$runtime")"
  socket="$runtime/owner.sock" label=disposable
  : >"$work/launch.plist"
  ln "$work/launch.plist" "$plist"
  socket_file "$socket"
  socket_id="$(fixture_inode "$socket")"
  job_started=true plist_created=true
  printf '\tpath = %s\n' "$plist" >"$base/job"
  /bin/rm -f "$base/stopped" "$base/unobservable"
}
expect_cleanup() {
  local handler="$1" initial="$2" expected="$3" rc
  if (trap "$handler" EXIT; exit "$initial"); then rc=0; else rc=$?; fi
  test "$rc" -eq "$expected"
}

model_hq success
expect_cleanup cleanup_hq_fixture 0 0
test -f "$base/stopped"; test ! -e "$work"; test ! -e "$runtime"; test ! -e "$plist"
model_hq failed_bootstrap
job_started=false
/bin/rm "$base/job"
expect_cleanup cleanup_hq_fixture 23 23
test ! -e "$base/stopped"; test ! -e "$work"; test ! -e "$runtime"; test ! -e "$plist"
model_hq foreign_job
printf '\tpath = %s\n' "$base/other.plist" >"$base/job"
expect_cleanup cleanup_hq_fixture 23 23
test ! -e "$base/stopped"; test -e "$plist"; test -S "$socket"
model_hq nested_only
printf '\tresources = {\n\t\tpath = %s\n\t}\n' "$plist" >"$base/job"
expect_cleanup cleanup_hq_fixture 23 23
test ! -e "$base/stopped"; test -e "$plist"; test -S "$socket"
model_hq duplicate_path
printf '\tpath = %s\n' "$base/other.plist" >>"$base/job"
expect_cleanup cleanup_hq_fixture 0 1
test ! -e "$base/stopped"; test -e "$plist"; test -S "$socket"
model_hq unknown
: >"$base/unobservable"
expect_cleanup cleanup_hq_fixture 0 1
test ! -e "$base/stopped"; test -e "$plist"; test -S "$socket"
model_hq replaced_plist
: >"$work/new.plist"
mv -f "$work/new.plist" "$plist"
expect_cleanup cleanup_hq_fixture 23 23
test ! -e "$base/stopped"; test -e "$plist"; test -e "$work"
model_hq replaced_socket
socket_file "$work/new.sock"
mv -f "$work/new.sock" "$socket"
expect_cleanup cleanup_hq_fixture 0 1
test -e "$base/stopped"; test -S "$socket"; test -d "$runtime"
model_hq preexisting
plist_created=false job_started=false socket_id= runtime_id=
expect_cleanup cleanup_hq_fixture 23 23
test ! -e "$base/stopped"; test -e "$plist"; test -S "$socket"

rm "$base/job"
group=/Groups/test_group account=/Users/test_role group_id=group-uuid account_id=role-uuid
stage="$base/stage" home="$base/home" records="$base/records"
mkdir "$stage" "$home" "$records"
stage_id="$(fixture_inode "$stage")" home_id="$(fixture_inode "$home")"
account_created=true group_created=true
echo "GeneratedUID: $group_id" >"$records/test_group"
echo "GeneratedUID: replacement" >"$records/test_role"
expect_cleanup cleanup_account_fixture 7 7
test -e "$home"; test -e "$records/test_role"; test -e "$records/test_group"
echo "GeneratedUID: $account_id" >"$records/test_role"
expect_cleanup cleanup_account_fixture 0 0
test ! -e "$home"; test ! -e "$stage"; test ! -e "$records/test_role"; test ! -e "$records/test_group"
