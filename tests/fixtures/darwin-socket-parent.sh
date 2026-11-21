# Keep the role and files if a comparison job may still depend on them.
cleanup_socket_parent_fixture() {
  local rc=$? cleanup_rc=0
  trap - EXIT
  if ! fixture_same_inode "$stage" "$stage_id" || [[ -e "$stage/socket-parent.plist" || -L "$stage/socket-parent.plist" ]]; then
    echo 'retaining fixture account and files after unconfirmed socket comparison cleanup' >&2
    exit 1
  fi
  ( true; cleanup_account_fixture ) || cleanup_rc=$?
  if (( rc != 0 )); then exit "$rc"; fi
  exit "$cleanup_rc"
}
