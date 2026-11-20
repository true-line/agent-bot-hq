"""Disposable account and filesystem setup for the archived Darwin broker tests."""

from contextlib import ExitStack
import os
from pathlib import Path
import pwd
import re
import stat
import secrets
import subprocess
import sys


ROLE = "_agent-bot-hq"
ROLE_HOME = Path("/private/var/agent-bot-hq")
RUNTIME = Path("/Library/Application Support/ai.true-line.agent-bot-hq")
IPC = RUNTIME / "ipc"


def run(*args):
    return subprocess.check_output(args, text=True, timeout=15)


def root(*args):
    return run("/usr/bin/sudo", "-n", "--", *map(str, args))


def records(kind, field):
    rows = run("/usr/bin/dscl", ".", "-list", "/" + kind, field)
    ids = {}
    for line in rows.splitlines():
        fields = line.rsplit(None, 1)
        if len(fields) == 2:
            ids[fields[0]] = int(fields[1])
    return ids


def names_in(kind):
    return set(run("/usr/bin/dscl", ".", "-list", "/" + kind).splitlines())


def new_record(cleanup, path, **attributes):
    root("/usr/bin/dscl", ".", "-create", path)
    cleanup.callback(root, "/usr/bin/dscl", ".", "-delete", path)
    for key, value in attributes.items():
        root("/usr/bin/dscl", ".", "-create", path, key, str(value))


def new_dir(cleanup, path, owner, mode):
    # No -p, replacement, or recursive cleanup. Register only paths this
    # fixture successfully created, and preserve unexpected children.
    root("/bin/mkdir", "-m", "0700", path)
    cleanup.callback(root, "/bin/rmdir", path)
    root("/usr/sbin/chown", owner, path)
    root("/bin/chmod", mode, path)


def main():
    if not (sys.platform == "darwin" and os.geteuid() != 0
            and os.environ.get("GITHUB_ACTIONS") == "true"
            and os.environ.get("RUNNER_OS") == "macOS"
            and os.environ.get("RUNNER_ENVIRONMENT") == "github-hosted"):
        raise SystemExit("Requires an ordinary user on a disposable GitHub-hosted macOS runner.")
    if len(sys.argv) != 3:
        raise SystemExit("Expected the unpacked HQ root and Node executable.")
    archive, node = map(Path, sys.argv[1:])
    controller = archive / "tests/packaged-darwin-harness-bind.mjs"
    stage = archive.parent
    if not (stage.parent == Path("/private/tmp") and re.fullmatch(r"hq-artifact\.[A-Za-z0-9]{8}", stage.name)
            and archive == stage / "hq" and node.is_absolute() and controller.is_file()
            and (archive / "governance/interim-release.json").is_file()):
        raise SystemExit("Expected the native archive staged by the outer account fixture.")
    stage_stat = stage.lstat()
    if not (stat.S_ISDIR(stage_stat.st_mode) and stage_stat.st_uid == 0 and stage_stat.st_mode & 0o022 == 0):
        raise SystemExit("Expected the native archive and packaged broker test.")
    hq = pwd.getpwnam(ROLE)
    if (hq.pw_uid in (0, os.geteuid()) or Path(hq.pw_dir).resolve() != ROLE_HOME
            or ROLE_HOME.is_symlink() or ROLE_HOME.stat().st_uid != hq.pw_uid):
        raise SystemExit("Requires the fresh dedicated HQ role from the artifact fixture.")
    uids = records("Users", "UniqueID")
    primary = records("Users", "PrimaryGroupID")
    gids = records("Groups", "PrimaryGroupID")
    if (uids.get(ROLE) != hq.pw_uid or primary.get(ROLE) != hq.pw_gid or gids.get(ROLE) != hq.pw_gid):
        raise SystemExit("Dedicated account inventory mismatch.")
    available = sorted(set(range(300, 400)) - set(uids.values()) - set(primary.values()) - set(gids.values()))
    existing = names_in("Users") | names_in("Groups")
    prefix = "_hqb" + secrets.token_hex(3)
    names = [prefix + suffix for suffix in ("a", "b")]
    if (len(available) < 2 or any(name in existing for name in names)
            or os.path.lexists(RUNTIME)
            or any(os.path.lexists("/var/agent-bot-harness-" + name) for name in names)):
        raise SystemExit("Requires two unused service identities and an unused fixture layout.")
    with ExitStack() as cleanup:
        new_dir(cleanup, RUNTIME, "root:wheel", "0755")
        new_dir(cleanup, IPC, "root:wheel", "0755")
        for name, uid in zip(names, available):
            home = "/var/agent-bot-harness-" + name
            new_record(cleanup, "/Groups/" + name, PrimaryGroupID=uid, Password="*")
            new_record(cleanup, "/Users/" + name, UniqueID=uid, PrimaryGroupID=uid,
                       NFSHomeDirectory=home, RealName="Agent Bot Harness",
                       IsHidden="1", UserShell="/usr/bin/false", Password="*")
            if any(run("/usr/bin/id", field, name).strip() != str(uid) for field in ("-u", "-g")):
                raise RuntimeError("Fixture role did not resolve to its assigned IDs.")
            new_dir(cleanup, home, f"{uid}:{uid}", "0700")
            new_dir(cleanup, IPC / name, f"{hq.pw_uid}:{uid}", "2750")
        # The enclosing artifact fixture owns ROLE_HOME and removes its contents.
        state = run("/usr/bin/sudo", "-n", "-H", "-u", ROLE, "--", "/usr/bin/mktemp", "-d",
                    str(ROLE_HOME / "broker-state.XXXXXXXX")).strip()
        subprocess.run([node, controller, archive, state, *names], check=True, timeout=150)


if __name__ == "__main__":
    main()
