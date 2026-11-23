"""Set up the two temporary macOS broker identities and listeners on hosted CI."""
from contextlib import ExitStack
import json
import os
from pathlib import Path
import secrets
import shutil
import socket
import subprocess
import sys
import tempfile


def run(*args):
    return subprocess.check_output(args, text=True, timeout=15)


def dscl(*args):
    run("/usr/bin/sudo", "-n", "/usr/bin/dscl", ".", *args)


def records(kind, attribute):
    rows = run("/usr/bin/dscl", ".", "-list", "/" + kind, attribute)
    return {row.split()[0]: int(row.split()[1]) for row in rows.splitlines()
            if len(row.split()) == 2}


def create_record(stack, path, attributes):
    dscl("-create", path)
    stack.callback(dscl, "-delete", path)
    for attribute, value in attributes.items():
        dscl("-create", path, attribute, str(value))


def main():
    if (sys.platform != "darwin" or os.getuid() == 0 or
            os.environ.get("RUNNER_ENVIRONMENT") != "github-hosted" or
            os.environ.get("GITHUB_ACTIONS") != "true"):
        raise SystemExit("This test requires a disposable GitHub-hosted macOS runner.")
    tests = Path(__file__).resolve().parent
    users = records("Users", "UniqueID")
    groups = records("Groups", "PrimaryGroupID")
    unused = sorted(set(range(300, 400)) - set(users.values()) - set(groups.values()))
    if len(unused) < 2:
        raise SystemExit("two unused fixture IDs are required")
    with tempfile.TemporaryDirectory(prefix="hq-broker-", dir="/private/tmp") as temp, ExitStack() as stack:
        root = Path(temp)
        client = root / "member-client.mjs"
        shutil.copyfile(tests / client.name, client)
        client.chmod(0o644)
        endpoints = []
        sockets = []
        prefix = "_hqb" + secrets.token_hex(4)
        for suffix, uid in zip(("a", "b"), unused):
            name = prefix + suffix
            if name in users or name in groups:
                raise RuntimeError("fixture name already in use")
            create_record(stack, "/Groups/" + name, {"PrimaryGroupID": uid, "Password": "*"})
            create_record(stack, "/Users/" + name, {
                "UniqueID": uid, "PrimaryGroupID": uid, "UserShell": "/usr/bin/false",
                "NFSHomeDirectory": "/var/empty", "Password": "*", "IsHidden": 1,
            })
            if (int(run("/usr/bin/id", "-u", name)) != uid or
                    int(run("/usr/bin/id", "-g", name)) != uid):
                raise RuntimeError("fixture account did not resolve to its assigned IDs")
            parent = root / name
            parent.mkdir(mode=0o700)
            run("/usr/bin/sudo", "-n", "/usr/sbin/chown", f"{os.getuid()}:{uid}", str(parent))
            run("/usr/bin/sudo", "-n", "/bin/chmod", "2750", str(parent))
            listener = stack.enter_context(socket.socket(socket.AF_UNIX, socket.SOCK_STREAM))
            path = parent / "broker.sock"
            listener.bind(str(path))
            listener.listen()
            path.chmod(0o660)
            sockets.append(listener.fileno())
            endpoints.append({"account": name, "uid": uid, "gid": uid, "path": str(path), "fd": listener.fileno()})
        root.chmod(0o711)
        subprocess.run([shutil.which("node"), str(tests / "darwin-broker-accounts.mjs"), temp,
                        json.dumps(endpoints)], check=True, pass_fds=sockets, timeout=75)


if __name__ == "__main__":
    main()
