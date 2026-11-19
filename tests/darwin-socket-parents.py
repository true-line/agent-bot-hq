"""Hosted-only comparison of two pathname parents using identical system jobs."""

import os
from pathlib import Path
import plistlib
import re
import secrets
import socket
import stat
import subprocess
import sys
import tempfile
import time


ROLE = "_agent-bot-hq"
CANDIDATE = Path("/Library/Application Support/ai.true-line.agent-bot-hq")


def sudo(*args, check=True):
    return subprocess.run(["/usr/bin/sudo", "-n", *args], check=check,
                          stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=15)


def sip_state():
    result = subprocess.run(["/usr/bin/csrutil", "status"], capture_output=True, text=True)
    for value in ("enabled", "disabled"):
        if result.returncode == 0 and result.stdout.strip() == f"System Integrity Protection status: {value}.":
            return value
    return "custom" if "custom configuration" in result.stdout.lower() else "unknown"


def root_directory(path):
    entry = path.lstat()
    return stat.S_ISDIR(entry.st_mode) and entry.st_uid == 0 and not entry.st_mode & 0o022


def native_refusal(journal):
    events = journal.read_bytes().splitlines()
    if b"role" in events:
        for event in events:
            match = re.fullmatch(rb"native=(-?[0-9]{1,10})", event)
            if match and int(match[1]) != 0:
                return f"native-refusal {int(match[1])}"
    return None


def observe(endpoint, journal):
    nonce = secrets.token_bytes(32)
    deadline = time.monotonic() + 10
    while time.monotonic() < deadline:
        refusal = native_refusal(journal)
        if refusal:
            return refusal
        try:
            entry = endpoint.lstat()
        except FileNotFoundError:
            time.sleep(.05)
            continue
        if not (stat.S_ISSOCK(entry.st_mode) and entry.st_uid == 0 and stat.S_IMODE(entry.st_mode) == 0o666):
            return "unexpected socket metadata"
        with socket.socket(socket.AF_UNIX) as client:
            client.settimeout(4)
            try:
                client.connect(str(endpoint))
                client.sendall(nonce)
                with client.makefile("rb") as response:
                    if response.read(32) != nonce:
                        return native_refusal(journal) or "owner round trip failed"
            except ConnectionRefusedError:
                time.sleep(.05)
                continue
            except OSError:
                return native_refusal(journal) or "owner round trip failed"
        events = journal.read_bytes().splitlines()
        return "passed" if events == [b"role", b"native=0", b"descriptor"] else "descriptor evidence missing"
    return native_refusal(journal) or "publication timed out"


def run_trial(stage, parent):
    token = secrets.token_hex(6)
    label = "ai.true-line.agent-bot-hq-ci." + token
    target = "system/" + label
    endpoint = parent / ("hq-ci-" + token + ".sock")
    plist = Path("/Library/LaunchDaemons") / (label + ".plist")
    journal = stage / (token + ".result")
    if any(os.path.lexists(p) for p in (plist, endpoint, journal)) or sudo("/bin/launchctl", "print", target, check=False).returncode == 0:
        raise RuntimeError("disposable trial collision")
    config = {"Label": label, "UserName": ROLE, "GroupName": ROLE, "Umask": 0o077,
              "ProgramArguments": ["/usr/bin/ruby", "--disable-gems", str(stage / "darwin-socket-parent-probe.rb"),
                                   str(journal), str(os.getuid())],
              "Sockets": {"owner-control": {"SockType": "stream", "SockPathName": str(endpoint), "SockPathMode": 0o666}}}
    sudo("/usr/bin/install", "-o", ROLE, "-g", ROLE, "-m", "0644", "/dev/null", journal)
    with tempfile.NamedTemporaryFile() as source:
        plistlib.dump(config, source)
        source.flush()
        sudo("/usr/bin/install", "-o", "root", "-g", "wheel", "-m", "0644", source.name, plist)
    loaded = False
    try:
        if sudo("/bin/launchctl", "bootstrap", "system", plist, check=False).returncode != 0:
            return "bootstrap refused"
        loaded = True
        return observe(endpoint, journal)
    finally:
        if loaded or sudo("/bin/launchctl", "print", target, check=False).returncode == 0:
            sudo("/bin/launchctl", "bootout", target)
        try:
            entry = endpoint.lstat()
        except FileNotFoundError:
            entry = None
        if entry is not None:
            if not stat.S_ISSOCK(entry.st_mode) or entry.st_uid != 0:
                raise RuntimeError("unexpected disposable endpoint during cleanup")
            sudo("/bin/rm", "-f", endpoint)
        sudo("/bin/rm", plist)


def main():
    if (sys.platform != "darwin" or os.getuid() == 0 or os.getenv("GITHUB_ACTIONS") != "true" or
            os.getenv("RUNNER_ENVIRONMENT") != "github-hosted" or os.getenv("GITHUB_REPOSITORY") != "true-line/agent-bot-hq"):
        raise RuntimeError("requires the disposable hosted macOS runner")
    stage = Path(sys.argv[1])
    if (not root_directory(stage) or not all(root_directory(p) for p in CANDIDATE.parents)
            or os.path.lexists(CANDIDATE)):
        raise RuntimeError("unexpected initial fixture directories")
    print("System Integrity Protection:", sip_state(), flush=True)
    sudo("/bin/mkdir", "-m", "0755", CANDIDATE)
    try:
        sudo("/usr/sbin/chown", "root:wheel", CANDIDATE)
        metadata = CANDIDATE.lstat()
        if not root_directory(CANDIDATE) or metadata.st_gid != 0 or stat.S_IMODE(metadata.st_mode) != 0o755:
            raise RuntimeError("unexpected product directory metadata")
        for name, parent in (("previous", Path("/private/var")), ("candidate", CANDIDATE)):
            result = run_trial(stage, parent)
            print(f"{name} parent: {result}", flush=True)
            if name == "candidate" and result != "passed":
                return 1
    finally:
        sudo("/bin/rmdir", CANDIDATE)
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (RuntimeError, OSError, subprocess.SubprocessError):
        sys.exit("Socket parent comparison failed during fixture setup or cleanup.")
