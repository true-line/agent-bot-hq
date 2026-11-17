"""Linux socket checks for the systemd owner endpoint. No input from the wire."""
import os
import socket
import struct
import sys


def peer_uid(connection):
    fmt = "iII"  # Linux struct ucred: pid_t, uid_t, gid_t.
    credentials = connection.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, struct.calcsize(fmt))
    pid, uid, _ = struct.unpack(fmt, credentials)
    return uid if pid > 0 else None


if sys.argv[1:] == ["probe"]:
    left, right = socket.socketpair()
    with left, right:
        sys.exit(0 if peer_uid(left) == os.getuid() else 1)

with socket.socket(fileno=3) as sock:
    if sock.family != socket.AF_UNIX or sock.getsockopt(socket.SOL_SOCKET, socket.SO_TYPE) != socket.SOCK_STREAM:
        sys.exit(1)
    listening = sock.getsockopt(socket.SOL_SOCKET, socket.SO_ACCEPTCONN)
    if sys.argv[1] == "listener":
        sys.exit(0 if listening and sock.getsockname() == sys.argv[2] else 1)
    if sys.argv[1] == "peer":
        sys.exit(0 if not listening and peer_uid(sock) == int(sys.argv[2]) else 1)
    sys.exit(1)
