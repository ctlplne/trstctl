"""Wait for PostgreSQL on the same host port the restore binary will use.

The container's pg_isready can see PostgreSQL's temporary init server while
Docker's published port is resetting connections. A PostgreSQL SSLRequest has
an unambiguous one-byte response before authentication, so this probe needs no
password and does not create database state.
"""

import socket
import struct
import sys
import time

SSL_REQUEST = struct.pack("!II", 8, 80877103)


def postgres_handshake(port: int) -> bool:
    try:
        with socket.create_connection(("127.0.0.1", port), timeout=1) as connection:
            connection.settimeout(1)
            connection.sendall(SSL_REQUEST)
            return connection.recv(1) in (b"N", b"S")
    except (OSError, TimeoutError):
        return False


def wait_ready(port: int, *, timeout: float = 60, interval: float = 1) -> bool:
    deadline = time.monotonic() + timeout
    consecutive = 0
    while time.monotonic() < deadline:
        consecutive = consecutive + 1 if postgres_handshake(port) else 0
        if consecutive >= 2:
            return True
        time.sleep(min(interval, max(0, deadline - time.monotonic())))
    return False


if __name__ == "__main__":
    if len(sys.argv) != 2:
        raise SystemExit("usage: restore_postgres_ready.py HOST_PORT")
    host_port = int(sys.argv[1])
    if not 1 <= host_port <= 65535:
        raise SystemExit("PostgreSQL host port out of range")
    raise SystemExit(0 if wait_ready(host_port) else 1)
