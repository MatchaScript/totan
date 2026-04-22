#!/usr/bin/env python3
"""Mock HTTP proxy used by e2e tests.

Supports two request shapes that totan produces upstream:

- **Plain HTTP** (`GET http://host/path HTTP/1.1`): respond 200 with a body
  `"<proxy-id>:<target>"` so tests can assert both (a) the request reached a
  proxy at all and (b) the *correct* proxy was chosen (for PAC routing tests).

- **CONNECT** (`CONNECT host:port HTTP/1.1`): respond 200 and close. We do not
  actually tunnel to a TLS backend — the test only verifies that the CONNECT
  line arrived at the expected proxy, which it reads from the logfile.

Environment:
    PORT      TCP port to bind (127.0.0.1)
    PROXY_ID  Identity string embedded in plain-HTTP responses and log lines
    LOGFILE   Path to append request log (one line per request)
"""

import os
import socket
import sys
import threading


PORT = int(os.environ.get("PORT", "8880"))
PROXY_ID = os.environ.get("PROXY_ID", "proxy-default")
LOGFILE = os.environ.get("LOGFILE", f"/tmp/mock-proxy-{PORT}.log")

_log_lock = threading.Lock()


def log(msg: str) -> None:
    """Append a request log line and echo to stdout."""
    with _log_lock:
        with open(LOGFILE, "a") as f:
            f.write(msg + "\n")
    print(f"[{PROXY_ID}] {msg}", flush=True)


def handle(conn: socket.socket) -> None:
    try:
        conn.settimeout(5.0)
        buf = b""
        while b"\r\n\r\n" not in buf:
            chunk = conn.recv(4096)
            if not chunk:
                return
            buf += chunk
            if len(buf) > 65536:
                return  # header flood guard

        first = buf.split(b"\r\n", 1)[0].decode(errors="replace")
        parts = first.split()
        if len(parts) < 3:
            return
        method, target = parts[0], parts[1]
        log(f"{method} {target}")

        if method == "CONNECT":
            conn.sendall(b"HTTP/1.1 200 Connection established\r\n\r\n")
            # No actual tunneling — test asserts the log, not end-to-end TLS.
        else:
            body = f"{PROXY_ID}:{target}".encode()
            resp = (
                b"HTTP/1.1 200 OK\r\n"
                b"Content-Type: text/plain\r\n"
                b"Content-Length: " + str(len(body)).encode() + b"\r\n"
                b"Connection: close\r\n"
                b"\r\n" + body
            )
            conn.sendall(resp)
    except Exception as exc:
        log(f"error: {exc}")
    finally:
        try:
            conn.close()
        except Exception:
            pass


def main() -> None:
    # Truncate existing log at startup so tests start clean.
    open(LOGFILE, "w").close()

    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", PORT))
    srv.listen(64)
    print(
        f"[{PROXY_ID}] listening on 127.0.0.1:{PORT}  log={LOGFILE}",
        flush=True,
    )

    while True:
        conn, _ = srv.accept()
        threading.Thread(target=handle, args=(conn,), daemon=True).start()


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        sys.exit(0)
