#!/usr/bin/env python3
"""Backend HTTP/HTTPS server used as the *origin* in totan e2e tests.

Together with mock-proxy.py (in MODE=forward) this lets us validate the
full data path — kernel interception → totan → forward proxy → real origin
→ response back through the proxy → back to the client — instead of just
asserting the proxy log line.

Endpoints (the response body and status are the assertions):
    GET  /              → "backend:<id>" (used to verify which backend served)
    GET  /headers       → echo of request headers, one per line
    GET  /bytes/N       → 'A' * N (size-bounded payloads, e.g. 1 MB)
    POST /echo          → request body, byte-for-byte (Content-Type preserved)
    GET  /status/N      → response with status code N
    GET  /sleep/MS      → respond after MS milliseconds (timeouts/concurrency)

Environment:
    PORT       TCP port to bind on 127.0.0.1
    BACKEND_ID Identity string baked into "/" responses
    TLS_CERT   Optional path to a PEM cert; when set the listener is HTTPS
    TLS_KEY    Optional path to a PEM key
    LOGFILE    Append a one-line summary per request
"""

import http.server
import os
import socketserver
import ssl
import sys
import threading
import time


PORT = int(os.environ.get("PORT", "9080"))
BACKEND_ID = os.environ.get("BACKEND_ID", "backend-default")
LOGFILE = os.environ.get("LOGFILE", f"/tmp/mock-backend-{PORT}.log")
TLS_CERT = os.environ.get("TLS_CERT")
TLS_KEY = os.environ.get("TLS_KEY")

_log_lock = threading.Lock()


def _log(line: str) -> None:
    with _log_lock:
        with open(LOGFILE, "a") as f:
            f.write(line + "\n")


class Handler(http.server.BaseHTTPRequestHandler):
    # Fast and quiet: stderr noise from the default logger drowns the test
    # output and slows ab benchmarks. Per-request lines go to LOGFILE only.
    def log_message(self, format: str, *args) -> None:  # noqa: A003
        pass

    def _record(self, body_len: int = 0) -> None:
        _log(
            f"{self.command} {self.path} host={self.headers.get('Host', '-')} "
            f"len={body_len}"
        )

    def _send(self, status: int, body: bytes, ctype: str = "text/plain") -> None:
        self.send_response(status)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Connection", self.headers.get("Connection", "close"))
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    # GET ----------------------------------------------------------------
    def do_GET(self) -> None:  # noqa: N802
        self._record()
        if self.path == "/":
            self._send(200, f"backend:{BACKEND_ID}".encode())
        elif self.path == "/headers":
            body = "\n".join(f"{k}: {v}" for k, v in self.headers.items())
            self._send(200, body.encode())
        elif self.path.startswith("/bytes/"):
            try:
                n = int(self.path[len("/bytes/") :])
                n = max(0, min(n, 16 * 1024 * 1024))  # cap at 16 MB
                self._send(200, b"A" * n, ctype="application/octet-stream")
            except ValueError:
                self._send(400, b"bad N")
        elif self.path.startswith("/status/"):
            try:
                code = int(self.path[len("/status/") :])
                self._send(code, f"status {code}".encode())
            except ValueError:
                self._send(400, b"bad code")
        elif self.path.startswith("/sleep/"):
            try:
                ms = int(self.path[len("/sleep/") :])
                time.sleep(min(ms, 30_000) / 1000.0)
                self._send(200, f"slept {ms}ms".encode())
            except ValueError:
                self._send(400, b"bad ms")
        else:
            self._send(404, b"not found")

    # POST ---------------------------------------------------------------
    def do_POST(self) -> None:  # noqa: N802
        try:
            n = int(self.headers.get("Content-Length", "0"))
        except ValueError:
            n = 0
        body = self.rfile.read(n) if n > 0 else b""
        self._record(body_len=len(body))
        if self.path == "/echo":
            ctype = self.headers.get("Content-Type", "application/octet-stream")
            self._send(200, body, ctype=ctype)
        else:
            self._send(404, b"not found")


class ThreadedServer(socketserver.ThreadingMixIn, http.server.HTTPServer):
    daemon_threads = True
    allow_reuse_address = True


def main() -> None:
    open(LOGFILE, "w").close()
    server = ThreadedServer(("127.0.0.1", PORT), Handler)
    scheme = "http"
    if TLS_CERT and TLS_KEY:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(certfile=TLS_CERT, keyfile=TLS_KEY)
        server.socket = ctx.wrap_socket(server.socket, server_side=True)
        scheme = "https"
    print(
        f"[{BACKEND_ID}] backend listening on {scheme}://127.0.0.1:{PORT}"
        f"  log={LOGFILE}",
        flush=True,
    )
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        sys.exit(0)


if __name__ == "__main__":
    main()
