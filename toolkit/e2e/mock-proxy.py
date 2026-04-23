#!/usr/bin/env python3
"""Mock HTTP/forward-proxy used by e2e tests.

Two execution modes, controlled by the ``MODE`` env:

- ``MODE=stub`` (default): respond locally without contacting an origin. Plain
  HTTP gets a synthetic body ``"<proxy-id>:<request-target>"`` and CONNECT gets
  a 200 with no actual tunnel. Useful when the test only needs to verify which
  upstream proxy was selected by PAC.

- ``MODE=forward``: behave as a real forward proxy. Plain HTTP requests are
  re-issued to the resolved origin and the response is streamed back; CONNECT
  opens a TCP connection to the resolved authority and bidirectionally pipes
  bytes. Origin selection follows ``RESOLVE`` (host[:port]=ip[:port], comma-
  separated); otherwise the requested authority is dialled directly.

Common environment:
    PORT      TCP port to bind on 127.0.0.1
    PROXY_ID  Identity string embedded in stub-mode bodies and log lines
    LOGFILE   Path to append the request log (one line per request)
    MODE      "stub" (default) or "forward"
    RESOLVE   "a.test:443=127.0.0.1:9443,plain.test:80=127.0.0.1:9080"
              Used only in MODE=forward to redirect requests away from
              unreachable test hostnames (RFC 5737 IPs in totan e2e).
"""

import os
import socket
import sys
import threading


PORT = int(os.environ.get("PORT", "8880"))
PROXY_ID = os.environ.get("PROXY_ID", "proxy-default")
LOGFILE = os.environ.get("LOGFILE", f"/tmp/mock-proxy-{PORT}.log")
MODE = os.environ.get("MODE", "stub").lower()


def _parse_resolve(s: str) -> dict[str, tuple[str, int]]:
    """Parse a RESOLVE env spec into {authority -> (ip, port)}.

    Authority is matched case-insensitively; the lookup key includes the port
    so the same hostname can map to different backends per scheme.
    """
    out: dict[str, tuple[str, int]] = {}
    for entry in (s or "").split(","):
        entry = entry.strip()
        if not entry:
            continue
        try:
            src, dst = entry.split("=", 1)
            src_host, src_port = src.rsplit(":", 1)
            dst_host, dst_port = dst.rsplit(":", 1)
            out[f"{src_host.lower()}:{int(src_port)}"] = (dst_host, int(dst_port))
        except ValueError:
            print(f"[{PROXY_ID}] bad RESOLVE entry: {entry!r}", file=sys.stderr, flush=True)
    return out


RESOLVE = _parse_resolve(os.environ.get("RESOLVE", ""))

_log_lock = threading.Lock()


def log(msg: str) -> None:
    """Append a request log line and echo to stdout."""
    with _log_lock:
        with open(LOGFILE, "a") as f:
            f.write(msg + "\n")
    print(f"[{PROXY_ID}] {msg}", flush=True)


def _resolve_authority(authority: str) -> tuple[str, int]:
    """Map ``host:port`` to the actual ``(ip, port)`` to dial.

    Falls through to the requested authority verbatim when the test suite
    didn't override it.
    """
    host, _, port = authority.rpartition(":")
    key = f"{host.lower()}:{int(port)}"
    if key in RESOLVE:
        return RESOLVE[key]
    return host, int(port)


def _read_headers(conn: socket.socket) -> bytes:
    """Read until the end of the request headers (CRLFCRLF)."""
    buf = b""
    while b"\r\n\r\n" not in buf:
        chunk = conn.recv(4096)
        if not chunk:
            return buf
        buf += chunk
        if len(buf) > 65536:
            return buf  # header flood guard
    return buf


def _pipe(a: socket.socket, b: socket.socket) -> None:
    """One-way byte pump; closes the write side on EOF so the peer unblocks."""
    try:
        while True:
            data = a.recv(65536)
            if not data:
                break
            b.sendall(data)
    except OSError:
        pass
    finally:
        try:
            b.shutdown(socket.SHUT_WR)
        except OSError:
            pass


def _tunnel(client: socket.socket, upstream: socket.socket) -> None:
    """Bidirectional pipe between client and upstream until both close."""
    t1 = threading.Thread(target=_pipe, args=(client, upstream), daemon=True)
    t2 = threading.Thread(target=_pipe, args=(upstream, client), daemon=True)
    t1.start()
    t2.start()
    t1.join()
    t2.join()


def _handle_connect(conn: socket.socket, target: str) -> None:
    """CONNECT host:port — log and either tunnel or stub-200."""
    log(f"CONNECT {target}")
    if MODE != "forward":
        conn.sendall(b"HTTP/1.1 200 Connection established\r\n\r\n")
        return
    host, port = _resolve_authority(target)
    try:
        upstream = socket.create_connection((host, port), timeout=5.0)
    except OSError as e:
        log(f"CONNECT {target} -> dial {host}:{port} failed: {e}")
        conn.sendall(b"HTTP/1.1 502 Bad Gateway\r\n\r\n")
        return
    conn.sendall(b"HTTP/1.1 200 Connection established\r\n\r\n")
    upstream.settimeout(None)
    conn.settimeout(None)
    _tunnel(conn, upstream)
    upstream.close()


def _handle_http(conn: socket.socket, raw_request: bytes, method: str, target: str) -> None:
    """Plain HTTP — log and either stub-respond or forward upstream."""
    log(f"{method} {target}")

    if MODE != "forward":
        body = f"{PROXY_ID}:{target}".encode()
        resp = (
            b"HTTP/1.1 200 OK\r\n"
            b"Content-Type: text/plain\r\n"
            b"Content-Length: " + str(len(body)).encode() + b"\r\n"
            b"Connection: close\r\n"
            b"\r\n" + body
        )
        conn.sendall(resp)
        return

    # Forward mode: target must be absolute-form URI (RFC 7230 §5.3.2).
    if not target.lower().startswith("http://"):
        conn.sendall(b"HTTP/1.1 400 Bad Request\r\n\r\norigin-form not accepted")
        return
    rest = target[len("http://") :]
    authority, _, path = rest.partition("/")
    path = "/" + path if path else "/"
    if ":" not in authority:
        authority = authority + ":80"
    host, port = _resolve_authority(authority)

    # Rewrite the request-line into origin-form for the backend (it's an
    # http.server, not a forward proxy) and replay headers + the part of the
    # body we already buffered. The Connection-close header keeps things
    # simple — no upstream pool, no keep-alive bookkeeping.
    head, _, body_already = raw_request.partition(b"\r\n\r\n")
    lines = head.split(b"\r\n")
    lines[0] = f"{method} {path} HTTP/1.1".encode()
    rebuilt = b"\r\n".join(lines) + b"\r\n\r\n" + body_already

    try:
        upstream = socket.create_connection((host, port), timeout=5.0)
    except OSError as e:
        log(f"{method} {target} -> dial {host}:{port} failed: {e}")
        conn.sendall(b"HTTP/1.1 502 Bad Gateway\r\n\r\n")
        return
    upstream.sendall(rebuilt)
    upstream.settimeout(None)
    conn.settimeout(None)
    _tunnel(conn, upstream)
    upstream.close()


def handle(conn: socket.socket) -> None:
    try:
        conn.settimeout(5.0)
        buf = _read_headers(conn)
        if not buf:
            return
        first = buf.split(b"\r\n", 1)[0].decode(errors="replace")
        parts = first.split()
        if len(parts) < 3:
            return
        method, target = parts[0], parts[1]
        if method == "CONNECT":
            _handle_connect(conn, target)
        else:
            _handle_http(conn, buf, method, target)
    except Exception as exc:
        log(f"error: {exc}")
    finally:
        try:
            conn.close()
        except Exception:
            pass


def main() -> None:
    open(LOGFILE, "w").close()  # truncate so each run starts clean

    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", PORT))
    srv.listen(64)
    print(
        f"[{PROXY_ID}] listening on 127.0.0.1:{PORT}  log={LOGFILE} mode={MODE}",
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
