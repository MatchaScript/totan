#!/usr/bin/env python3
"""Mock SOCKS5 proxy for totan e2e tests.

Implements just enough of RFC 1928 to validate totan's SOCKS5 client path:
no-auth method only, CONNECT command only, IPv4 / domain / IPv6 ATYP. Once
the handshake succeeds the connection is bidirectionally piped to the
resolved upstream so end-to-end TLS can complete through the tunnel.

Each handshake is appended to ``LOGFILE`` as ``CONNECT <authority>``, matching
the HTTP mock's log shape so test assertions can be uniform.

Environment:
    PORT      TCP port to bind on 127.0.0.1
    PROXY_ID  Identity string in stdout/log lines
    LOGFILE   Path to append the request log
    RESOLVE   "a.test:443=127.0.0.1:9443" — redirect away from RFC-5737 IPs
"""

import os
import socket
import struct
import sys
import threading


PORT = int(os.environ.get("PORT", "1080"))
PROXY_ID = os.environ.get("PROXY_ID", "socks5-default")
LOGFILE = os.environ.get("LOGFILE", f"/tmp/mock-socks5-{PORT}.log")


def _parse_resolve(s: str) -> dict[str, tuple[str, int]]:
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
    with _log_lock:
        with open(LOGFILE, "a") as f:
            f.write(msg + "\n")
    print(f"[{PROXY_ID}] {msg}", flush=True)


def _resolve(host: str, port: int) -> tuple[str, int]:
    return RESOLVE.get(f"{host.lower()}:{port}", (host, port))


def _read_exact(conn: socket.socket, n: int) -> bytes:
    buf = b""
    while len(buf) < n:
        chunk = conn.recv(n - len(buf))
        if not chunk:
            raise ConnectionError("short read")
        buf += chunk
    return buf


def _pipe(a: socket.socket, b: socket.socket) -> None:
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


def handle(conn: socket.socket) -> None:
    upstream = None
    try:
        conn.settimeout(5.0)

        # --- Greeting --------------------------------------------------------
        ver, nmethods = struct.unpack("!BB", _read_exact(conn, 2))
        if ver != 0x05:
            return
        methods = _read_exact(conn, nmethods)
        if 0x00 not in methods:  # only no-auth supported
            conn.sendall(b"\x05\xff")
            return
        conn.sendall(b"\x05\x00")

        # --- Request ---------------------------------------------------------
        head = _read_exact(conn, 4)
        ver, cmd, _rsv, atyp = struct.unpack("!BBBB", head)
        if ver != 0x05 or cmd != 0x01:  # CONNECT only
            conn.sendall(b"\x05\x07\x00\x01\x00\x00\x00\x00\x00\x00")
            return

        if atyp == 0x01:  # IPv4
            ip = socket.inet_ntoa(_read_exact(conn, 4))
            host = ip
        elif atyp == 0x03:  # domain
            (dlen,) = struct.unpack("!B", _read_exact(conn, 1))
            host = _read_exact(conn, dlen).decode()
        elif atyp == 0x04:  # IPv6
            ip6 = _read_exact(conn, 16)
            host = socket.inet_ntop(socket.AF_INET6, ip6)
        else:
            conn.sendall(b"\x05\x08\x00\x01\x00\x00\x00\x00\x00\x00")
            return

        (port,) = struct.unpack("!H", _read_exact(conn, 2))
        log(f"CONNECT {host}:{port}")

        dst_host, dst_port = _resolve(host, port)
        try:
            upstream = socket.create_connection((dst_host, dst_port), timeout=5.0)
        except OSError as e:
            log(f"CONNECT {host}:{port} -> dial {dst_host}:{dst_port} failed: {e}")
            conn.sendall(b"\x05\x05\x00\x01\x00\x00\x00\x00\x00\x00")  # connection refused
            return

        # Success reply (BND.ADDR=0.0.0.0, BND.PORT=0; clients ignore both).
        conn.sendall(b"\x05\x00\x00\x01\x00\x00\x00\x00\x00\x00")

        upstream.settimeout(None)
        conn.settimeout(None)
        t1 = threading.Thread(target=_pipe, args=(conn, upstream), daemon=True)
        t2 = threading.Thread(target=_pipe, args=(upstream, conn), daemon=True)
        t1.start()
        t2.start()
        t1.join()
        t2.join()
    except Exception as exc:
        log(f"error: {exc}")
    finally:
        try:
            conn.close()
        except Exception:
            pass
        if upstream is not None:
            try:
                upstream.close()
            except Exception:
                pass


def main() -> None:
    open(LOGFILE, "w").close()
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", PORT))
    srv.listen(64)
    print(f"[{PROXY_ID}] SOCKS5 listening on 127.0.0.1:{PORT}  log={LOGFILE}", flush=True)
    while True:
        conn, _ = srv.accept()
        threading.Thread(target=handle, args=(conn,), daemon=True).start()


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        sys.exit(0)
