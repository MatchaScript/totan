#!/usr/bin/env python3
"""Create fresh HTTP/1.1 connections and validate every proxied response."""

from __future__ import annotations

import argparse
import socket
import sys
import time
from collections import Counter
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass


MAX_RESPONSE_BYTES = 64 * 1024


@dataclass(frozen=True)
class Target:
    name: str
    family: socket.AddressFamily
    address: str
    host_header: str
    expected_body: bytes


TARGETS = {
    "ipv4": Target(
        name="ipv4",
        family=socket.AF_INET,
        address="192.0.2.10",
        host_header="192.0.2.10",
        expected_body=b"stress-proxy:http://192.0.2.10/",
    ),
    "ipv6": Target(
        name="ipv6",
        family=socket.AF_INET6,
        address="2001:db8::10",
        host_header="[2001:db8::10]",
        expected_body=b"stress-proxy:http://[2001:db8::10]/",
    ),
}


def read_response(sock: socket.socket) -> tuple[bytes, bytes]:
    response = bytearray()
    header_end = -1
    content_length: int | None = None

    while len(response) < MAX_RESPONSE_BYTES:
        chunk = sock.recv(4096)
        if not chunk:
            break
        response.extend(chunk)

        if header_end < 0:
            header_end = response.find(b"\r\n\r\n")
            if header_end >= 0:
                header = bytes(response[:header_end])
                for line in header.split(b"\r\n")[1:]:
                    name, separator, value = line.partition(b":")
                    if separator and name.strip().lower() == b"content-length":
                        content_length = int(value.strip())
                        break

        if header_end >= 0 and content_length is not None:
            body_length = len(response) - (header_end + 4)
            if body_length >= content_length:
                break

    if len(response) >= MAX_RESPONSE_BYTES:
        raise RuntimeError("response exceeded size limit")
    if header_end < 0:
        raise RuntimeError("response headers were incomplete")

    header = bytes(response[:header_end])
    body = bytes(response[header_end + 4 :])
    if content_length is None:
        raise RuntimeError("response had no Content-Length")
    if len(body) != content_length:
        raise RuntimeError(
            f"response body was incomplete: expected={content_length} actual={len(body)}"
        )
    return header, body


def request_once(target: Target, timeout: float) -> str:
    request = (
        "GET / HTTP/1.1\r\n"
        f"Host: {target.host_header}\r\n"
        "User-Agent: totan-connection-churn/1\r\n"
        "Accept: */*\r\n"
        "Connection: close\r\n"
        "\r\n"
    ).encode()

    with socket.socket(target.family, socket.SOCK_STREAM) as sock:
        sock.settimeout(timeout)
        sock.connect((target.address, 80))
        sock.sendall(request)
        header, body = read_response(sock)

    status_line = header.split(b"\r\n", 1)[0]
    fields = status_line.split()
    if len(fields) < 2 or fields[1] != b"200":
        raise RuntimeError(f"unexpected status line: {status_line!r}")
    if body != target.expected_body:
        raise RuntimeError(
            f"unexpected body: expected={target.expected_body!r} actual={body!r}"
        )
    return target.name


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("targets", nargs="+", choices=sorted(TARGETS))
    parser.add_argument("--requests", type=int, required=True)
    parser.add_argument("--concurrency", type=int, required=True)
    parser.add_argument("--timeout", type=float, default=5.0)
    args = parser.parse_args()
    if args.requests < 1:
        parser.error("--requests must be positive")
    if not 1 <= args.concurrency <= args.requests:
        parser.error("--concurrency must be between 1 and --requests")
    if args.timeout <= 0:
        parser.error("--timeout must be positive")
    return args


def main() -> int:
    args = parse_args()
    targets = [TARGETS[name] for name in args.targets]
    work = [targets[index % len(targets)] for index in range(args.requests)]
    completed: Counter[str] = Counter()
    failures: Counter[str] = Counter()
    started = time.perf_counter()

    with ThreadPoolExecutor(max_workers=args.concurrency) as executor:
        future_targets = {
            executor.submit(request_once, target, args.timeout): target for target in work
        }
        for future in as_completed(future_targets):
            target = future_targets[future]
            try:
                completed[future.result()] += 1
            except Exception as error:  # aggregate and report every request failure
                failures[f"{target.name}: {type(error).__name__}: {error}"] += 1

    elapsed = time.perf_counter() - started
    succeeded = sum(completed.values())
    failed = sum(failures.values())
    observed_rps = succeeded / elapsed if elapsed else 0.0

    print(
        f"result: requested={args.requests} succeeded={succeeded} failed={failed} "
        f"elapsed={elapsed:.3f}s observed_rps={observed_rps:.1f}"
    )
    for target in targets:
        print(f"  {target.name}: succeeded={completed[target.name]}")
    for message, count in failures.most_common(10):
        print(f"  failure x{count}: {message}", file=sys.stderr)

    return 0 if succeeded == args.requests and failed == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
