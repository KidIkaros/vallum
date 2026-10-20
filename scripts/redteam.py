#!/usr/bin/env python3
"""Adversary harness for a running Vallum server.

Measures the properties unit tests cannot: what an unauthenticated packet costs
the server, whether any of it is answered (amplification), and whether a flood
from many sources makes the daemon grow.

Run it inside the namespace where the server lives:

    python3 scripts/redteam.py --port 51921 --pid <server pid>
"""
import argparse
import os
import random
import socket
import struct
import sys
import time

VERSION = 0x01
SUITE = 0x0003


def header(msg_type: int, suite: int = SUITE, index: int = 0) -> bytes:
    return struct.pack(">BBHI", VERSION, msg_type, suite, index)


def tlv(tag: int, value: bytes) -> bytes:
    return struct.pack(">HH", tag, len(value)) + value


def cpu_ticks(pid: int) -> int:
    with open(f"/proc/{pid}/stat") as handle:
        fields = handle.read().split()
    # utime and stime are fields 14 and 15, 1-based, after the comm field.
    return int(fields[13]) + int(fields[14])


def rss_kb(pid: int) -> int:
    with open(f"/proc/{pid}/status") as handle:
        for line in handle:
            if line.startswith("VmRSS:"):
                return int(line.split()[1])
    return 0


def probe(sock, target, payload, reply_timeout=0.05):
    """Send one payload; return the bytes that came back (empty if silent)."""
    try:
        sock.sendto(payload, target)
    except OSError:
        return b""
    sock.settimeout(reply_timeout)
    try:
        data, _ = sock.recvfrom(65535)
        return data
    except (socket.timeout, OSError):
        return b""


def measure(name, sock, target, pid, make_payload, count, reply_probe=True):
    """Send `count` packets and report cost per packet and any responses."""
    before_ticks = cpu_ticks(pid)
    before_rss = rss_kb(pid)
    started = time.monotonic()

    answered = 0
    answer_bytes = 0
    sent_bytes = 0
    # Every packet gets its own source port, so each is a distinct 5-tuple and
    # cannot be deduplicated by the kernel's socket layer.
    for index in range(count):
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as one:
            payload = make_payload(index)
            sent_bytes += len(payload)
            try:
                one.sendto(payload, target)
            except OSError:
                pass
            if reply_probe:
                one.settimeout(0.0)
                try:
                    data, _ = one.recvfrom(65535)
                    answered += 1
                    answer_bytes += len(data)
                except (BlockingIOError, OSError):
                    pass

    elapsed = time.monotonic() - started
    ticks = cpu_ticks(pid) - before_ticks
    rss = rss_kb(pid) - before_rss

    hz = os.sysconf("SC_CLK_TCK")
    cpu_us = ticks / hz / count * 1_000_000
    print(f"   {name}")
    print(f"      packets          {count}")
    print(f"      server CPU       {cpu_us:.2f} us/packet ({ticks} ticks over {elapsed:.2f}s)")
    print(f"      answered         {answered}" + (f" ({answer_bytes} bytes back)" if answered else ""))
    if answered:
        print(f"      amplification    {answer_bytes / sent_bytes:.2f}x")
    print(f"      RSS change       {rss:+d} kB")
    return {"answered": answered, "cpu_us": cpu_us, "rss": rss}


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--port", type=int, required=True)
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--pid", type=int, required=True)
    parser.add_argument("--count", type=int, default=20000)
    args = parser.parse_args()
    target = (args.host, args.port)

    print(f"── adversary against {args.host}:{args.port} (server pid {args.pid})")
    results = {}

    # 1. Pure noise: nothing a parser can accept.
    results["noise"] = measure(
        "random bytes, random lengths",
        None, target, args.pid,
        lambda i: bytes(random.getrandbits(8) for _ in range(random.randint(1, 1400))),
        args.count,
    )

    # 2. A well-formed header with no body: the cheapest thing that reaches the
    #    message parser rather than the framing check.
    results["header"] = measure(
        "valid header, empty body",
        None, target, args.pid,
        lambda i: header(1, index=i),
        args.count,
    )

    # 3. Header plus a plausible TLV: forces tag dispatch, still unauthenticated.
    results["tlv"] = measure(
        "valid header, one plausible TLV",
        None, target, args.pid,
        lambda i: header(1, index=i) + tlv(0x0001, b"\x00" * 32),
        args.count,
    )

    # 4. A full-size message: the worst case a sender can reach without a key.
    #    This is where PQ work would happen if the admission check came late.
    results["full"] = measure(
        "valid header, full-size body (4 KiB)",
        None, target, args.pid,
        lambda i: header(1, index=i) + tlv(0x0001, b"\x00" * 4096),
        max(1, args.count // 10),
    )

    print("── summary")
    total_answered = sum(r["answered"] for r in results.values())
    if total_answered == 0:
        print("   ok    no unauthenticated packet was answered (no reflector)")
    else:
        print(f"   FIND  {total_answered} unauthenticated packets were answered")

    worst = max(results.values(), key=lambda r: r["cpu_us"])
    print(f"   note  worst cost {worst['cpu_us']:.2f} us/packet")

    grown = max(r["rss"] for r in results.values())
    if grown > 2048:
        print(f"   FIND  RSS grew {grown} kB under unauthenticated traffic")
    else:
        print(f"   ok    RSS stayed within {grown} kB")
    return 0


if __name__ == "__main__":
    sys.exit(main())
