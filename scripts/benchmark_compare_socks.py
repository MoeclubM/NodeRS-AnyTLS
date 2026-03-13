#!/usr/bin/env python3
import argparse
import socket
import threading
import time
from typing import List, Tuple


def socks5_connect(proxy_host: str, proxy_port: int, target_host: str, target_port: int) -> socket.socket:
    sock = socket.create_connection((proxy_host, proxy_port), timeout=10)
    sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
    sock.sendall(b"\x05\x01\x00")
    resp = sock.recv(2)
    if resp != b"\x05\x00":
        raise RuntimeError(f"SOCKS auth method failed: {resp!r}")
    try:
        addr = socket.inet_aton(target_host)
        req = b"\x05\x01\x00\x01" + addr + target_port.to_bytes(2, "big")
    except OSError:
        host = target_host.encode("utf-8")
        req = b"\x05\x01\x00\x03" + bytes([len(host)]) + host + target_port.to_bytes(2, "big")
    sock.sendall(req)
    head = recv_exact(sock, 4)
    if head[1] != 0x00:
        raise RuntimeError(f"SOCKS connect failed, reply={head[1]}")
    atyp = head[3]
    if atyp == 1:
        recv_exact(sock, 4)
    elif atyp == 3:
        ln = recv_exact(sock, 1)[0]
        recv_exact(sock, ln)
    elif atyp == 4:
        recv_exact(sock, 16)
    recv_exact(sock, 2)
    return sock


def recv_exact(sock: socket.socket, size: int) -> bytes:
    data = bytearray()
    while len(data) < size:
        chunk = sock.recv(size - len(data))
        if not chunk:
            raise EOFError("unexpected EOF")
        data.extend(chunk)
    return bytes(data)


def worker_upload(proxy: Tuple[str, int], target: Tuple[str, int], duration: float, chunk_size: int, result: dict) -> None:
    sock = socks5_connect(proxy[0], proxy[1], target[0], target[1])
    payload = b"\0" * chunk_size
    deadline = time.perf_counter() + duration
    sent = 0
    packets = 0
    try:
        while time.perf_counter() < deadline:
            sock.sendall(payload)
            sent += len(payload)
            packets += 1
    finally:
        try:
            sock.shutdown(socket.SHUT_WR)
        except OSError:
            pass
        sock.close()
    result["bytes"] = sent
    result["packets"] = packets


def worker_download(
    proxy: Tuple[str, int],
    target: Tuple[str, int],
    duration: float,
    chunk_size: int,
    result: dict,
) -> None:
    sock = socks5_connect(proxy[0], proxy[1], target[0], target[1])
    deadline = time.perf_counter() + duration
    received = 0
    packets = 0
    buf = bytearray()
    try:
        while time.perf_counter() < deadline:
            chunk = sock.recv(131072)
            if not chunk:
                break
            buf.extend(chunk)
            while len(buf) >= chunk_size:
                del buf[:chunk_size]
                received += chunk_size
                packets += 1
    finally:
        sock.close()
    result["bytes"] = received
    result["packets"] = packets


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--proxies", required=True, help="comma separated host:port list")
    parser.add_argument("--target", required=True, help="host:port")
    parser.add_argument("--mode", choices=["upload", "download"], required=True)
    parser.add_argument("--seconds", type=float, default=5)
    parser.add_argument("--parallel", type=int, default=1)
    parser.add_argument("--chunk-size", type=int, default=32768)
    args = parser.parse_args()

    proxies: List[Tuple[str, int]] = []
    for item in args.proxies.split(","):
        host, port = item.rsplit(":", 1)
        proxies.append((host, int(port)))
    target_host, target_port = args.target.rsplit(":", 1)
    target = (target_host, int(target_port))

    threads = []
    results = []
    start = time.perf_counter()
    for index in range(args.parallel):
        result = {}
        proxy = proxies[index % len(proxies)]
        worker = worker_upload if args.mode == "upload" else worker_download
        thread = threading.Thread(
            target=worker,
            args=(proxy, target, args.seconds, args.chunk_size, result),
            daemon=True,
        )
        threads.append(thread)
        results.append(result)
        thread.start()
    for thread in threads:
        thread.join()
    elapsed = max(time.perf_counter() - start, 1e-6)
    total_bytes = sum(item.get("bytes", 0) for item in results)
    total_packets = sum(item.get("packets", 0) for item in results)
    mbps = total_bytes * 8 / elapsed / 1_000_000
    pps = total_packets / elapsed
    print(
        f"mode={args.mode} parallel={args.parallel} chunk={args.chunk_size} "
        f"bytes={total_bytes} mbps={mbps:.2f} pps={pps:.2f}"
    )


if __name__ == "__main__":
    main()
