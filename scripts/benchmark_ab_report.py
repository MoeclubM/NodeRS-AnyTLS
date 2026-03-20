#!/usr/bin/env python3
from __future__ import annotations

import argparse
import csv
import json
import os
import pathlib
import shutil
import socket
import subprocess
import sys
import tarfile
import tempfile
import time
import urllib.request
from contextlib import ExitStack, contextmanager
from dataclasses import dataclass
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse


ROOT = pathlib.Path(__file__).resolve().parent.parent
COMPARE_SOCKS = ROOT / "scripts" / "benchmark_compare_socks.py"
USERS = [f"bench-user-uuid-{index:02d}" for index in range(1, 5)]


@dataclass(frozen=True)
class Case:
    name: str
    mode: str
    parallel: int
    chunk_size: int
    seconds: int
    netem_profile: str | None = None
    category: str = "throughput"
    capture_curve: bool = False


@dataclass
class Implementation:
    label: str
    kind: str
    ref: str
    commit: str
    binary: pathlib.Path


def build_cases(long_connection_seconds: int, idle_seconds: int) -> list[Case]:
    long_connection_seconds = max(5, long_connection_seconds)
    idle_seconds = max(5, idle_seconds)
    return [
        Case(
            "upload-long-connection",
            "upload",
            1,
            32768,
            long_connection_seconds,
            capture_curve=True,
        ),
        Case(
            "download-long-connection",
            "download",
            1,
            32768,
            long_connection_seconds,
            capture_curve=True,
        ),
        Case(
            "upload-long-connection-lossy",
            "upload",
            1,
            32768,
            long_connection_seconds,
            "lossy-small",
            capture_curve=True,
        ),
        Case(
            "download-long-connection-lossy",
            "download",
            1,
            32768,
            long_connection_seconds,
            "lossy-small",
            capture_curve=True,
        ),
        Case(
            f"idle-keepalive-{idle_seconds}s",
            "idle",
            4,
            1024,
            idle_seconds,
            category="stability",
        ),
    ]


NETEM_PROFILES = {
    "lossy-small": ["delay", "15ms", "3ms", "loss", "0.5%"],
}

FIXED_COMPARE_TAGS = ["v0.0.23", "v0.0.18"]


def throughput_cases(cases: list[Case]) -> list[Case]:
    return [case for case in cases if case.category == "throughput"]


def stability_cases(cases: list[Case]) -> list[Case]:
    return [case for case in cases if case.category == "stability"]


def curve_cases(cases: list[Case]) -> list[Case]:
    return [case for case in cases if case.capture_curve]


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Compare current NodeRS, previous tags, and sing-box on Linux.")
    parser.add_argument("--output-dir", required=True)
    parser.add_argument("--target", default="x86_64-unknown-linux-musl")
    parser.add_argument(
        "--compare-count",
        type=int,
        default=3,
        help="Total number of previous tags to benchmark. The default keeps fixed baselines "
        "v0.0.23 and v0.0.18, then adds the latest previous tag.",
    )
    parser.add_argument("--sing-version", default="latest")
    parser.add_argument("--enable-netem", action="store_true")
    parser.add_argument("--long-connection-seconds", type=int, default=30)
    parser.add_argument("--idle-seconds", type=int, default=95)
    parser.add_argument("--curve-sample-interval", type=float, default=1.0)
    return parser.parse_args()


def run_checked(
    command: list[str],
    *,
    cwd: pathlib.Path | None = None,
    env: dict[str, str] | None = None,
    capture_output: bool = False,
) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        command,
        cwd=str(cwd or ROOT),
        env=env,
        text=True,
        check=True,
        capture_output=capture_output,
    )


def git_output(*args: str) -> str:
    return run_checked(["git", *args], capture_output=True).stdout.strip()


def run_best_effort(
    command: list[str],
    *,
    cwd: pathlib.Path | None = None,
    env: dict[str, str] | None = None,
) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        command,
        cwd=str(cwd or ROOT),
        env=env,
        text=True,
        check=False,
        capture_output=True,
    )


def select_previous_tags(limit: int) -> list[str]:
    if limit <= 0:
        return []

    head_tags = set(filter(None, git_output("tag", "--points-at", "HEAD").splitlines()))
    tags = [
        line.strip()
        for line in git_output("tag", "--sort=-version:refname").splitlines()
        if line.strip().startswith("v")
    ]
    selected: list[str] = []
    available = [tag for tag in tags if tag not in head_tags]

    for tag in FIXED_COMPARE_TAGS:
        if tag in available and tag not in selected:
            selected.append(tag)
            if len(selected) >= limit:
                return selected

    for tag in available:
        if tag in selected:
            continue
        selected.append(tag)
        if len(selected) >= limit:
            break
    return selected


def reserve_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        return int(sock.getsockname()[1])


def wait_tcp(host: str, port: int, timeout_seconds: float = 20.0) -> None:
    deadline = time.time() + timeout_seconds
    last_error: Exception | None = None
    while time.time() < deadline:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(0.5)
            try:
                sock.connect((host, port))
                return
            except OSError as error:
                last_error = error
        time.sleep(0.2)
    raise RuntimeError(f"port {host}:{port} not ready: {last_error}")


@contextmanager
def applied_netem(profile: str | None, enabled: bool):
    if not enabled or profile is None:
        yield
        return
    arguments = NETEM_PROFILES[profile]
    run_best_effort(["sudo", "tc", "qdisc", "del", "dev", "lo", "root"])
    run_checked(["sudo", "tc", "qdisc", "replace", "dev", "lo", "root", "netem", *arguments])
    time.sleep(0.2)
    try:
        yield
    finally:
        run_best_effort(["sudo", "tc", "qdisc", "del", "dev", "lo", "root"])
        time.sleep(0.2)


def ensure_tls_materials(work_dir: pathlib.Path) -> tuple[pathlib.Path, pathlib.Path]:
    cert_path = work_dir / "cert.pem"
    key_path = work_dir / "key.pem"
    run_checked(
        [
            "openssl",
            "req",
            "-x509",
            "-newkey",
            "rsa:2048",
            "-nodes",
            "-days",
            "30",
            "-subj",
            "/CN=localhost",
            "-addext",
            "subjectAltName=DNS:localhost",
            "-keyout",
            str(key_path),
            "-out",
            str(cert_path),
        ]
    )
    return cert_path, key_path


class MockPanel:
    def __init__(self, port: int, server_port: int):
        self.port = port
        self.server_port = server_port
        self.httpd: ThreadingHTTPServer | None = None

    def start(self) -> None:
        panel = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, fmt: str, *args) -> None:
                return

            def _auth(self) -> bool:
                qs = parse_qs(urlparse(self.path).query)
                return qs.get("token", [""])[0] == "bench-token"

            def _json(self, payload: object, code: int = 200) -> None:
                raw = json.dumps(payload).encode("utf-8")
                self.send_response(code)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(raw)))
                self.end_headers()
                self.wfile.write(raw)

            def do_GET(self) -> None:
                if not self._auth():
                    self._json({"error": "forbidden"}, 403)
                    return
                path = urlparse(self.path).path
                if path.endswith("/config"):
                    self._json(
                        {
                            "protocol": "anytls",
                            "server_port": panel.server_port,
                            "server_name": "localhost",
                            "padding_scheme": [],
                            "routes": [],
                            "base_config": {"pull_interval": 600, "push_interval": 600},
                        }
                    )
                    return
                if path.endswith("/user"):
                    self._json(
                        {
                            "users": [
                                {
                                    "id": index + 1,
                                    "uuid": user,
                                    "speed_limit": 0,
                                    "device_limit": 0,
                                }
                                for index, user in enumerate(USERS)
                            ]
                        }
                    )
                    return
                if path.endswith("/alivelist"):
                    self._json({"alive": {}})
                    return
                self._json({"error": "not found"}, 404)

            def do_POST(self) -> None:
                if not self._auth():
                    self._json({"error": "forbidden"}, 403)
                    return
                length = int(self.headers.get("Content-Length", "0"))
                if length:
                    self.rfile.read(length)
                self._json({"ok": True})

        self.httpd = ThreadingHTTPServer(("127.0.0.1", self.port), Handler)
        self.httpd.serve_forever()

    def __enter__(self) -> "MockPanel":
        import threading

        self.thread = threading.Thread(target=self.start, daemon=True)
        self.thread.start()
        wait_tcp("127.0.0.1", self.port)
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        if self.httpd is not None:
            self.httpd.shutdown()
            self.httpd.server_close()
        if hasattr(self, "thread"):
            self.thread.join(timeout=5)


@contextmanager
def started_process(
    command: list[str],
    *,
    stdout_path: pathlib.Path,
    stderr_path: pathlib.Path,
    ready_port: int | None = None,
    cwd: pathlib.Path | None = None,
):
    stdout_path.parent.mkdir(parents=True, exist_ok=True)
    stderr_path.parent.mkdir(parents=True, exist_ok=True)
    with open(stdout_path, "w", encoding="utf-8") as stdout_file, open(
        stderr_path,
        "w",
        encoding="utf-8",
    ) as stderr_file:
        process = subprocess.Popen(
            command,
            cwd=str(cwd or ROOT),
            stdout=stdout_file,
            stderr=stderr_file,
            text=True,
        )
        try:
            if ready_port is not None:
                wait_tcp("127.0.0.1", ready_port)
            yield process
        finally:
            if process.poll() is None:
                process.terminate()
                try:
                    process.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait(timeout=5)


def summarize_curve(samples: list[dict[str, object]]) -> dict[str, object]:
    if not samples:
        return {
            "curve_points": 0,
            "curve_avg_mbps": None,
            "curve_peak_mbps": None,
            "curve_min_mbps": None,
            "curve_tail_mbps": None,
        }
    mbps_values = [float(sample["mbps"]) for sample in samples]
    tail_values = mbps_values[-min(5, len(mbps_values)) :]
    return {
        "curve_points": len(samples),
        "curve_avg_mbps": round(sum(mbps_values) / len(mbps_values), 2),
        "curve_peak_mbps": round(max(mbps_values), 2),
        "curve_min_mbps": round(min(mbps_values), 2),
        "curve_tail_mbps": round(sum(tail_values) / len(tail_values), 2),
    }


def run_compare_socks(
    *,
    proxies: list[str],
    target: str,
    case: Case,
    curve_sample_interval: float,
    logs_dir: pathlib.Path,
) -> dict[str, object]:
    stdout_path = logs_dir / f"{case.name}.stdout.log"
    stderr_path = logs_dir / f"{case.name}.stderr.log"
    curve_path = logs_dir / f"{case.name}.curve.json"
    command = [
        sys.executable,
        str(COMPARE_SOCKS),
        "--proxies",
        ",".join(proxies),
        "--target",
        target,
        "--mode",
        case.mode,
        "--seconds",
        str(case.seconds),
        "--parallel",
        str(case.parallel),
        "--chunk-size",
        str(case.chunk_size),
        "--insecure",
    ]
    if case.capture_curve:
        command.extend(["--curve-file", str(curve_path), "--sample-interval", str(curve_sample_interval)])
    with open(stdout_path, "w", encoding="utf-8") as stdout_file, open(
        stderr_path,
        "w",
        encoding="utf-8",
    ) as stderr_file:
        process = subprocess.Popen(command, stdout=stdout_file, stderr=stderr_file, text=True)
        process.wait()
    if process.returncode != 0:
        raise RuntimeError(
            f"{case.name} failed:\nSTDOUT:\n{stdout_path.read_text(encoding='utf-8', errors='ignore')}\n"
            f"STDERR:\n{stderr_path.read_text(encoding='utf-8', errors='ignore')}"
        )
    metrics = json.loads(stdout_path.read_text(encoding="utf-8", errors="ignore"))
    if case.capture_curve and curve_path.exists():
        curve = json.loads(curve_path.read_text(encoding="utf-8"))
        metrics["curve_samples"] = curve.get("samples", [])
        metrics["curve_log"] = str(curve_path)
        metrics.update(summarize_curve(metrics["curve_samples"]))
    metrics["stdout_log"] = str(stdout_path)
    metrics["stderr_log"] = str(stderr_path)
    metrics["status"] = "pass"
    return metrics


def write_node_config(
    path: pathlib.Path,
    *,
    panel_port: int,
    cert_path: pathlib.Path,
    key_path: pathlib.Path,
) -> None:
    path.write_text(
        "\n".join(
            [
                "[panel]",
                f'url = "http://127.0.0.1:{panel_port}"',
                'token = "bench-token"',
                "node_id = 1",
                "timeout_seconds = 5",
                "",
                "[node]",
                'listen_ip = "127.0.0.1"',
                "",
                "[tls]",
                f'cert_path = "{cert_path.as_posix()}"',
                f'key_path = "{key_path.as_posix()}"',
                "reload_interval_seconds = 600",
                "",
                "[outbound]",
                'dns_resolver = "system"',
                'ip_strategy = "system"',
                "",
                "[report]",
                "status_interval_seconds = 600",
                "min_traffic_bytes = 0",
                "",
                "[log]",
                'level = "warn"',
                "",
            ]
        ),
        encoding="utf-8",
    )


def write_sing_server_config(
    path: pathlib.Path,
    *,
    server_port: int,
    cert_path: pathlib.Path,
    key_path: pathlib.Path,
) -> None:
    path.write_text(
        json.dumps(
            {
                "log": {"level": "warn"},
                "inbounds": [
                    {
                        "type": "anytls",
                        "tag": "anytls-in",
                        "listen": "127.0.0.1",
                        "listen_port": server_port,
                        "users": [{"name": user, "password": user} for user in USERS],
                        "padding_scheme": [],
                        "tls": {
                            "enabled": True,
                            "server_name": "localhost",
                            "certificate_path": str(cert_path),
                            "key_path": str(key_path),
                        },
                    }
                ],
                "outbounds": [{"type": "direct", "tag": "direct"}],
                "route": {"final": "direct"},
            },
            indent=2,
        ),
        encoding="utf-8",
    )


def write_sing_client_config(path: pathlib.Path, *, socks_port: int, server_port: int, user: str) -> None:
    path.write_text(
        json.dumps(
            {
                "log": {"level": "warn"},
                "inbounds": [
                    {
                        "type": "socks",
                        "tag": "socks-in",
                        "listen": "127.0.0.1",
                        "listen_port": socks_port,
                    }
                ],
                "outbounds": [
                    {
                        "type": "anytls",
                        "tag": "proxy",
                        "server": "127.0.0.1",
                        "server_port": server_port,
                        "password": user,
                        "tls": {"enabled": True, "server_name": "localhost", "insecure": True},
                    }
                ],
                "route": {"final": "proxy"},
            },
            indent=2,
        ),
        encoding="utf-8",
    )


def start_sing_clients(
    stack: ExitStack,
    *,
    sing_binary: pathlib.Path,
    work_dir: pathlib.Path,
    logs_dir: pathlib.Path,
    server_port: int,
) -> list[str]:
    proxies: list[str] = []
    socks_ports = [reserve_port() for _ in USERS]
    for index, socks_port in enumerate(socks_ports):
        config_path = work_dir / f"client-{index}.json"
        write_sing_client_config(config_path, socks_port=socks_port, server_port=server_port, user=USERS[index])
        stack.enter_context(
            started_process(
                [str(sing_binary), "run", "-c", str(config_path)],
                stdout_path=logs_dir / f"client-{index}.stdout.log",
                stderr_path=logs_dir / f"client-{index}.stderr.log",
                ready_port=socks_port,
            )
        )
        proxies.append(f"127.0.0.1:{socks_port}")
    return proxies


def benchmark_impl(
    implementation: Implementation,
    *,
    cases: list[Case],
    bench_binary: pathlib.Path,
    sing_binary: pathlib.Path,
    output_dir: pathlib.Path,
    curve_sample_interval: float = 1.0,
    enable_netem: bool = False,
) -> list[dict[str, object]]:
    impl_dir = output_dir / implementation.label
    impl_dir.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix=f"benchmark-{implementation.label}-") as temp_dir:
        work_dir = pathlib.Path(temp_dir)
        cert_path, key_path = ensure_tls_materials(work_dir)
        sink_port = reserve_port()
        source_port = reserve_port()
        server_port = reserve_port()

        with ExitStack() as stack:
            stack.enter_context(
                started_process(
                    [str(bench_binary), "sink", "--listen", f"127.0.0.1:{sink_port}"],
                    stdout_path=impl_dir / "sink.stdout.log",
                    stderr_path=impl_dir / "sink.stderr.log",
                    ready_port=sink_port,
                )
            )

            if implementation.kind == "singbox":
                server_config = work_dir / "sing-server.json"
                write_sing_server_config(
                    server_config,
                    server_port=server_port,
                    cert_path=cert_path,
                    key_path=key_path,
                )
                stack.enter_context(
                    started_process(
                        [str(implementation.binary), "run", "-c", str(server_config)],
                        stdout_path=impl_dir / "server.stdout.log",
                        stderr_path=impl_dir / "server.stderr.log",
                        ready_port=server_port,
                    )
                )
            else:
                panel_port = reserve_port()
                node_config = work_dir / "node-config.toml"
                write_node_config(
                    node_config,
                    panel_port=panel_port,
                    cert_path=cert_path,
                    key_path=key_path,
                )
                stack.enter_context(MockPanel(panel_port, server_port))
                stack.enter_context(
                    started_process(
                        [str(implementation.binary), str(node_config)],
                        stdout_path=impl_dir / "server.stdout.log",
                        stderr_path=impl_dir / "server.stderr.log",
                        ready_port=server_port,
                    )
                )

            proxies = start_sing_clients(
                stack,
                sing_binary=sing_binary,
                work_dir=work_dir,
                logs_dir=impl_dir,
                server_port=server_port,
            )

            rows: list[dict[str, object]] = []
            for case in cases:
                with applied_netem(case.netem_profile, enable_netem):
                    if case.mode == "download":
                        with started_process(
                            [
                                str(bench_binary),
                                "source",
                                "--listen",
                                f"127.0.0.1:{source_port}",
                                "--chunk-size",
                                str(case.chunk_size),
                            ],
                            stdout_path=impl_dir / f"{case.name}.source.stdout.log",
                            stderr_path=impl_dir / f"{case.name}.source.stderr.log",
                            ready_port=source_port,
                        ):
                            metrics = run_compare_socks(
                                proxies=proxies,
                                target=f"127.0.0.1:{source_port}",
                                case=case,
                                curve_sample_interval=curve_sample_interval,
                                logs_dir=impl_dir,
                            )
                    else:
                        metrics = run_compare_socks(
                            proxies=proxies,
                            target=f"127.0.0.1:{sink_port}",
                            case=case,
                            curve_sample_interval=curve_sample_interval,
                            logs_dir=impl_dir,
                        )
                rows.append(
                    {
                        "impl": implementation.label,
                        "ref": implementation.ref,
                        "commit": implementation.commit,
                        "version": implementation.ref,
                        "scenario": case.name,
                        **metrics,
                    }
                )

        return rows


def binary_path(target_dir: pathlib.Path, target: str, name: str) -> pathlib.Path:
    return target_dir / target / "release" / name


def build_current_variant(
    output_dir: pathlib.Path,
    target: str,
    *,
    label: str,
) -> tuple[pathlib.Path, pathlib.Path]:
    target_dir = output_dir / "build-current" / label
    env = os.environ.copy()
    env["CARGO_TARGET_DIR"] = str(target_dir)
    command = [
        "cargo",
        "build",
        "--release",
        "--locked",
        "--target",
        target,
        "--bin",
        "noders-anytls",
        "--bin",
        "bench_anytls",
    ]
    run_checked(command, env=env)
    return binary_path(target_dir, target, "noders-anytls"), binary_path(target_dir, target, "bench_anytls")


def build_ref(ref: str, *, output_dir: pathlib.Path, target: str) -> pathlib.Path:
    worktree_root = output_dir / "worktrees"
    build_root = output_dir / "build-tags"
    worktree_root.mkdir(parents=True, exist_ok=True)
    build_root.mkdir(parents=True, exist_ok=True)
    worktree_path = worktree_root / ref.replace("/", "_")
    target_dir = build_root / ref.replace("/", "_")
    run_checked(["git", "worktree", "add", "--detach", "--force", str(worktree_path), ref])
    try:
        env = os.environ.copy()
        env["CARGO_TARGET_DIR"] = str(target_dir)
        run_checked(
            [
                "cargo",
                "build",
                "--release",
                "--locked",
                "--target",
                target,
                "--bin",
                "noders-anytls",
            ],
            cwd=worktree_path,
            env=env,
        )
    finally:
        run_checked(["git", "worktree", "remove", "--force", str(worktree_path)])
    return binary_path(target_dir, target, "noders-anytls")


def github_json(url: str) -> dict:
    headers = {
        "User-Agent": "NodeRS-AnyTLS-benchmark",
        "Accept": "application/vnd.github+json",
    }
    github_token = os.environ.get("GITHUB_TOKEN") or os.environ.get("GH_TOKEN")
    if github_token:
        headers["Authorization"] = f"Bearer {github_token}"
    request = urllib.request.Request(url, headers=headers)
    with urllib.request.urlopen(request) as response:
        return json.load(response)


def download_sing_box(output_dir: pathlib.Path, version: str) -> tuple[pathlib.Path, str]:
    output_dir.mkdir(parents=True, exist_ok=True)
    if version == "latest":
        release = github_json("https://api.github.com/repos/SagerNet/sing-box/releases/latest")
    else:
        release = github_json(f"https://api.github.com/repos/SagerNet/sing-box/releases/tags/{version}")
    tag_name = release["tag_name"]
    binary_local = output_dir / f"sing-box-{tag_name}"
    if binary_local.exists():
        return binary_local, tag_name

    asset = next(
        (
            item
            for item in release.get("assets", [])
            if item["name"].endswith("linux-amd64.tar.gz") and "with-pgo" not in item["name"]
        ),
        None,
    )
    if asset is None:
        raise RuntimeError(f"unable to find linux-amd64 sing-box asset in release {tag_name}")

    archive_path = output_dir / asset["name"]
    urllib.request.urlretrieve(asset["browser_download_url"], archive_path)
    with tarfile.open(archive_path, "r:gz") as archive:
        archive.extractall(output_dir)
    archive_path.unlink(missing_ok=True)

    asset_stem = asset["name"][: -len(".tar.gz")]
    extracted_dir = output_dir / asset_stem
    extracted_binary = extracted_dir / "sing-box"
    if not extracted_binary.exists():
        raise RuntimeError(f"unexpected sing-box archive layout for {asset['name']}")
    shutil.move(str(extracted_binary), binary_local)
    shutil.rmtree(extracted_dir, ignore_errors=True)
    binary_local.chmod(0o755)
    return binary_local, tag_name


def safe_delta(current: float | None, baseline: float | None) -> str:
    if current is None or baseline is None or baseline == 0:
        return "n/a"
    return f"{((current - baseline) / baseline) * 100:+.2f}%"


def flatten_rows_for_csv(rows: list[dict[str, object]]) -> list[dict[str, object]]:
    flattened: list[dict[str, object]] = []
    for row in rows:
        flattened_row: dict[str, object] = {}
        for key, value in row.items():
            if key == "curve_samples":
                continue
            if isinstance(value, (list, dict)):
                flattened_row[key] = json.dumps(value, ensure_ascii=True)
            else:
                flattened_row[key] = value
        flattened.append(flattened_row)
    return flattened


def write_outputs(
    *,
    output_dir: pathlib.Path,
    cases: list[Case],
    current_impl: str,
    previous_tags: list[str],
    sing_version: str,
    result_rows: list[dict[str, object]],
) -> None:
    output_dir.mkdir(parents=True, exist_ok=True)
    throughput_group = throughput_cases(cases)
    stability_group = stability_cases(cases)
    curve_group = curve_cases(cases)
    latency_group = list(throughput_group)
    raw_json = {
        "generated_at_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "current_impl": current_impl,
        "previous_tags": previous_tags,
        "sing_box_version": sing_version,
        "cases": [case.__dict__ for case in cases],
        "results": result_rows,
    }
    (output_dir / "benchmark-ab-report.json").write_text(json.dumps(raw_json, indent=2), encoding="utf-8")

    csv_rows = flatten_rows_for_csv(result_rows)
    with open(output_dir / "benchmark-ab-report.csv", "w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=sorted({key for row in csv_rows for key in row}))
        writer.writeheader()
        writer.writerows(csv_rows)

    rows_by_scenario: dict[str, dict[str, dict[str, object]]] = {}
    for row in result_rows:
        rows_by_scenario.setdefault(str(row["scenario"]), {})[str(row["impl"])] = row

    impl_order = [current_impl, *previous_tags, "SingBox"]
    lines = [
        "# Benchmark AB Report",
        "",
        f"- Current: `{current_impl}`",
        f"- Previous tags: {', '.join(f'`{tag}`' for tag in previous_tags) if previous_tags else 'none'}",
        f"- Sing-box: `{sing_version}`",
        f"- Long connection seconds: `{max((case.seconds for case in curve_group), default=0)}`",
        f"- Idle seconds: `{max((case.seconds for case in stability_group), default=0)}`",
        "",
        "## Real Connection Throughput",
        "",
        "| Scenario | " + " | ".join(impl_order) + " | Current vs Best Prev | Current vs Sing-box |",
        "| --- | " + " | ".join(["---"] * len(impl_order)) + " | --- | --- |",
    ]
    throughput_summary_rows: list[dict[str, object]] = []
    for case in throughput_group:
        scenario_rows = rows_by_scenario.get(case.name, {})
        current_mbps = scenario_rows.get(current_impl, {}).get("mbps")
        previous_values = [
            float(scenario_rows[tag]["mbps"])
            for tag in previous_tags
            if tag in scenario_rows and scenario_rows[tag].get("mbps") is not None
        ]
        best_previous = max(previous_values) if previous_values else None
        sing_mbps = scenario_rows.get("SingBox", {}).get("mbps")
        cells = []
        for impl in impl_order:
            value = scenario_rows.get(impl, {}).get("mbps")
            cells.append(f"{value:.2f}" if isinstance(value, (int, float)) else "n/a")
        lines.append(
            f"| `{case.name}` | {' | '.join(cells)} | "
            f"{safe_delta(float(current_mbps) if current_mbps is not None else None, best_previous)} | "
            f"{safe_delta(float(current_mbps) if current_mbps is not None else None, float(sing_mbps) if sing_mbps is not None else None)} |"
        )
        throughput_summary_rows.append(
            {
                "scenario": case.name,
                "current_mbps": current_mbps,
                "best_previous_mbps": best_previous,
                "sing_box_mbps": sing_mbps,
                "current_vs_best_previous": safe_delta(
                    float(current_mbps) if current_mbps is not None else None,
                    best_previous,
                ),
                "current_vs_sing_box": safe_delta(
                    float(current_mbps) if current_mbps is not None else None,
                    float(sing_mbps) if sing_mbps is not None else None,
                ),
            }
        )

    latency_summary_rows: list[dict[str, object]] = []
    if latency_group:
        lines.extend(
            [
                "",
                "## Real Connection Latency",
                "",
                "| Scenario | Implementation | Avg Tunnel Connect ms | Avg First Byte ms |",
                "| --- | --- | --- | --- |",
            ]
        )
        for case in latency_group:
            scenario_rows = rows_by_scenario.get(case.name, {})
            for impl in impl_order:
                row = scenario_rows.get(impl)
                connect_ms = row.get("connect_ms") if row else None
                first_byte_ms = row.get("first_byte_ms") if row else None
                lines.append(
                    f"| `{case.name}` | `{impl}` | "
                    f"{f'{connect_ms:.2f}' if isinstance(connect_ms, (int, float)) else 'n/a'} | "
                    f"{f'{first_byte_ms:.2f}' if isinstance(first_byte_ms, (int, float)) else 'n/a'} |"
                )
                latency_summary_rows.append(
                    {
                        "scenario": case.name,
                        "impl": impl,
                        "connect_ms": connect_ms,
                        "first_byte_ms": first_byte_ms,
                    }
                )

    stability_summary_rows: list[dict[str, object]] = []
    if stability_group:
        lines.extend(
            [
                "",
                "## Long Connection Stability",
                "",
                "| Scenario | Implementation | Status | Avg Tunnel Connect ms |",
                "| --- | --- | --- | --- |",
            ]
        )
        for case in stability_group:
            for impl in impl_order:
                row = rows_by_scenario.get(case.name, {}).get(impl)
                status = row.get("status", "n/a") if row else "n/a"
                connect_ms = row.get("connect_ms") if row else None
                lines.append(
                    f"| `{case.name}` | `{impl}` | {status} | "
                    f"{f'{connect_ms:.2f}' if isinstance(connect_ms, (int, float)) else 'n/a'} |"
                )
                stability_summary_rows.append(
                    {
                        "scenario": case.name,
                        "impl": impl,
                        "status": status,
                        "connect_ms": connect_ms,
                    }
                )

    curve_summary_rows: list[dict[str, object]] = []
    curve_tail_rows: list[dict[str, object]] = []
    if curve_group:
        lines.extend(
            [
                "",
                "## Long Connection Curve Summary",
                "",
                "| Scenario | Implementation | Avg Mbps | Peak Mbps | Min Mbps | Tail Avg Mbps | Samples |",
                "| --- | --- | --- | --- | --- | --- | --- |",
            ]
        )
        for case in curve_group:
            scenario_rows = rows_by_scenario.get(case.name, {})
            for impl in impl_order:
                row = scenario_rows.get(impl)
                lines.append(
                    f"| `{case.name}` | `{impl}` | "
                    f"{f'{row.get('curve_avg_mbps'):.2f}' if row and isinstance(row.get('curve_avg_mbps'), (int, float)) else 'n/a'} | "
                    f"{f'{row.get('curve_peak_mbps'):.2f}' if row and isinstance(row.get('curve_peak_mbps'), (int, float)) else 'n/a'} | "
                    f"{f'{row.get('curve_min_mbps'):.2f}' if row and isinstance(row.get('curve_min_mbps'), (int, float)) else 'n/a'} | "
                    f"{f'{row.get('curve_tail_mbps'):.2f}' if row and isinstance(row.get('curve_tail_mbps'), (int, float)) else 'n/a'} | "
                    f"{row.get('curve_points', 'n/a') if row else 'n/a'} |"
                )
                curve_summary_rows.append(
                    {
                        "scenario": case.name,
                        "impl": impl,
                        "curve_avg_mbps": row.get("curve_avg_mbps") if row else None,
                        "curve_peak_mbps": row.get("curve_peak_mbps") if row else None,
                        "curve_min_mbps": row.get("curve_min_mbps") if row else None,
                        "curve_tail_mbps": row.get("curve_tail_mbps") if row else None,
                        "curve_points": row.get("curve_points") if row else None,
                    }
                )

            current_tail = scenario_rows.get(current_impl, {}).get("curve_tail_mbps")
            previous_tail_values = [
                float(scenario_rows[tag]["curve_tail_mbps"])
                for tag in previous_tags
                if tag in scenario_rows and scenario_rows[tag].get("curve_tail_mbps") is not None
            ]
            best_previous_tail = max(previous_tail_values) if previous_tail_values else None
            sing_tail = scenario_rows.get("SingBox", {}).get("curve_tail_mbps")
            curve_tail_rows.append(
                {
                    "scenario": case.name,
                    "current_tail_mbps": current_tail,
                    "best_previous_tail_mbps": best_previous_tail,
                    "sing_box_tail_mbps": sing_tail,
                    "current_vs_best_previous_tail": safe_delta(
                        float(current_tail) if current_tail is not None else None,
                        best_previous_tail,
                    ),
                    "current_vs_sing_box_tail": safe_delta(
                        float(current_tail) if current_tail is not None else None,
                        float(sing_tail) if sing_tail is not None else None,
                    ),
                }
            )

        lines.extend(
            [
                "",
                "## Long Connection Tail Comparison",
                "",
                "| Scenario | Current Tail Mbps | Best Prev Tail Mbps | Sing-box Tail Mbps | Current vs Best Prev | Current vs Sing-box |",
                "| --- | --- | --- | --- | --- | --- |",
            ]
        )
        for row in curve_tail_rows:
            lines.append(
                f"| `{row['scenario']}` | "
                f"{f'{row['current_tail_mbps']:.2f}' if isinstance(row['current_tail_mbps'], (int, float)) else 'n/a'} | "
                f"{f'{row['best_previous_tail_mbps']:.2f}' if isinstance(row['best_previous_tail_mbps'], (int, float)) else 'n/a'} | "
                f"{f'{row['sing_box_tail_mbps']:.2f}' if isinstance(row['sing_box_tail_mbps'], (int, float)) else 'n/a'} | "
                f"{row['current_vs_best_previous_tail']} | "
                f"{row['current_vs_sing_box_tail']} |"
            )

    (output_dir / "report.md").write_text("\n".join(lines) + "\n", encoding="utf-8")
    (output_dir / "summary.json").write_text(
        json.dumps(
            {
                "throughput": throughput_summary_rows,
                "latency": latency_summary_rows,
                "stability": stability_summary_rows,
                "curve_summary": curve_summary_rows,
                "curve_tail_comparison": curve_tail_rows,
            },
            indent=2,
        ),
        encoding="utf-8",
    )


def main() -> int:
    args = parse_args()
    output_dir = pathlib.Path(args.output_dir).resolve()
    output_dir.mkdir(parents=True, exist_ok=True)
    cases = build_cases(args.long_connection_seconds, args.idle_seconds)

    current_commit = git_output("rev-parse", "HEAD")
    previous_tags = select_previous_tags(args.compare_count)
    current_node, bench_binary = build_current_variant(
        output_dir,
        args.target,
        label=f"{args.target}-default",
    )
    implementations = [
        Implementation(
            label="current",
            kind="node",
            ref="HEAD",
            commit=current_commit,
            binary=current_node,
        )
    ]
    for tag in previous_tags:
        implementations.append(
            Implementation(
                label=tag,
                kind="node",
                ref=tag,
                commit=git_output("rev-list", "-n", "1", tag),
                binary=build_ref(tag, output_dir=output_dir, target=args.target),
            )
        )

    sing_binary, sing_version = download_sing_box(output_dir / "sing-box", args.sing_version)
    implementations.append(
        Implementation(
            label="SingBox",
            kind="singbox",
            ref=sing_version,
            commit=sing_version,
            binary=sing_binary,
        )
    )

    result_rows: list[dict[str, object]] = []
    for implementation in implementations:
        rows = benchmark_impl(
            implementation,
            cases=cases,
            bench_binary=bench_binary,
            sing_binary=sing_binary,
            output_dir=output_dir / "logs",
            curve_sample_interval=args.curve_sample_interval,
            enable_netem=args.enable_netem,
        )
        result_rows.extend(rows)

    write_outputs(
        output_dir=output_dir,
        cases=cases,
        current_impl="current",
        previous_tags=previous_tags,
        sing_version=sing_version,
        result_rows=result_rows,
    )
    print(output_dir / "report.md")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
