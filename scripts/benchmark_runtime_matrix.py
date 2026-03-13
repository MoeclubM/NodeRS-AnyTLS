#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import pathlib
import time

from benchmark_ab_report import (
    CASES,
    Implementation,
    benchmark_impl,
    build_current_variant,
    download_sing_box,
    git_output,
    safe_delta,
)


VARIANTS = [
    ("gnu-system", "x86_64-unknown-linux-gnu", []),
    ("gnu-mimalloc", "x86_64-unknown-linux-gnu", ["linux-mimalloc"]),
    ("musl-system", "x86_64-unknown-linux-musl", []),
    ("musl-mimalloc", "x86_64-unknown-linux-musl", ["linux-mimalloc"]),
]


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Benchmark current runtime variants on Linux.")
    parser.add_argument("--output-dir", required=True)
    parser.add_argument("--sing-version", default="latest")
    parser.add_argument("--enable-netem", action="store_true")
    return parser.parse_args()


def rows_by_scenario(result_rows: list[dict[str, object]]) -> dict[str, dict[str, dict[str, object]]]:
    rows: dict[str, dict[str, dict[str, object]]] = {}
    for row in result_rows:
        rows.setdefault(str(row["scenario"]), {})[str(row["impl"])] = row
    return rows


def write_outputs(
    *,
    output_dir: pathlib.Path,
    sing_version: str,
    idle_rows: list[dict[str, object]],
    result_rows: list[dict[str, object]],
) -> None:
    output_dir.mkdir(parents=True, exist_ok=True)
    raw_json = {
        "generated_at_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "variants": [label for label, _, _ in VARIANTS],
        "sing_box_version": sing_version,
        "cases": [case.__dict__ for case in CASES],
        "idle_memory": idle_rows,
        "results": result_rows,
    }
    (output_dir / "runtime-matrix-report.json").write_text(json.dumps(raw_json, indent=2), encoding="utf-8")

    scenario_rows = rows_by_scenario(result_rows)
    impl_order = [label for label, _, _ in VARIANTS] + ["SingBox"]
    lines = [
        "# Runtime Matrix Report",
        "",
        "- Baseline: `gnu-system`",
        "- Variants: `gnu-mimalloc`, `musl-system`, `musl-mimalloc`",
        f"- Sing-box: `{sing_version}`",
        "",
        "## Throughput",
        "",
        "| Scenario | "
        + " | ".join(impl_order)
        + " | gnu-mimalloc vs gnu-system | musl-system vs gnu-system | musl-mimalloc vs musl-system | musl-mimalloc vs gnu-system |",
        "| --- | " + " | ".join(["---"] * len(impl_order)) + " | --- | --- | --- | --- |",
    ]
    summary_rows: list[dict[str, object]] = []
    for case in CASES:
        case_rows = scenario_rows.get(case.name, {})
        values = {label: case_rows.get(label, {}).get("mbps") for label in impl_order}
        cells = [
            f"{values[label]:.2f}" if isinstance(values[label], (int, float)) else "n/a"
            for label in impl_order
        ]
        lines.append(
            f"| `{case.name}` | {' | '.join(cells)} | "
            f"{safe_delta(values['gnu-mimalloc'], values['gnu-system'])} | "
            f"{safe_delta(values['musl-system'], values['gnu-system'])} | "
            f"{safe_delta(values['musl-mimalloc'], values['musl-system'])} | "
            f"{safe_delta(values['musl-mimalloc'], values['gnu-system'])} |"
        )
        summary_rows.append(
            {
                "scenario": case.name,
                "gnu_system_mbps": values["gnu-system"],
                "gnu_mimalloc_mbps": values["gnu-mimalloc"],
                "musl_system_mbps": values["musl-system"],
                "musl_mimalloc_mbps": values["musl-mimalloc"],
                "sing_box_mbps": values["SingBox"],
                "gnu_mimalloc_vs_gnu_system": safe_delta(values["gnu-mimalloc"], values["gnu-system"]),
                "musl_system_vs_gnu_system": safe_delta(values["musl-system"], values["gnu-system"]),
                "musl_mimalloc_vs_musl_system": safe_delta(values["musl-mimalloc"], values["musl-system"]),
                "musl_mimalloc_vs_gnu_system": safe_delta(values["musl-mimalloc"], values["gnu-system"]),
            }
        )

    lines.extend(
        [
            "",
            "## Idle Memory",
            "",
            "| Implementation | Peak RSS MB | Avg RSS MB | Peak Private MB | Avg Private MB | vs gnu-system Private |",
            "| --- | --- | --- | --- | --- | --- |",
        ]
    )
    idle_by_impl = {str(row["impl"]): row for row in idle_rows}
    baseline_private = idle_by_impl.get("gnu-system", {}).get("avg_private_mb")
    memory_summary: list[dict[str, object]] = []
    for label in impl_order:
        row = idle_by_impl.get(label)
        if row is None:
            lines.append(f"| `{label}` | n/a | n/a | n/a | n/a | n/a |")
            continue
        lines.append(
            f"| `{label}` | {row['peak_rss_mb']:.2f} | {row['avg_rss_mb']:.2f} | "
            f"{row['peak_private_mb']:.2f} | {row['avg_private_mb']:.2f} | "
            f"{safe_delta(row['avg_private_mb'], baseline_private)} |"
        )
        memory_summary.append(
            {
                "impl": label,
                "peak_rss_mb": row["peak_rss_mb"],
                "avg_rss_mb": row["avg_rss_mb"],
                "peak_private_mb": row["peak_private_mb"],
                "avg_private_mb": row["avg_private_mb"],
                "vs_gnu_system_private": safe_delta(row["avg_private_mb"], baseline_private),
            }
        )

    small_case = next((item for item in summary_rows if item["scenario"] == "download-concurrency-small"), None)
    gnu_system_private = idle_by_impl.get("gnu-system", {}).get("avg_private_mb")
    gnu_mimalloc_private = idle_by_impl.get("gnu-mimalloc", {}).get("avg_private_mb")
    musl_system_private = idle_by_impl.get("musl-system", {}).get("avg_private_mb")
    musl_mimalloc_private = idle_by_impl.get("musl-mimalloc", {}).get("avg_private_mb")

    def signed_delta(current: float | None, baseline: float | None) -> float | None:
        if current is None or baseline in (None, 0):
            return None
        return ((current - baseline) / baseline) * 100

    small_gnu_mimalloc = signed_delta(
        small_case["gnu_mimalloc_mbps"] if small_case else None,
        small_case["gnu_system_mbps"] if small_case else None,
    )
    small_musl_system = signed_delta(
        small_case["musl_system_mbps"] if small_case else None,
        small_case["gnu_system_mbps"] if small_case else None,
    )
    memory_gnu_mimalloc = signed_delta(gnu_mimalloc_private, gnu_system_private)
    memory_musl_system = signed_delta(musl_system_private, gnu_system_private)
    memory_musl_mimalloc = signed_delta(musl_mimalloc_private, gnu_system_private)

    if memory_gnu_mimalloc is not None and memory_musl_system is not None:
        if abs(memory_gnu_mimalloc) > abs(memory_musl_system) * 1.5:
            memory_culprit = "mimalloc"
        elif abs(memory_musl_system) > abs(memory_gnu_mimalloc) * 1.5:
            memory_culprit = "musl"
        else:
            memory_culprit = "mixed"
    else:
        memory_culprit = "n/a"

    if small_gnu_mimalloc is not None and small_musl_system is not None:
        if abs(small_gnu_mimalloc) > abs(small_musl_system) * 1.5:
            small_packet_culprit = "mimalloc"
        elif abs(small_musl_system) > abs(small_gnu_mimalloc) * 1.5:
            small_packet_culprit = "musl"
        else:
            small_packet_culprit = "mixed"
    else:
        small_packet_culprit = "n/a"

    lines.extend(
        [
            "",
            "## Signals",
            "",
            f"- Likely idle-memory culprit: `{memory_culprit}`",
            f"- `gnu-mimalloc` avg private vs `gnu-system`: {safe_delta(gnu_mimalloc_private, gnu_system_private)}",
            f"- `musl-system` avg private vs `gnu-system`: {safe_delta(musl_system_private, gnu_system_private)}",
            f"- `musl-mimalloc` avg private vs `gnu-system`: {safe_delta(musl_mimalloc_private, gnu_system_private)}",
            f"- Likely small-packet culprit on `download-concurrency-small`: `{small_packet_culprit}`",
            f"- `gnu-mimalloc` vs `gnu-system`: {small_case['gnu_mimalloc_vs_gnu_system'] if small_case else 'n/a'}",
            f"- `musl-system` vs `gnu-system`: {small_case['musl_system_vs_gnu_system'] if small_case else 'n/a'}",
            f"- `musl-mimalloc` vs `gnu-system`: {small_case['musl_mimalloc_vs_gnu_system'] if small_case else 'n/a'}",
        ]
    )

    (output_dir / "report.md").write_text("\n".join(lines) + "\n", encoding="utf-8")
    (output_dir / "summary.json").write_text(
        json.dumps({"throughput": summary_rows, "memory": memory_summary}, indent=2),
        encoding="utf-8",
    )


def main() -> int:
    args = parse_args()
    output_dir = pathlib.Path(args.output_dir).resolve()
    output_dir.mkdir(parents=True, exist_ok=True)

    current_commit = git_output("rev-parse", "HEAD")
    implementations: list[Implementation] = []
    for label, target, features in VARIANTS:
        node_binary, bench_binary = build_current_variant(
            output_dir,
            target,
            label=label,
            features=features,
        )
        implementations.append(
            Implementation(
                label=label,
                kind="node",
                ref="HEAD",
                commit=current_commit,
                binary=node_binary,
                bench_binary=bench_binary,
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
            version=sing_version,
            bench_binary=implementations[0].bench_binary,
        )
    )

    idle_rows: list[dict[str, object]] = []
    result_rows: list[dict[str, object]] = []
    for implementation in implementations:
        idle_memory, rows = benchmark_impl(
            implementation,
            bench_binary=implementations[0].bench_binary,
            sing_binary=sing_binary,
            output_dir=output_dir / "logs",
            enable_netem=args.enable_netem,
        )
        idle_rows.append({"impl": implementation.label, **idle_memory})
        result_rows.extend(rows)

    write_outputs(
        output_dir=output_dir,
        sing_version=sing_version,
        idle_rows=idle_rows,
        result_rows=result_rows,
    )
    print(output_dir / "report.md")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
