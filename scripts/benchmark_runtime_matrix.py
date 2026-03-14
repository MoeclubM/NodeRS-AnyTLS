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
    ("gnu-system", "x86_64-unknown-linux-gnu"),
    ("musl-system", "x86_64-unknown-linux-musl"),
]


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Benchmark current supported runtime variants on Linux.")
    parser.add_argument("--output-dir", required=True)
    parser.add_argument("--sing-version", default="latest")
    parser.add_argument("--enable-netem", action="store_true")
    return parser.parse_args()


def rows_by_scenario(result_rows: list[dict[str, object]]) -> dict[str, dict[str, dict[str, object]]]:
    rows: dict[str, dict[str, dict[str, object]]] = {}
    for row in result_rows:
        rows.setdefault(str(row["scenario"]), {})[str(row["impl"])] = row
    return rows


def throughput_delta(summary_rows: list[dict[str, object]], scenario: str) -> str:
    row = next((item for item in summary_rows if item["scenario"] == scenario), None)
    if row is None:
        return "n/a"
    return str(row["musl_system_vs_gnu_system"])


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
        "variants": [label for label, _ in VARIANTS],
        "sing_box_version": sing_version,
        "cases": [case.__dict__ for case in CASES],
        "idle_memory": idle_rows,
        "results": result_rows,
    }
    (output_dir / "runtime-matrix-report.json").write_text(json.dumps(raw_json, indent=2), encoding="utf-8")

    scenario_rows = rows_by_scenario(result_rows)
    impl_order = [label for label, _ in VARIANTS] + ["SingBox"]
    lines = [
        "# Runtime Matrix Report",
        "",
        "- Baseline: `gnu-system`",
        "- Variants: `musl-system`",
        f"- Sing-box: `{sing_version}`",
        "",
        "## Throughput",
        "",
        "| Scenario | " + " | ".join(impl_order) + " | musl-system vs gnu-system |",
        "| --- | " + " | ".join(["---"] * len(impl_order)) + " | --- |",
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
            f"{safe_delta(values['musl-system'], values['gnu-system'])} |"
        )
        summary_rows.append(
            {
                "scenario": case.name,
                "gnu_system_mbps": values["gnu-system"],
                "musl_system_mbps": values["musl-system"],
                "sing_box_mbps": values["SingBox"],
                "musl_system_vs_gnu_system": safe_delta(values["musl-system"], values["gnu-system"]),
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

    gnu_system_private = idle_by_impl.get("gnu-system", {}).get("avg_private_mb")
    musl_system_private = idle_by_impl.get("musl-system", {}).get("avg_private_mb")
    lines.extend(
        [
            "",
            "## Signals",
            "",
            f"- `idle private` musl vs gnu: {safe_delta(musl_system_private, gnu_system_private)}",
            f"- `download-concurrency-small` musl vs gnu: {throughput_delta(summary_rows, 'download-concurrency-small')}",
            f"- `download-concurrency-large` musl vs gnu: {throughput_delta(summary_rows, 'download-concurrency-large')}",
            f"- `download-concurrency-small-lossy` musl vs gnu: {throughput_delta(summary_rows, 'download-concurrency-small-lossy')}",
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
    for label, target in VARIANTS:
        node_binary, bench_binary = build_current_variant(
            output_dir,
            target,
            label=label,
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
