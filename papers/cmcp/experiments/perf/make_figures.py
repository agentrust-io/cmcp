"""
Generate the cMCP paper result figures from a committed perf results JSON.

Two figures, both matplotlib -> PDF (render cleanly in Tectonic):

  figures/latency-breakdown.pdf
      Per-component latency (Cedar eval, audit append) at the 12-rule bundle,
      p50/p95/p99 grouped bars, log-scaled microseconds.

  figures/cedar-latency-vs-rules.pdf
      Cedar evaluation latency (p50 and p99) vs. Cedar policy rule count,
      from the scaling sweep.

Numbers come only from experiments/results/perf-<date>.json produced by run.py.
Nothing is hard-coded.

Run (from this paper directory):
  PYTHONUTF8=1 python experiments/perf/make_figures.py
"""

from __future__ import annotations

import glob
import json
import os
from pathlib import Path

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt  # noqa: E402

HERE = Path(__file__).resolve().parent
PAPER_ROOT = HERE.parent.parent  # …/agentrust-io/cmcp
RESULTS_DIR = HERE.parent / "results"
FIG_DIR = PAPER_ROOT / "figures"


def _load_results() -> dict:
    files = sorted(glob.glob(str(RESULTS_DIR / "perf-*.json")))
    if not files:
        raise SystemExit(f"No perf results found in {RESULTS_DIR}. Run run.py first.")
    with open(files[-1], encoding="utf-8") as fh:
        return json.load(fh)


def fig_latency_breakdown(data: dict) -> None:
    bd = data["latency_breakdown"]
    components = [
        ("Cedar eval", bd["cedar_eval_us"]),
        ("Audit append", bd["audit_entry_us"]),
    ]
    percentiles = ["p50", "p95", "p99"]
    x = range(len(components))
    width = 0.25

    fig, ax = plt.subplots(figsize=(5.2, 3.1))
    colors = ["#2b6cb0", "#4299e1", "#90cdf4"]
    for i, p in enumerate(percentiles):
        vals = [c[1][p] for c in components]
        offs = [xi + (i - 1) * width for xi in x]
        bars = ax.bar(offs, vals, width, label=p, color=colors[i])
        for b, v in zip(bars, vals):
            ax.annotate(
                f"{v:.0f}",
                (b.get_x() + b.get_width() / 2, v),
                ha="center", va="bottom", fontsize=7,
            )
    ax.set_yscale("log")
    ax.set_ylabel("Latency (microseconds, log)")
    ax.set_xticks(list(x))
    ax.set_xticklabels([c[0] for c in components])
    n = bd["policy_rules_count"]
    ax.set_title(f"Per-component latency, {n}-rule bundle (software-only)", fontsize=10)
    ax.legend(title="percentile", fontsize=8, title_fontsize=8)
    ax.grid(axis="y", ls=":", alpha=0.5)
    fig.tight_layout()
    out = FIG_DIR / "latency-breakdown.pdf"
    fig.savefig(out)
    plt.close(fig)
    print(f"wrote {out}")


def fig_cedar_vs_rules(data: dict) -> None:
    sweep = data["rule_count_sweep"]
    rules = [r["rules"] for r in sweep]
    p50 = [r["cedar_eval_us"]["p50"] for r in sweep]
    p99 = [r["cedar_eval_us"]["p99"] for r in sweep]

    fig, ax = plt.subplots(figsize=(5.2, 3.1))
    ax.plot(rules, p50, marker="o", color="#2b6cb0", label="p50")
    ax.plot(rules, p99, marker="s", color="#dd6b20", label="p99")
    ax.set_xscale("log")
    ax.set_xlabel("Cedar rules in bundle")
    ax.set_ylabel("Cedar eval latency (microseconds)")
    ax.set_title("Cedar eval latency vs. rule count (software-only)", fontsize=10)
    ax.set_xticks(rules)
    ax.set_xticklabels([str(r) for r in rules])
    ax.minorticks_off()
    ax.legend(fontsize=9)
    ax.grid(ls=":", alpha=0.5)
    fig.tight_layout()
    out = FIG_DIR / "cedar-latency-vs-rules.pdf"
    fig.savefig(out)
    plt.close(fig)
    print(f"wrote {out}")


def main() -> None:
    os.makedirs(FIG_DIR, exist_ok=True)
    data = _load_results()
    print(f"source: {data.get('timestamp')} python={data.get('python')}")
    fig_latency_breakdown(data)
    fig_cedar_vs_rules(data)


if __name__ == "__main__":
    main()
