#!/usr/bin/env python3
"""
ftpm-benchmark-analyzer.py - summarise CA-side fTPM benchmark runs and plot them.

Each CSV is one complete run with the columns:

    seq,t_ta_ns,busy_ticks,total_ticks

It computes, per run and pooled across all runs:
    T_TA   the fTPM request time   (t_ta_ns / 1e6, in ms)
    U      CPU utilisation         (busy_ticks / total_ticks)

Pass any number of run files (a glob works):

    python3 ftpm-benchmark-analyzer.py ~/optee/benchmark/results/run*.csv
    python3 ftpm-benchmark-analyzer.py run*.csv --warmup 10 --out summary.txt --plot summary.png

The diagram (PNG) shows the T_TA distribution per run as a boxplot, with a
second panel for each run's utilisation. Needs matplotlib for the plot:

    pip install matplotlib        (text summary still works without it)
"""
import argparse
import csv
import math
import re
import statistics
import sys


def natural_key(path):
    """Sort run10 after run2, not before it."""
    nums = re.findall(r"\d+", path)
    return (int(nums[-1]) if nums else 0, path)


def load(path):
    """Return the rows of one run as a list of dicts, in file order."""
    with open(path, newline="") as f:
        rows = list(csv.DictReader(f))
    needed = {"seq", "t_ta_ns", "busy_ticks", "total_ticks"}
    if rows and not needed.issubset(rows[0]):
        sys.exit(f"{path}: expected columns {sorted(needed)}, got {list(rows[0])}")
    return rows


def pct(v, p):
    k = max(0, min(len(v) - 1, math.ceil(p / 100 * len(v)) - 1))
    return v[k]


def describe(name, vals, unit=""):
    v = sorted(x for x in vals if x is not None)
    if not v:
        return f"{name:<16} no data"
    sd = statistics.stdev(v) if len(v) > 1 else 0.0
    return (f"{name:<16} n={len(v):<5} min={v[0]:.4g}{unit}  p50={pct(v, 50):.4g}{unit}  "
            f"mean={statistics.fmean(v):.4g}{unit}  p95={pct(v, 95):.4g}{unit}  "
            f"max={v[-1]:.4g}{unit}  sd={sd:.3g}")


def run_stats(rows, warmup):
    """Pull T_TA (ms) and utilisation out of one run's rows, after warm-up."""
    rows = [r for r in rows if int(r["seq"]) >= warmup]
    ta_ms = [int(r["t_ta_ns"]) / 1e6 for r in rows]
    busy = sum(int(r["busy_ticks"]) for r in rows)
    total = sum(int(r["total_ticks"]) for r in rows)
    u_pooled = busy / total if total else None
    return ta_ms, busy, total, u_pooled


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("csv", nargs="+", help="one or more run CSVs (a glob is fine)")
    ap.add_argument("--warmup", type=int, default=10,
                    help="discard the first N requests of each run (default 10)")
    ap.add_argument("--out", help="also write the text summary to this file")
    ap.add_argument("--plot", default="summary.png",
                    help="write the diagram here (default summary.png; '' to skip)")
    a = ap.parse_args()

    paths = sorted(a.csv, key=natural_key)
    lines = [f"runs analysed: {len(paths)} (warm-up {a.warmup} discarded per run)", ""]

    per_run = []          # (label, ta_ms list, u_pooled) for the plot
    all_ta = []           # every T_TA sample, for the pooled row
    busy_all = total_all = 0

    for p in paths:
        label = re.sub(r"\.csv$", "", p.split("/")[-1])
        ta_ms, busy, total, u_pooled = run_stats(load(p), a.warmup)
        if not ta_ms:
            lines.append(f"{label}: no requests after warm-up")
            continue
        per_run.append((label, ta_ms, u_pooled))
        all_ta += ta_ms
        busy_all += busy
        total_all += total
        u_txt = f"{u_pooled:.4f}" if u_pooled is not None else "undefined (0 ticks)"
        lines.append(f"{label:<10} {describe('T_TA', ta_ms, ' ms')}")
        lines.append(f"{'':<10} U(pooled)={u_txt}   ({busy}/{total} ticks)")

    lines += ["", "-" * 60,
              describe("T_TA (all runs)", all_ta, " ms"),
              f"U pooled over all runs: "
              + (f"{busy_all / total_all:.4f}  ({busy_all}/{total_all} ticks)"
                 if total_all else "no ticks recorded")]

    text = "\n".join(lines)
    print(text)
    if a.out:
        with open(a.out, "w") as f:
            f.write(text + "\n")

    if a.plot and per_run:
        make_plot(per_run, a.plot)


def make_plot(per_run, path):
    try:
        import matplotlib
        matplotlib.use("Agg")           # no display needed, write straight to file
        import matplotlib.pyplot as plt
    except ImportError:
        print("\n(matplotlib not installed - skipping the diagram; "
              "run 'pip install matplotlib' to get it)", file=sys.stderr)
        return

    labels = [r[0] for r in per_run]
    ta_data = [r[1] for r in per_run]
    u_data = [r[2] if r[2] is not None else 0 for r in per_run]
    x = range(len(labels))

    fig, (ax1, ax2) = plt.subplots(2, 1, figsize=(max(7, len(labels) * 0.9), 7),
                                   sharex=True)

    ax1.boxplot(ta_data, tick_labels=labels, showfliers=False)
    ax1.set_ylabel("T_TA (ms)")
    ax1.set_title("fTPM request time per run")
    ax1.grid(True, axis="y", alpha=0.3)

    ax2.bar(x, u_data)
    ax2.set_xticks(list(x))
    ax2.set_xticklabels(labels, rotation=45, ha="right")
    ax2.set_ylabel("U (busy / total)")
    ax2.set_title("CPU utilisation per run (pooled)")
    ax2.grid(True, axis="y", alpha=0.3)

    fig.tight_layout()
    fig.savefig(path, dpi=120)
    print(f"\ndiagram written to {path}")


if __name__ == "__main__":
    main()