#!/usr/bin/env python3
"""
ftpm-benchmark-analyzer.py - summarise CA-side fTPM benchmark runs and plot them.

Each CSV is one complete run, in the format bench.h writes:

    seq,t_ftpm_ns,cpu_proc_ns,busy_ticks,total_ticks,rss_kb

It computes, per run and pooled across all runs:
    T_FTPM wall-clock fTPM request time   (t_ftpm_ns / 1e6, ms)
    T_CPU  CA-process CPU time per request (cpu_proc_ns / 1e6, ms)   [new]
    U      system-wide CPU utilisation    (busy_ticks / total_ticks)
    RSS    peak resident set size         (max rss_kb, in MiB)        [new]

Pass any number of run files (a glob works):

    python3 ftpm-benchmark-analyzer.py ~/optee/benchmark/results/run*.csv

Overhead study: give the no-security runs with --baseline and the
with-security runs as the positional args; the delta of the medians is
printed as the overhead attestation adds:

    python3 ftpm-benchmark-analyzer.py sec/run*.csv --baseline base/run*.csv

Options:
    --warmup N   discard the first N requests of each run (default 10)
    --cores C    also report U x C (undo the all-cores averaging)
    --out FILE   also write the text summary there
    --plot FILE  write the diagram (default summary.png; '' to skip)

Needs matplotlib for the plot:  pip install --break-system-packages matplotlib
(The text summary works without it.)
"""
import argparse
import csv
import glob
import math
import os
import re
import statistics
import sys

# Used when no CSV paths are given on the command line.
DEFAULT_GLOB = "~/optee/benchmark/results/run*.csv"

# Used when no output paths are given on the command line.
OUT_DIR = "~/shared/DAT300-Remote-Attestation/FTPM/results"

def natural_key(path):
    """Sort run10 after run2, not before it."""
    nums = re.findall(r"\d+", path)
    return (int(nums[-1]) if nums else 0, path)


def load(path):
    """Return the rows of one run as a list of dicts, in file order."""
    with open(path, newline="") as f:
        rows = list(csv.DictReader(f))
    needed = {"seq", "t_ftpm_ns", "busy_ticks", "total_ticks"}
    if rows and not needed.issubset(rows[0]):
        sys.exit(f"{path}: expected at least columns {sorted(needed)}, got {list(rows[0])}")
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
    """Pull the metrics out of one run's rows, after warm-up."""
    rows = [r for r in rows if int(r["seq"]) >= warmup]
    ta_ms = [int(r["t_ftpm_ns"]) / 1e6 for r in rows]
    cpu_ms = [int(r["cpu_proc_ns"]) / 1e6 for r in rows] if rows and "cpu_proc_ns" in rows[0] else []
    rss_kb = [int(r["rss_kb"]) for r in rows] if rows and "rss_kb" in rows[0] else []
    busy = sum(int(r["busy_ticks"]) for r in rows)
    total = sum(int(r["total_ticks"]) for r in rows)
    u_pooled = busy / total if total else None
    return dict(ta=ta_ms, cpu=cpu_ms, rss=rss_kb, busy=busy, total=total, u=u_pooled)


def collect(paths, warmup):
    """Load every run file; return per-run list and the pooled aggregates."""
    per_run, all_ta, all_cpu = [], [], []
    busy_all = total_all = 0
    rss_peak = 0
    for p in sorted(paths, key=natural_key):
        label = re.sub(r"\.csv$", "", p.split("/")[-1])
        s = run_stats(load(p), warmup)
        if not s["ta"]:
            per_run.append((label, s, "no requests after warm-up"))
            continue
        per_run.append((label, s, None))
        all_ta += s["ta"]
        all_cpu += s["cpu"]
        busy_all += s["busy"]
        total_all += s["total"]
        if s["rss"]:
            rss_peak = max(rss_peak, max(s["rss"]))
    return dict(per_run=per_run, ta=all_ta, cpu=all_cpu,
                busy=busy_all, total=total_all, rss_peak=rss_peak)

def ensure_dir(path):
    """Create the parent directory of an output file if it doesn't exist."""
    d = os.path.dirname(path)
    if d:
        os.makedirs(d, exist_ok=True)


def delta_line(name, sec_vals, base_vals, unit):
    s = pct(sorted(sec_vals), 50)
    b = pct(sorted(base_vals), 50)
    pctg = f"  ({(s - b) / b * 100:+.1f}%)" if b else ""
    return (f"{name} baseline={b:.4g}{unit}  with-sec={s:.4g}{unit}  "
            f"delta={s - b:+.4g}{unit}{pctg}")


def make_plot(per_run, path):
    try:
        import matplotlib
        matplotlib.use("Agg")           # no display needed, write straight to file
        import matplotlib.pyplot as plt
    except ImportError:
        print("\n(matplotlib not installed - skipping the diagram; "
              "run 'pip install --break-system-packages matplotlib' to get it)",
              file=sys.stderr)
        return

    runs = [(label, s) for label, s, note in per_run if note is None]
    labels = [label for label, _ in runs]
    ta_data = [s["ta"] for _, s in runs]
    cpu_data = [s["cpu"] for _, s in runs]
    u_data = [s["u"] if s["u"] is not None else 0 for _, s in runs]
    x = range(len(labels))
    has_cpu = all(cpu_data)

    n = 3 if has_cpu else 2
    fig, axes = plt.subplots(n, 1, figsize=(max(7, len(labels) * 0.9), 3 * n),
                             sharex=True)
    ax = list(axes)

    ax[0].boxplot(ta_data, tick_labels=labels, showfliers=False)
    ax[0].set_ylabel("T_FTPM (ms)")
    ax[0].set_title("Wall-clock fTPM request time per run")
    ax[0].grid(True, axis="y", alpha=0.3)

    i = 1
    if has_cpu:
        ax[i].boxplot(cpu_data, tick_labels=labels, showfliers=False)
        ax[i].set_ylabel("T_CPU (ms)")
        ax[i].set_title("CA-process CPU time per run")
        ax[i].grid(True, axis="y", alpha=0.3)
        i += 1

    ax[i].bar(x, u_data)
    ax[i].set_xticks(list(x))
    ax[i].set_xticklabels(labels, rotation=45, ha="right")
    ax[i].set_ylabel("U (busy / total)")
    ax[i].set_title("System CPU utilisation per run (pooled)")
    ax[i].grid(True, axis="y", alpha=0.3)

    fig.tight_layout()
    fig.savefig(path, dpi=120)
    print(f"\ndiagram written to {path}")


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("csv", nargs="*",
                    help=f"run CSVs (a glob is fine); default {DEFAULT_GLOB}")
    ap.add_argument("--baseline", nargs="+", default=[], metavar="CSV",
                    help="no-security run CSVs; prints the overhead delta")
    ap.add_argument("--warmup", type=int, default=0,
                    help="discard the first N requests of each run (default 0)")
    ap.add_argument("--cores", type=int, default=0,
                    help="also report U x this core count (undo all-cores averaging)")
    ap.add_argument("--out", default=OUT_DIR + "/benchmark-summary.txt",
                    help="also write the text summary here")
    ap.add_argument("--plot", default=OUT_DIR + "/benchmark-summary.png",
                    help="write the plot here ('' to skip)")
    a = ap.parse_args()

    # No files given -> use the default results glob (expanded here, since the
    # shell can't expand it when nothing is typed).
    if not a.csv:
        a.csv = sorted(glob.glob(os.path.expanduser(DEFAULT_GLOB)))
        if not a.csv:
            sys.exit(f"no CSVs given and none found at {DEFAULT_GLOB}")

    agg = collect(a.csv, a.warmup)
    lines = [f"runs analysed: {len(agg['per_run'])} "
             f"(warm-up {a.warmup} discarded per run)", ""]

    for label, s, note in agg["per_run"]:
        if note:
            lines.append(f"{label}: {note}")
            continue
        lines.append(f"{label:<10} {describe('T_FTPM', s['ta'], ' ms')}")
        if s["cpu"]:
            lines.append(f"{'':<10} {describe('T_CPU', s['cpu'], ' ms')}")
        u_txt = f"{s['u']:.4f}" if s["u"] is not None else "undefined (0 ticks)"
        if a.cores:
            u_txt += f"   (U x {a.cores} = {s['u'] * a.cores:.4f})" if s["u"] is not None else ""
        lines.append(f"{'':<10} U(pooled)={u_txt}   ({s['busy']}/{s['total']} ticks)")
        if s["rss"]:
            lines.append(f"{'':<10} RSS peak={max(s['rss']) / 1024:.2f} MiB")

    lines += ["", "-" * 60, describe("T_FTPM (all)", agg["ta"], " ms")]
    if agg["cpu"]:
        lines.append(describe("T_CPU (all)", agg["cpu"], " ms"))
    if agg["total"]:
        u = agg["busy"] / agg["total"]
        u_line = f"U pooled over all runs: {u:.4f}  ({agg['busy']}/{agg['total']} ticks)"
        if a.cores:
            u_line += f"   (U x {a.cores} = {u * a.cores:.4f})"
        lines.append(u_line)
    else:
        lines.append("U pooled: no ticks recorded")
    if agg["rss_peak"]:
        lines.append(f"RSS peak over all runs: {agg['rss_peak'] / 1024:.2f} MiB")

    # ---- overhead vs baseline ----------------------------------------
    if a.baseline:
        base = collect(a.baseline, a.warmup)
        lines += ["", "=" * 60, "OVERHEAD (with-security  minus  baseline), medians:"]
        lines.append(delta_line("T_FTPM", agg["ta"], base["ta"], " ms"))
        if agg["cpu"] and base["cpu"]:
            lines.append(delta_line("T_CPU ", agg["cpu"], base["cpu"], " ms"))
        if agg["rss_peak"] and base["rss_peak"]:
            lines.append(f"RSS peak   baseline={base['rss_peak']/1024:.2f} MiB  "
                         f"with-sec={agg['rss_peak']/1024:.2f} MiB  "
                         f"delta={(agg['rss_peak']-base['rss_peak'])/1024:+.2f} MiB")

    text = "\n".join(lines)
    print(text)
    if a.out:
        out_path = ensure_dir(a.out)
        with open(out_path, "w") as f:
            f.write(text + "\n")

    if a.plot and any(note is None for _, _, note in agg["per_run"]):
        make_plot(agg["per_run"], ensure_dir(a.plot))

if __name__ == "__main__":
    main()