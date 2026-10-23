#!/usr/bin/env python3
"""
compare-analyzer.py - compare several modules (idle / ftpm / tpm / tpm-file)
in one figure.

Each module is a benchmark result set written by bench.h:

    seq,t_ftpm_ns,cpu_proc_ns,busy_ticks,total_ticks,rss_kb

For every module you pass, it loads all the run CSVs and computes, averaged
over the rounds:

    U        system CPU utilisation  (busy_ticks / total_ticks), per round
    T        request time (ms)       (t_ftpm_ns / 1e6), per round mean

and draws two bar panels in one diagram so the modules sit side by side:

    1. mean U per module          (all modules, including idle)
    2. mean request time (ms)     (timed modules only - idle's "time" is just
                                   the sampling window, so it is left out)

Bars show the mean across rounds; the error bar is the standard deviation
across rounds.

Each --<module> takes a PATH that is either a directory (the script finds the
run CSVs under it, e.g. RPi4/results/ftpm or its benchmark-data/ subfolder) or
a glob of CSVs.

Usage:
    python3 compare-analyzer.py \
        --idle     RPi4/results/idle \
        --ftpm     RPi4/results/ftpm \
        --tpm      RPi4/results/tpm \
        --tpm-file RPi4/results/tpm-file \
        --plot compare.png

    # any subset works, and --add labels extra modules:
    python3 compare-analyzer.py --ftpm RPi4/results/ftpm --add pta=some/dir

Options:
    --warmup N   discard the first N requests (by seq) of each round
    --cores C    also report / plot U x C (undo all-cores averaging)
    --out FILE   also write the text summary there
    --plot FILE  write the diagram (default compare-summary.png; '' to skip)

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

OUT_DIR = "~/shared/DAT300-Remote-Attestation/RPi4/results/compare"

# label -> (display name, bar colour, is this module "timed"?)
#   idle is NOT timed: its t_ftpm_ns is just the idle sampling window.
META = {
    "idle":     ("idle",             "#9e9e9e", False),
    "ftpm":     ("fTPM",             "#1f77b4", True),
    "tpm":      ("TPM (IMA)",        "#2ca02c", True),
    "tpm-file": ("TPM (file/PCR16)", "#ff7f0e", True),
}

# Order modules are shown in, when present. Unknown labels go after these.
ORDER = ["idle", "ftpm", "tpm-file", "tpm"]


def meta(label):
    return META.get(label, (label, None, True))


def natural_key(path):
    nums = re.findall(r"\d+", path)
    return (int(nums[-1]) if nums else 0, path)

def find_csvs(path):
    """A directory -> its per-round benchmark CSVs; otherwise treat as a glob.

    You normally pass the exact folder holding the CSVs (e.g.
    .../ftpm/benchmark-data or .../idle/idle-data). If that folder has no CSVs
    directly, we also look one level down in benchmark-data/ or idle-data/, so
    passing the parent label folder (.../ftpm) works too.

    When a directory is given, only per-round files (run*.csv / idle_run*.csv)
    are taken, so DoS CSVs sitting in a sibling dos-data/ folder can never
    sneak into the averages. An explicit glob/file path is trusted as given.
    """
    path = os.path.expanduser(path)
    from_dir = os.path.isdir(path)
    if from_dir:
        cands = glob.glob(os.path.join(path, "*.csv"))
        if not cands:
            for sub in ("benchmark-data", "idle-data"):
                cands = glob.glob(os.path.join(path, sub, "*.csv"))
                if cands:
                    break
    else:
        cands = glob.glob(path)

    good = []
    for p in cands:
        try:
            with open(p, newline="") as f:
                head = f.readline()
            if "t_ftpm_ns" in head and "busy_ticks" in head:
                good.append(p)
        except OSError:
            pass
    return sorted(set(good), key=natural_key)


def read_rows(path):
    with open(path, newline="") as f:
        return list(csv.DictReader(f))


def per_round(path, warmup):
    """One dict per round: pooled U and mean request time (ms) for that round."""
    rounds = []
    files = find_csvs(path)
    for p in files:
        rows = [r for r in read_rows(p) if int(r["seq"]) >= warmup]
        if not rows:
            continue
        busy = sum(int(r["busy_ticks"]) for r in rows)
        total = sum(int(r["total_ticks"]) for r in rows)
        times = [int(r["t_ftpm_ns"]) / 1e6 for r in rows]
        rounds.append(dict(
            file=os.path.basename(p),
            u=(busy / total if total else None),
            busy=busy, total=total,
            t_mean=statistics.fmean(times) if times else None,
            times=times,
        ))
    return rounds, [os.path.basename(p) for p in files]


def agg(rounds):
    """Across-rounds aggregate for one module."""
    us = [r["u"] for r in rounds if r["u"] is not None]
    tmeans = [r["t_mean"] for r in rounds if r["t_mean"] is not None]
    all_t = sorted(t for r in rounds for t in r["times"])
    busy = sum(r["busy"] for r in rounds)
    total = sum(r["total"] for r in rounds)

    def msd(v):
        if not v:
            return (float("nan"), 0.0)
        return (statistics.fmean(v), statistics.stdev(v) if len(v) > 1 else 0.0)

    u_mean, u_sd = msd(us)
    t_mean, t_sd = msd(tmeans)
    return dict(
        n_rounds=len(rounds),
        u_mean=u_mean, u_sd=u_sd,
        u_pooled=(busy / total if total else float("nan")),
        t_mean=t_mean, t_sd=t_sd,
        t_p50=(all_t[max(0, math.ceil(0.50 * len(all_t)) - 1)] if all_t else float("nan")),
        t_p95=(all_t[max(0, math.ceil(0.95 * len(all_t)) - 1)] if all_t else float("nan")),
        n_req=len(all_t),
    )


def ordered_labels(selected):
    known = [l for l in ORDER if l in selected]
    extra = [l for l in selected if l not in ORDER]
    return known + extra


def ensure_dir(path):
    path = os.path.expanduser(path)
    d = os.path.dirname(path)
    if d:
        os.makedirs(d, exist_ok=True)
    return path


def make_plot(labels, data, path, cores):
    try:
        import matplotlib
        matplotlib.use("Agg")
        import matplotlib.pyplot as plt
    except ImportError:
        print("\n(matplotlib not installed - skipping the diagram; "
              "run 'pip install --break-system-packages matplotlib')",
              file=sys.stderr)
        return

    disp = [meta(l)[0] for l in labels]
    colours = [meta(l)[1] for l in labels]

    timed = [l for l in labels if meta(l)[2] and not math.isnan(data[l]["t_mean"])]
    n_panels = 2 if timed else 1
    fig, axes = plt.subplots(1, n_panels, figsize=(5.5 * n_panels, 4.5))
    axes = axes if n_panels > 1 else [axes]

    # ---- panel 1: U in percent ---------------------------------------------
    scale = cores if cores else 1
    max_pct = 100 * scale                       # 100 % of total, or cores*100 % of one core
    u_mean = [data[l]["u_mean"] * scale * 100 for l in labels]
    u_sd   = [data[l]["u_sd"]   * scale * 100 for l in labels]   # same scaling as the mean

    x = range(len(labels))
    bars = axes[0].bar(x, u_mean, color=colours)
    axes[0].set_xticks(list(x))
    axes[0].set_xticklabels(disp, rotation=0, ha="center")
    axes[0].set_ylabel("CPU utilisation (% of one core)" if cores
                       else "CPU utilisation (% of total)")
    axes[0].set_title("Mean CPU utilisation per round"
                      + (f" ({cores} cores)" if cores else ""))
    axes[0].grid(True, axis="y", alpha=0.3)
    axes[0].yaxis.set_major_formatter(matplotlib.ticker.PercentFormatter(decimals=0))
    for b, v in zip(bars, u_mean):
        axes[0].annotate(f"{v:.2f}%", (b.get_x() + b.get_width() / 2, v),
                         ha="center", va="bottom", fontsize=8)

    # axes[0].axhline(max_pct, color="black", linestyle="--", linewidth=0.8)
    # axes[0].annotate("max (all cores busy)" if cores else "max (100 %)",
    #                  (len(labels) - 0.5, max_pct), ha="right", va="bottom", fontsize=8)

    # ---- panel 2: request time (timed modules only) ----------------------
    if timed:
        tx = range(len(timed))
        tdisp = [meta(l)[0] for l in timed]
        tcol = [meta(l)[1] for l in timed]
        t_mean = [data[l]["t_mean"] for l in timed]
        t_sd = [data[l]["t_sd"] for l in timed]
        tbars = axes[1].bar(tx, t_mean, color=tcol)
        axes[1].set_xticks(list(tx))
        axes[1].set_xticklabels(tdisp, rotation=0, ha="center")
        axes[1].set_ylabel("request time (ms)")
        axes[1].set_title("Mean request time per round")
        axes[1].grid(True, axis="y", alpha=0.3)
        for b, v in zip(tbars, t_mean):
            axes[1].annotate(f"{v:.2f}", (b.get_x() + b.get_width() / 2, v),
                             ha="center", va="bottom", fontsize=8)

    fig.tight_layout()
    fig.savefig(path, dpi=120)
    print(f"\ndiagram written to {path}")


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--idle", help="idle result dir or CSV glob")
    ap.add_argument("--ftpm", help="fTPM result dir or CSV glob")
    ap.add_argument("--tpm", help="TPM (IMA) result dir or CSV glob")
    ap.add_argument("--tpm-file", dest="tpm_file",
                    help="TPM-via-fTPM-CA result dir or CSV glob")
    ap.add_argument("--add", action="append", default=[], metavar="LABEL=PATH",
                    help="an extra module, e.g. --add pta=results/pta (repeatable)")
    ap.add_argument("--warmup", type=int, default=0,
                    help="discard the first N requests (by seq) of each round")
    ap.add_argument("--cores", type=int, default=0,
                    help="also report / plot U x this core count")
    ap.add_argument("--out", default=OUT_DIR + "/compare-benchmark-summary.txt",
                    help="also write the text summary here")
    ap.add_argument("--plot", default=OUT_DIR + "/compare-benchmark-summary.png",
                    help="write the diagram here ('' to skip)")
    a = ap.parse_args()

    # Collect selected modules in a stable order.
    selected = {}
    for label, path in (("idle", a.idle), ("ftpm", a.ftpm),
                        ("tpm", a.tpm), ("tpm-file", a.tpm_file)):
        if path:
            selected[label] = path
    for item in a.add:
        if "=" not in item:
            sys.exit(f"--add expects LABEL=PATH, got {item!r}")
        label, path = item.split("=", 1)
        selected[label] = path

    if not selected:
        sys.exit("give at least one module, e.g. --ftpm RPi4/results/ftpm")

    labels = ordered_labels(selected)
    data = {}
    lines = [f"comparison: {', '.join(labels)}  (warm-up {a.warmup} per round)", ""]
    for l in labels:
        rounds, files = per_round(selected[l], a.warmup)
        if not rounds:
            sys.exit(f"{l}: no per-round benchmark CSVs (run*.csv / idle_run*.csv) "
                     f"found under {selected[l]!r}")
        s = agg(rounds)
        data[l] = s
        disp = meta(l)[0]
        u_extra = f"   (U x {a.cores} = {s['u_mean'] * a.cores:.4f})" if a.cores else ""
        lines.append(f"{disp:<18} rounds={s['n_rounds']}  req={s['n_req']}  "
                     f"files={len(files)}")
        lines.append(f"{'':<18} U mean={s['u_mean']:.4f} +/- {s['u_sd']:.4f}"
                     f"   (pooled {s['u_pooled']:.4f}){u_extra}")
        if meta(l)[2] and not math.isnan(s["t_mean"]):
            lines.append(f"{'':<18} T mean={s['t_mean']:.3f} +/- {s['t_sd']:.3f} ms"
                         f"   (p50 {s['t_p50']:.3f}  p95 {s['t_p95']:.3f} ms)")
        else:
            lines.append(f"{'':<18} T  n/a (not a timed module)")
        lines.append("")

    text = "\n".join(lines)
    print(text)
    if a.out:
        with open(ensure_dir(a.out), "w") as f:
            f.write(text + "\n")

    if a.plot:
        make_plot(labels, data, ensure_dir(a.plot), a.cores)


if __name__ == "__main__":
    main()