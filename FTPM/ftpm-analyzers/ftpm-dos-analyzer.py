#!/usr/bin/env python3
"""
ftpm-dos-analyzer.py - availability analysis of the RA under fTPM load.

Pairs two per-level CSVs from one DoS run and reports availability:

  CA side   (latency)   ca_load<N>.csv        from bench.h (BENCH_OUT)
                        seq,t_ftpm_ns,cpu_proc_ns,busy_ticks,total_ticks,rss_kb
  Verifier  (verdict)   verifier_load<N>.csv  from verifier.py --dos
                        seq,unix_time,result,load_level

Enrollment is done SEPARATELY (not inside a run), so every row here is an
attest and the two files share the same seq numbering: CA seq k and verifier
seq k are the same request. They are matched by seq:
    verifier TRUSTED  + CA row at that seq -> completed, latency from CA
    verifier TIMEOUT/LOST                  -> denied (no latency)
    verifier TRUSTED  but no CA row        -> denied (CA never logged it)

Per load level N it reports:
    n          completed attestations (matched CA latency)
    denied     requests the verifier did not get answered in time
    success%   n / (n + denied)
    p50/p95/p99/max   fTPM latency over completed requests (ms)

Usage:
    python3 ftpm-dos-analyzer.py                 # auto-discover under results dir
    python3 ftpm-dos-analyzer.py --warmup 1      # also drop the first attest
    python3 ftpm-dos-analyzer.py ca_load*.csv verifier_load*.csv   # explicit

Needs matplotlib for the plot:  pip install --break-system-packages matplotlib
(The text summary works without it.)
"""
import argparse
import csv
import glob
import math
import os
import re
import sys

# Auto-discovery when no files are given on the command line.
RESULTS_DIR = "~/optee/dos/results"
CA_GLOB = RESULTS_DIR + "/ca_load*.csv"
VERIFIER_GLOB = RESULTS_DIR + "/verifier_load*.csv"

# Used when no output paths are given on the command line.
OUT_DIR = "~/shared/DAT300-Remote-Attestation/FTPM/results"

# Verifier results that mean "this request was NOT answered in time".
DENIED_TAGS = {"TIMEOUT/LOST"}

def pct(v, p):
    """Same percentile convention as the CA-side benchmark analyzer."""
    if not v:
        return float("nan")
    k = max(0, min(len(v) - 1, math.ceil(p / 100 * len(v)) - 1))
    return v[k]


def level_of(path):
    """The load level N encoded in a filename like ca_load4.csv -> '4'."""
    m = re.search(r"load[_-]?(\d+)", os.path.basename(path))
    if m:
        return m.group(1)
    nums = re.findall(r"\d+", os.path.basename(path))
    return nums[-1] if nums else re.sub(r"\.csv$", "", os.path.basename(path))


def numkey(s):
    """Sort '10' after '2', and '2' after '1'."""
    nums = re.findall(r"\d+", str(s))
    return (int(nums[0]) if nums else 1 << 30, str(s))


def read_ca(path):
    """ca_load<N>.csv -> {seq: latency_ms}. Latency is t_ftpm_ns / 1e6."""
    out = {}
    with open(path, newline="") as f:
        rd = csv.DictReader(f)
        if rd.fieldnames and not {"seq", "t_ftpm_ns"}.issubset(rd.fieldnames):
            sys.exit(f"{path}: expected seq,t_ftpm_ns,...  got {rd.fieldnames}")
        for r in rd:
            out[int(r["seq"])] = int(r["t_ftpm_ns"]) / 1e6
    return out


def read_verifier(path):
    """verifier_load<N>.csv -> list of (seq, result), in file order."""
    out = []
    with open(path, newline="") as f:
        rd = csv.DictReader(f)
        if rd.fieldnames and not {"seq", "result"}.issubset(rd.fieldnames):
            sys.exit(f"{path}: expected seq,...,result  got {rd.fieldnames}")
        for r in rd:
            out.append((int(r["seq"]), (r["result"] or "").strip()))
    return out


def pair_files(ca_paths, verifier_paths):
    """Group CA and verifier files by load level N."""
    levels = {}
    for p in ca_paths:
        levels.setdefault(level_of(p), {}).setdefault("ca", []).append(p)
    for p in verifier_paths:
        levels.setdefault(level_of(p), {}).setdefault("ver", []).append(p)
    return levels


def merge_level(ca_paths, ver_paths, warmup):
    """
    Merge one level's CA + verifier files into availability stats.

    Enroll is separate, so CA and verifier share seq numbering. Match by seq:
    the verifier row is the authority on answered vs denied; its latency (when
    completed) is the CA's t_ftpm_ns at the SAME seq.
    """
    ca = {}
    for p in ca_paths:
        ca.update(read_ca(p))

    ver = []
    for p in ver_paths:
        ver += read_verifier(p)

    # In seq order so warmup drops the *first* attests consistently.
    ver_attests = sorted((seq, res) for seq, res in ver)
    if warmup > 0:
        ver_attests = ver_attests[warmup:]

    completed_lat, denied = [], 0

    if ver_attests:
        for seq, res in ver_attests:
            if res in DENIED_TAGS:
                denied += 1
            elif seq in ca:
                completed_lat.append(ca[seq])     # same-seq latency
            else:
                denied += 1          # verifier says answered but CA has no row
    else:
        # CA-only (no verifier file): latency only, availability unknown.
        ca_seqs = sorted(ca)
        if warmup > 0:
            ca_seqs = ca_seqs[warmup:]
        completed_lat = [ca[s] for s in ca_seqs]
        denied = None

    lat = sorted(completed_lat)
    n = len(lat)
    if denied is None:
        succ = float("nan")
    else:
        total = n + denied
        succ = 100 * n / total if total else float("nan")
    return dict(n=n, denied=(0 if denied is None else denied),
                denied_known=(denied is not None), succ=succ,
                p50=pct(lat, 50), p95=pct(lat, 95), p99=pct(lat, 99),
                mx=(lat[-1] if lat else float("nan")),
                have_ca=bool(ca), have_ver=bool(ver))


def summarise(levels, warmup):
    out = []
    for key in sorted(levels, key=numkey):
        files = levels[key]
        s = merge_level(files.get("ca", []), files.get("ver", []), warmup)
        s["level"] = key
        out.append(s)
    return out


def format_text(rows, warmup):
    lines = [f"load levels: {len(rows)} (warm-up {warmup} attests discarded "
             f"per side)", ""]
    for s in rows:
        succ = f"{s['succ']:5.1f}%" if not math.isnan(s["succ"]) else "   -  "
        denied = f"{s['denied']:<3}" if s["denied_known"] else " ? "
        src = "".join(("C" if s["have_ca"] else "-",
                       "V" if s["have_ver"] else "-"))
        lines.append(
            f"load={s['level']:<6} [{src}] n={s['n']:<4} denied={denied} "
            f"success={succ}   "
            f"p50={s['p50']:8.1f}  p95={s['p95']:8.1f}  p99={s['p99']:8.1f}  "
            f"max={s['mx']:8.1f} ms")
    lines += ["", "[CV] = CA latency file + verifier verdict file present; "
              "'-' = missing (denied '?' means no verifier file)."]
    return "\n".join(lines)


def ensure_dir(path):
    path = os.path.expanduser(path)
    d = os.path.dirname(path)
    if d:
        os.makedirs(d, exist_ok=True)
    return path


def make_plot(rows, path):
    try:
        import matplotlib
        matplotlib.use("Agg")
        import matplotlib.pyplot as plt
    except ImportError:
        print("\n(matplotlib not installed - skipping the plot; "
              "run 'pip install --break-system-packages matplotlib')",
              file=sys.stderr)
        return

    xs, labels = [], []
    for i, s in enumerate(rows):
        m = re.findall(r"\d+", str(s["level"]))
        xs.append(int(m[0]) if m else i)
        labels.append(str(s["level"]))

    fig, ax = plt.subplots(2, 1, figsize=(8, 7), sharex=True)

    # Latency: NaN at fully-denied levels. matplotlib skips them, so the line
    # ends where completions end - that is correct, not a bug. We DON'T invent
    # a value; the success panel below explains the gap.
    ax[0].plot(xs, [s["p50"] for s in rows], "o-", label="p50")
    ax[0].plot(xs, [s["p95"] for s in rows], "s-", label="p95")
    ax[0].plot(xs, [s["p99"] for s in rows], "^-", label="p99")
    ax[0].set_ylabel("fTPM latency (ms)")
    ax[0].set_title("CA-side fTPM latency (completed requests) vs load")
    ax[0].legend()
    ax[0].grid(True, alpha=0.3)

    # Shade the levels where no request completed (latency undefined), so the
    # gap in the latency line is explained rather than mysterious.
    denied_xs = [x for x, s in zip(xs, rows) if math.isnan(s["p50"])]
    for x in denied_xs:
        ax[0].axvspan(x - 0.4, x + 0.4, color="tab:red", alpha=0.08)
    if denied_xs:
        ax[0].text(0.99, 0.02, "shaded = no completed requests (fully denied)",
                   transform=ax[0].transAxes, ha="right", va="bottom",
                   fontsize=8, color="tab:red")

    succ = [s["succ"] for s in rows]
    ax[1].plot(xs, succ, "o-", color="tab:red")
    ax[1].set_ylabel("success rate (%)")
    ax[1].set_ylim(-5, 105)
    ax[1].set_xlabel("contending TPM workers on the attester device")
    ax[1].set_title("Attestation success rate vs load")
    ax[1].grid(True, alpha=0.3)
    ax[1].set_xticks(xs)
    ax[1].set_xticklabels(labels, rotation=0, ha="right")

    fig.tight_layout()
    fig.savefig(path, dpi=120)
    print(f"\nplot written to {path}")


def expand(patterns):
    files = []
    for pat in patterns:
        files += glob.glob(os.path.expanduser(pat)) or []
    return sorted(set(files), key=numkey)


def main():
    ap = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("csv", nargs="*",
                    help="explicit CSVs (CA and/or verifier, globs ok); "
                         "sorted into the two kinds by name. Default: "
                         f"auto-discover under {RESULTS_DIR}")
    ap.add_argument("--ca-glob", default=CA_GLOB,
                    help=f"CA latency files (default {CA_GLOB})")
    ap.add_argument("--verifier-glob", default=VERIFIER_GLOB,
                    help=f"verifier verdict files (default {VERIFIER_GLOB})")
    ap.add_argument("--warmup", type=int, default=0,
                    help="discard the first N attests (by seq) from both sides")
    ap.add_argument("--out", default=OUT_DIR + "/dos-summary.txt",
                    help="also write the text summary here")
    ap.add_argument("--plot", default=OUT_DIR + "/dos-summary.png",
                    help="write the plot here ('' to skip)")
    a = ap.parse_args()

    if a.csv:
        # Explicit files: sort each path into CA vs verifier by its name.
        allf = expand(a.csv)
        ca = [p for p in allf if "ca_load" in os.path.basename(p)
              or "ca-" in os.path.basename(p)]
        ver = [p for p in allf if "verifier" in os.path.basename(p)]
        leftover = [p for p in allf if p not in ca and p not in ver]
        if leftover:
            # Unlabelled files: peek at the header to classify.
            for p in leftover:
                with open(p, newline="") as f:
                    head = (f.readline() or "")
                (ca if "t_ftpm_ns" in head else ver).append(p)
    else:
        ca = expand([a.ca_glob])
        ver = expand([a.verifier_glob])

    if not ca and not ver:
        sys.exit(f"no CSVs found. Looked for {a.ca_glob} and {a.verifier_glob}")

    levels = pair_files(ca, ver)
    summary = summarise(levels, a.warmup)
    text = format_text(summary, a.warmup)
    print(text)

    if a.out:
        out_path = ensure_dir(a.out)
        with open(out_path, "w") as f:
            f.write(text + "\n")

    if a.plot and any(not math.isnan(s["p50"]) for s in summary):
        make_plot(summary, ensure_dir(a.plot))


if __name__ == "__main__":
    main()