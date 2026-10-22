#!/usr/bin/env python3
"""
dos-analyzer.py - availability analysis of the RA under TPM load.

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
    denied     requests not answered (verifier timeout, or over the SLA)
    success%   fraction of attests that completed (within the SLA, if set)
    U          CPU utilisation busy/total over that level   (1.0 = cores pegged)
    thr        completed attestations per second            (throughput)
    p50/p95/p99/max   latency over completed requests (ms)

Two knobs for the availability story:
    --sla MS     treat completed attests slower than MS as denied. This applies
                 a tighter service-level objective *after the fact*, so you can
                 find the load where success drops below 100% without re-running
                 the sweep. The latency percentiles still show the TRUE latency;
                 only success%/denied reflect the SLA.
    --warmup N   drop the first N attests of each level (worker spin-up ramp).

The --device label flows through to the titles and the default output names.

Usage:
    python3 dos-analyzer.py                       # auto-discover under results dir
    python3 dos-analyzer.py --device tpm-file     # label the outputs
    python3 dos-analyzer.py --sla 1000 --warmup 1 # 1 s SLA, drop first attest
    python3 dos-analyzer.py ca_load*.csv verifier_load*.csv   # explicit

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

# Used when no device is specified. (title, plot, and output file names are device-specific.)
DEVICE = "ftpm"

# Per-module display name + latency-metric label. Unknown labels fall back to
# the label itself (see meta()), so new modules work without editing this.
DEVICE_META = {
    "ftpm":     ("fTPM",             "fTPM latency"),
    "tpm":      ("TPM (IMA)",        "TPM latency"),
    "tpm-file": ("TPM (file/PCR16)", "TPM latency"),
    "idle":     ("idle baseline",    "window"),
}


def meta(device):
    """(display name, latency-metric label) for a module/device label."""
    return DEVICE_META.get(device, (device, f"{device} latency"))


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
    """ca_load<N>.csv -> ({seq: latency_ms}, busy_ticks, total_ticks).

    Latency is t_ftpm_ns / 1e6. busy/total come from the same rows and let us
    compute U (CPU utilisation) for the level.
    """
    out = {}
    busy = total = 0
    with open(path, newline="") as f:
        rd = csv.DictReader(f)
        if rd.fieldnames and not {"seq", "t_ftpm_ns"}.issubset(rd.fieldnames):
            sys.exit(f"{path}: expected seq,t_ftpm_ns,...  got {rd.fieldnames}")
        has_u = bool(rd.fieldnames) and {"busy_ticks", "total_ticks"}.issubset(rd.fieldnames)
        for r in rd:
            out[int(r["seq"])] = int(r["t_ftpm_ns"]) / 1e6
            if has_u:
                busy += int(r["busy_ticks"])
                total += int(r["total_ticks"])
    return out, busy, total


def read_verifier(path):
    """verifier_load<N>.csv -> list of (seq, result, unix_time|None)."""
    out = []
    with open(path, newline="") as f:
        rd = csv.DictReader(f)
        if rd.fieldnames and not {"seq", "result"}.issubset(rd.fieldnames):
            sys.exit(f"{path}: expected seq,...,result  got {rd.fieldnames}")
        has_t = bool(rd.fieldnames) and "unix_time" in rd.fieldnames
        for r in rd:
            t = None
            if has_t:
                try:
                    t = float(r["unix_time"])
                except (TypeError, ValueError):
                    t = None
            out.append((int(r["seq"]), (r["result"] or "").strip(), t))
    return out


def pair_files(ca_paths, verifier_paths):
    """Group CA and verifier files by load level N."""
    levels = {}
    for p in ca_paths:
        levels.setdefault(level_of(p), {}).setdefault("ca", []).append(p)
    for p in verifier_paths:
        levels.setdefault(level_of(p), {}).setdefault("ver", []).append(p)
    return levels


def merge_level(ca_paths, ver_paths, warmup, sla):
    """
    Merge one level's CA + verifier files into availability stats.

    Enroll is separate, so CA and verifier share seq numbering. Match by seq:
    the verifier row is the authority on answered vs denied; its latency (when
    completed) is the CA's t_ftpm_ns at the SAME seq.

    sla (ms, or None): completed attests slower than this count as denied for
    success%/throughput, but still appear in the true latency percentiles.
    """
    ca = {}
    busy = total_ticks = 0
    for p in ca_paths:
        m, b, t = read_ca(p)
        ca.update(m)
        busy += b
        total_ticks += t

    ver = []
    for p in ver_paths:
        ver += read_verifier(p)

    # In seq order so warmup drops the *first* attests consistently.
    ver_attests = sorted(ver, key=lambda r: r[0])
    if warmup > 0:
        ver_attests = ver_attests[warmup:]

    completed_lat = []          # TRUE latency of every CA-logged completion
    times = []                  # verifier unix_time, for throughput
    n_within = 0                # completions within the SLA (== n if no SLA)

    if ver_attests:
        for seq, res, t in ver_attests:
            if t is not None:
                times.append(t)
            if res in DENIED_TAGS:
                continue                         # verifier timeout -> denied
            if seq in ca:
                lat = ca[seq]
                completed_lat.append(lat)
                if sla is None or lat <= sla:
                    n_within += 1
            # else: verifier answered but CA has no row -> denied
        total_attests = len(ver_attests)
        denied_known = True
    else:
        # CA-only (no verifier file): latency only, availability unknown.
        ca_seqs = sorted(ca)
        if warmup > 0:
            ca_seqs = ca_seqs[warmup:]
        completed_lat = [ca[s] for s in ca_seqs]
        n_within = sum(1 for l in completed_lat if sla is None or l <= sla)
        total_attests = None
        denied_known = False

    lat = sorted(completed_lat)
    n = len(lat)
    u = busy / total_ticks if total_ticks else float("nan")

    # Throughput: completed attests per wall-clock second over the level.
    span = (max(times) - min(times)) if len(times) >= 2 else 0.0
    if span > 0:
        thr = n / span
    elif lat:
        thr = 1000.0 / (sum(lat) / len(lat))     # fallback: back-to-back rate
    else:
        thr = float("nan")

    if not denied_known:
        succ = float("nan")
        denied = 0
    else:
        succ_count = n_within if sla is not None else n
        succ = 100 * succ_count / total_attests if total_attests else float("nan")
        denied = total_attests - succ_count

    return dict(n=n, denied=denied, denied_known=denied_known, succ=succ,
                u=u, thr=thr,
                p50=pct(lat, 50), p95=pct(lat, 95), p99=pct(lat, 99),
                mx=(lat[-1] if lat else float("nan")),
                have_ca=bool(ca), have_ver=bool(ver))


def summarise(levels, warmup, sla):
    out = []
    for key in sorted(levels, key=numkey):
        files = levels[key]
        s = merge_level(files.get("ca", []), files.get("ver", []), warmup, sla)
        s["level"] = key
        out.append(s)
    return out


def format_text(rows, warmup, device, sla):
    disp, _ = meta(device)
    sla_txt = f"{sla:.0f} ms" if sla is not None else "none (verifier timeout only)"
    lines = [f"device: {device} ({disp})",
             f"load levels: {len(rows)}  (warm-up {warmup} attests/side, "
             f"SLA {sla_txt})", ""]
    for s in rows:
        succ = f"{s['succ']:5.1f}%" if not math.isnan(s["succ"]) else "   -  "
        denied = f"{s['denied']:<4}" if s["denied_known"] else " ?  "
        u = f"{s['u']:.3f}" if not math.isnan(s["u"]) else "  -  "
        thr = f"{s['thr']:6.2f}" if not math.isnan(s["thr"]) else "   -  "
        src = "".join(("C" if s["have_ca"] else "-",
                       "V" if s["have_ver"] else "-"))
        lines.append(
            f"load={s['level']:<5} [{src}] n={s['n']:<4} denied={denied} "
            f"success={succ}  U={u}  thr={thr}/s  "
            f"p50={s['p50']:7.1f} p95={s['p95']:7.1f}"
            f"max={s['mx']:7.1f} ms")
    lines += ["", "[CV] = CA latency file + verifier verdict file present. "
              "U = busy/total ticks (1.0 = all cores pegged). "
              "thr = completed attests/sec."]
    if sla is not None:
        lines.append(f"success = completed within SLA ({sla:.0f} ms); slower "
                     f"completions are counted as denied (latency cols are still true).")
    return "\n".join(lines)


def ensure_dir(path):
    path = os.path.expanduser(path)
    d = os.path.dirname(path)
    if d:
        os.makedirs(d, exist_ok=True)
    return path


def make_plot(rows, path, device, sla):
    try:
        import matplotlib
        matplotlib.use("Agg")
        import matplotlib.pyplot as plt
    except ImportError:
        print("\n(matplotlib not installed - skipping the plot; "
              "run 'pip install --break-system-packages matplotlib')",
              file=sys.stderr)
        return

    disp, lat_label = meta(device)

    xs, labels = [], []
    for i, s in enumerate(rows):
        m = re.findall(r"\d+", str(s["level"]))
        xs.append(int(m[0]) if m else i)
        labels.append(str(s["level"]))

    # Decide which panels have data.
    panels = ["lat"]
    if any(s["denied_known"] for s in rows):
        panels.append("succ")
    if any(not math.isnan(s["u"]) for s in rows):
        panels.append("u")
    if any(not math.isnan(s["thr"]) for s in rows):
        panels.append("thr")

    n = len(panels)
    fig, axs = plt.subplots(n, 1, figsize=(8, 3.2 * n), sharex=True)
    axs = [axs] if n == 1 else list(axs)
    ax = dict(zip(panels, axs))

    # ---- latency -----------------------------------------------------------
    a = ax["lat"]
    a.plot(xs, [s["p50"] for s in rows], "o-", label="p50")
    a.plot(xs, [s["p95"] for s in rows], "s-", label="p95")
    # a.plot(xs, [s["p99"] for s in rows], "^-", label="p99")
    a.set_ylabel(f"{lat_label} (ms)")
    a.set_title(f"CA-side {disp} latency (completed requests) vs load")
    if sla is not None:
        a.axhline(sla, ls="--", color="k", alpha=0.6, label=f"SLA {sla:.0f} ms")
    a.legend()
    a.grid(True, alpha=0.3)
    denied_xs = [x for x, s in zip(xs, rows) if math.isnan(s["p50"])]
    for x in denied_xs:
        a.axvspan(x - 0.4, x + 0.4, color="tab:red", alpha=0.08)
    if denied_xs:
        a.text(0.99, 0.02, "shaded = no completed requests (fully denied)",
               transform=a.transAxes, ha="right", va="bottom",
               fontsize=8, color="tab:red")

    # ---- success rate ------------------------------------------------------
    if "succ" in ax:
        a = ax["succ"]
        a.plot(xs, [s["succ"] for s in rows], "o-", color="tab:red")
        a.set_ylabel("success rate (%)")
        a.set_ylim(-5, 105)
        ttl = "Attestation success rate vs load"
        if sla is not None:
            ttl += f"  (SLA {sla:.0f} ms)"
        a.set_title(f"{ttl} - {disp}")
        a.grid(True, alpha=0.3)

    # ---- U (CPU utilisation) ----------------------------------------------
    if "u" in ax:
        a = ax["u"]
        a.plot(xs, [s["u"] for s in rows], "o-", color="tab:green")
        a.axhline(1.0, ls="--", color="k", alpha=0.6, label="all cores pegged")
        a.set_ylabel("U (busy / total)")
        a.set_ylim(0, 1.05)
        a.set_title(f"CPU utilisation vs load - {disp}")
        a.legend()
        a.grid(True, alpha=0.3)

    # ---- throughput --------------------------------------------------------
    if "thr" in ax:
        a = ax["thr"]
        a.plot(xs, [s["thr"] for s in rows], "o-", color="tab:purple")
        a.set_ylabel("completed attests / s")
        a.set_title(f"Throughput vs load - {disp}")
        a.grid(True, alpha=0.3)

    # x axis only on the bottom panel
    axs[-1].set_xlabel("contending TPM workers on the attester device")
    axs[-1].set_xticks(xs)
    axs[-1].set_xticklabels(labels, rotation=0, ha="center")

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
    ap.add_argument("--device", default=DEVICE,
                    help=f"module/device label (default {DEVICE}); names titles + outputs")
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
    ap.add_argument("--sla", type=float, default=None, metavar="MS",
                    help="post-hoc SLA: completed attests slower than MS count "
                         "as denied (find the degradation knee without re-running)")
    ap.add_argument("--out", default=None,
                    help="also write the text summary here "
                         "(default OUT_DIR/<device>-dos-summary.txt)")
    ap.add_argument("--plot", default=None,
                    help="write the plot here ('' to skip; "
                         "default OUT_DIR/<device>-dos-summary.png)")
    a = ap.parse_args()

    # Fill the device-specific default output names now that --device is known.
    if a.out is None:
        a.out = OUT_DIR + f"/{a.device}-dos-summary.txt"
    if a.plot is None:
        a.plot = OUT_DIR + f"/{a.device}-dos-summary.png"

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
    summary = summarise(levels, a.warmup, a.sla)
    text = format_text(summary, a.warmup, a.device, a.sla)
    print(text)

    if a.out:
        out_path = ensure_dir(a.out)
        with open(out_path, "w") as f:
            f.write(text + "\n")

    if a.plot and summary:
        make_plot(summary, ensure_dir(a.plot), a.device, a.sla)


if __name__ == "__main__":
    main()