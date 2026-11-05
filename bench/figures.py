"""Paper figures (Figs. 7-11) and the numbers that fill Section 7, from results/final/.

    python3 -m bench.figures results/final   -> results/final/fig*.pdf|png, results/final/numbers.json

Every number printed into the paper is taken from numbers.json, which is computed
here from the raw CSV/JSON files of the runs; nothing is typed by hand.
"""
import csv
import glob
import json
import os
import re
import statistics
import sys

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt   # noqa: E402

plt.rcParams.update({"font.size": 8, "font.family": "serif", "axes.spines.top": False,
                     "axes.spines.right": False, "figure.dpi": 200, "legend.frameon": False,
                     "axes.grid": True, "grid.color": "#e3e8f2", "grid.linewidth": 0.6, "axes.axisbelow": True})
COL = {"PLEDGE": "#0066ff", "Guo et al. 2022": "#ff4f1f", "Romel et al. 2025": "#00b86b",
       "CALYPSO 2021": "#ffaa00"}   # validated categorical slots 1-4 (bench/figures palette)
SHORT = {"PLEDGE": "PLEDGE", "Guo et al. 2022": "Guo et al.", "Romel et al. 2025": "Romel et al.",
         "CALYPSO 2021": "CALYPSO"}


def rows(path):
    with open(path) as f:
        lines = [ln for ln in f if not ln.startswith("#")]
    return list(csv.DictReader(lines))


def pct(xs, p):
    xs = sorted(xs)
    if not xs:
        return float("nan")
    k = (len(xs) - 1) * p / 100
    lo = int(k)
    hi = min(lo + 1, len(xs) - 1)
    return xs[lo] + (xs[hi] - xs[lo]) * (k - lo)


def ledger_point(path):
    r = [x for x in rows(path) if x["ok"] == "true" and x["code"] == "VALID"]
    lat = [float(x["endorse_ms"]) + float(x["submit_ms"]) + float(x["commit_ms"]) for x in r]
    sh = [float(x["shares_ms"]) for x in r]
    return {"ok": len(r), "sent": len(rows(path)), "p50": pct(lat, 50), "p95": pct(lat, 95),
            "endorse_p50": pct([float(x["endorse_ms"]) for x in r], 50),
            "shares_p50": pct(sh, 50), "shares_p95": pct(sh, 95)}


def save(fig, d, name, layout=True):
    if layout:
        fig.tight_layout()
    fig.savefig(f"{d}/{name}.pdf", bbox_inches="tight")
    fig.savefig(f"{d}/{name}.png", bbox_inches="tight")
    plt.close(fig)


FIGS = {"crypto": "fig6_crypto", "ledger": "fig7_ledger", "bundling": "fig8_bundling",
        "lifecycle": "fig9_lifecycle", "e2e": "fig10_e2e"}      # paper figure numbers


def main(d):
    """Builds every figure whose input files exist in d; the others are skipped and listed."""
    N = {}
    skipped = []

    def sec_crypto():
        cr = rows(f"{d}/compare_crypto.csv")
        mi = rows(f"{d}/micro.csv")
        get = lambda s, op, v: next(float(x["median_ms"]) for x in cr
                                    if x["system"] == s and x["operation"] == op and int(x["value"]) == v)
        for s, key in (("PLEDGE", "pledge"), ("Guo et al. 2022", "guo")):
            for v in (5, 50):
                N[f"{key}_enc_{v}"] = get(s, "encrypt_header", v)
                N[f"{key}_dec_{v}"] = get(s, "first_decrypt", v)
        N["romel_enc_50"] = get("Romel et al. 2025", "encrypt_header", 50)
        N["romel_enc_5"] = get("Romel et al. 2025", "encrypt_header", 5)
        N["romel_dec"] = get("Romel et al. 2025", "first_decrypt", 1)
        N["calypso_enc"] = get("CALYPSO 2021", "encrypt_header", 2)
        N["calypso_release"] = get("CALYPSO 2021", "share_release_per_trustee", 2)
        N["calypso_dec"] = get("CALYPSO 2021", "first_decrypt", 2)
        per_grantee = (N["romel_enc_50"] - N["romel_enc_5"]) / 45
        N["romel_crossover"] = N["pledge_enc_5"] / per_grantee
        mget = lambda grp, op, v: next(float(x["mean_ms_or_bytes"]) for x in mi
                                       if x["group"] == grp and x["operation"] == op and int(x["value"]) == v)
        N["share_verify"] = mget("threshold", "share_verify", 2)
        N["share_gen"] = mget("threshold", "share_gen", 2)
        N["combine"] = mget("threshold", "combine_verified", 2)
        N["device_finish"] = mget("abe", "device_finish", 5)
        fig, ax = plt.subplots(1, 2, figsize=(7.0, 2.4))
        for s in ("PLEDGE", "Guo et al. 2022"):
            for i, op in enumerate(("encrypt_header", "first_decrypt")):
                pts = sorted((int(x["value"]), float(x["median_ms"]), float(x["iqr_ms"])) for x in cr
                             if x["system"] == s and x["operation"] == op)
                ax[i].errorbar([p[0] for p in pts], [p[1] for p in pts], yerr=[p[2] / 2 for p in pts], marker="o",
                               ms=4, lw=1.7, capsize=2, color=COL[s], label=SHORT[s])
        pts = sorted((int(x["value"]), float(x["median_ms"])) for x in cr
                     if x["system"] == "Romel et al. 2025" and x["operation"] == "encrypt_header")
        ax[0].plot([p[0] for p in pts], [p[1] for p in pts], marker="s", ms=4, lw=1.7, ls="--",
                   color=COL["Romel et al. 2025"], label="Romel et al. (x = grantees)")
        ax[0].axhline(N["calypso_enc"], color=COL["CALYPSO 2021"], ls=":", lw=1, label="CALYPSO")
        ax[1].axhline(N["romel_dec"], color=COL["Romel et al. 2025"], ls="--", lw=1, label="Romel et al.")
        ax[1].axhline(N["calypso_dec"], color=COL["CALYPSO 2021"], ls=":", lw=1, label="CALYPSO")
        ax[0].set(xlabel="policy attributes", ylabel="ms", title="(a) Encrypt one record")
        ax[1].set(xlabel="policy attributes", ylabel="ms", title="(b) First decryption")
        ax[0].legend(fontsize=6.5)
        ax[1].legend(fontsize=6.5)
        save(fig, d, "fig6_crypto")


    def sec_ledger():
        def load_ledger(dd):
            led, summ = {}, {}
            for path in glob.glob(f"{dd}/ledger_n*_r*_b1.csv") + glob.glob(f"{dd}/guo_n*_r*.csv"):
                m = re.search(r"(ledger|guo)_n(\d+)_r([\d.]+)", os.path.basename(path))
                sysn = "PLEDGE" if m.group(1) == "ledger" else "Guo et al. 2022"
                led[(sysn, int(m.group(2)), float(m.group(3)))] = ledger_point(path)
            for path in glob.glob(f"{dd}/ledger_summary_n*.json"):
                for e in json.load(open(path)):
                    summ[("PLEDGE" if e["system"] == "pledge" else "Guo et al. 2022", int(e["n"]), float(e["rate"]))] = \
                        float(e["throughput"])
            return led, summ
        fine = f"{d}/n4fine" if os.path.isdir(f"{d}/n4fine") else d
        led, summ = load_ledger(fine)
        led_all, summ_all = load_ledger(d)
        fig, ax = plt.subplots(1, 2, figsize=(7.0, 2.4))
        for s, mk in (("PLEDGE", "o"), ("Guo et al. 2022", "s")):
            pts = sorted((r, v) for (sy, nn, r), v in led.items() if sy == s and nn == 4)
            ls = "-" if s == "PLEDGE" else "--"
            ax[0].plot([r for r, _ in pts], [v["p50"] for _, v in pts], marker=mk, ms=4, lw=1.7, color=COL[s], ls=ls,
                       label=f"{SHORT[s]} p50")
            ax[0].plot([r for r, _ in pts], [v["p95"] for _, v in pts], marker=mk, ms=2, lw=0.8, color=COL[s], ls=":",
                       label=f"{SHORT[s]} p95")
            ax[1].plot([r for r, _ in pts], [summ.get((s, 4, r), float("nan")) for r, _ in pts], marker=mk, ms=4,
                       lw=1.7, color=COL[s], ls=ls, label=SHORT[s])
        rmax = max(r for (_, _, r) in led)
        ax[1].plot([0, rmax], [0, rmax], color="#cccccc", lw=0.8, ls=":", label="offered = committed")
        ax[0].set_yscale("log")
        ax[0].set(xlabel="offered rate (entries/s)", ylabel="commit latency (ms, log)", title="(a) Latency, n = 4")
        ax[1].set(xlabel="offered rate (entries/s)", ylabel="committed entries/s", title="(b) Throughput, n = 4")
        ax[0].legend(fontsize=6)
        ax[1].legend(fontsize=6)
        save(fig, d, "fig7_ledger")
        for (s, n, r), v in list(led.items()) + [(k, v) for k, v in led_all.items() if k[1] != 4]:
            key = "pledge" if s == "PLEDGE" else "guo"
            r = int(r)
            N[f"{key}_n{n}_r{r}_p50"], N[f"{key}_n{n}_r{r}_p95"] = v["p50"], v["p95"]
            N[f"{key}_n{n}_r{r}_thr"] = (summ if n == 4 else summ_all).get((s, n, float(r)))
            N[f"{key}_n{n}_r{r}_endorse_p50"] = v["endorse_p50"]
            if s == "PLEDGE":
                N[f"pledge_n{n}_r{r}_shares_p50"] = v["shares_p50"]
                N[f"pledge_n{n}_r{r}_shares_p95"] = v["shares_p95"]
        for n in (4, 7, 10):
            src = summ if n == 4 else summ_all
            N[f"max_thr_pledge_n{n}"] = max((t for (s, nn, _), t in src.items() if s == "PLEDGE" and nn == n), default=None)
            N[f"max_thr_guo_n{n}"] = max((t for (s, nn, _), t in src.items() if s != "PLEDGE" and nn == n), default=None)


    def sec_bundling():
        bd = f"{d}/bundles"
        bun = []
        for path in glob.glob(f"{bd}/ledger_n4_r*_b*.csv"):
            m = re.search(r"_r([\d.]+)_b(\d+)", path)
            v = ledger_point(path)
            v.update({"rate": float(m.group(1)), "bundle": int(m.group(2))})
            bun.append(v)
        bsum = {}
        for path in glob.glob(f"{bd}/ledger_summary_n*.json"):
            for e in json.load(open(path)):
                bsum[int(e["bundle"])] = float(e["throughput"])
        for v in bun:
            v["thr"] = bsum.get(v["bundle"], float("nan"))
        bun.sort(key=lambda v: v["bundle"])
        if bun:
            fig, ax = plt.subplots(1, 2, figsize=(7.0, 2.2))
            b = [v["bundle"] for v in bun]
            ax[0].plot(b, [v["p50"] for v in bun], marker="o", color=COL["PLEDGE"], label="commit p50")
            ax[0].plot(b, [v["shares_p50"] for v in bun], marker="^", color="#a020ff", label="key shares after commit, p50")
            ax[0].set_yscale("log")
            ax[0].set(xlabel="record tags per access entry (m)", ylabel="ms (log)", title="(a) Latency per entry")
            ax[0].legend(fontsize=6.5)
            ax[1].plot(b, [v["thr"] * v["bundle"] for v in bun], marker="o", color=COL["PLEDGE"])
            ax[1].set(xlabel="record tags per access entry (m)", ylabel="records opened per second",
                      title="(b) Records opened per second")
            save(fig, d, "fig8_bundling")
            for v in bun:
                N[f"bundle_{v['bundle']}_p50"] = v["p50"]
                N[f"bundle_{v['bundle']}_shares_p50"] = v["shares_p50"]
                N[f"bundle_{v['bundle']}_records_per_s"] = v["thr"] * v["bundle"]
                N[f"bundle_{v['bundle']}_entries_per_s"] = v["thr"]


    def sec_lifecycle():
        lc = rows(f"{d}/compare_lifecycle.csv")
        fig, ax = plt.subplots(1, 3, figsize=(7.0, 2.5))
        for i, op in enumerate(("revoke", "onboard_clinician", "narrow_consent")):
            for s in COL:
                pts = sorted((int(x["records_per_patient"]), float(x["seconds"]) * 1000) for x in lc
                             if x["system"] == s and x["operation"] == op and x["eligible_clinicians"] == "20"
                             and x["patients"] == "1")
                if pts:
                    big = max((x for x in lc if x["system"] == s and x["operation"] == op and x["eligible_clinicians"] == "20"
                               and x["patients"] == "1"), key=lambda x: int(x["records_per_patient"]))
                    lab = SHORT[s]
                    N[f"lc_{s}_{op}_{int(big['records_per_patient'])}"] = {"tx": int(big["ledger_txs"]),
                                                                        "ops": int(big["crypto_ops"])}
                    ax[i].plot([p[0] for p in pts], [max(p[1], 1e-3) for p in pts], marker="o", ms=4, lw=1.7,
                               color=COL[s], label=lab, ls="-" if s == "PLEDGE" else "--")
            ax[i].set_yscale("log")
            ax[i].set(xlabel="records affected", ylabel="ms (log)",
                      title={"revoke": "(a) Revoke a clinician", "onboard_clinician": "(b) Onboard a clinician",
                             "narrow_consent": "(c) Narrow a consent"}[op])
        h, l = ax[0].get_legend_handles_labels()
        fig.tight_layout(rect=(0, 0, 1, 0.86))
        fig.legend(h, l, loc="upper center", ncol=4, fontsize=7)
        save(fig, d, "fig9_lifecycle", layout=False)
        pick = lambda s, op, R, G, P: next(x for x in lc if x["system"] == s and x["operation"] == op and
                                           int(x["records_per_patient"]) == R and int(x["eligible_clinicians"]) == G
                                           and int(x["patients"]) == P)
        for s, key in (("PLEDGE", "pledge"), ("Guo et al. 2022", "guo"), ("Romel et al. 2025", "romel"),
                       ("CALYPSO 2021", "calypso")):
            for op in ("share", "revoke", "onboard_clinician", "narrow_consent"):
                try:
                    x = pick(s, op, 100, 20, 5)
                except StopIteration:
                    continue
                N[f"{key}_{op}_500"] = {"s": float(x["seconds"]), "tx": int(x["ledger_txs"]), "ops": int(x["crypto_ops"])}
            revs = [float(x["seconds"]) * 1000 for x in lc if x["system"] == s and x["operation"] == "revoke"]
            N[f"{key}_revoke_ms_range"] = [min(revs), max(revs)]


    def sec_fhir(path, prefix):
        fw = rows(path)
        tot = lambda k: sum(float(x[k]) for x in fw)
        N[prefix + "_patients"] = len(fw)
        N[prefix + "_resources"] = int(tot("resources"))
        N[prefix + "_restricted"] = int(tot("restricted"))
        N[prefix + "_enc_ms"] = statistics.median(float(x["encrypt_ms_median"]) for x in fw)
        N[prefix + "_put_ms"] = statistics.median(float(x["fhir_put_ms_mean"]) for x in fw)
        N[prefix + "_get_ms"] = statistics.median(float(x["fhir_get_ms_mean"]) for x in fw)
        N[prefix + "_expansion"] = tot("stored_bytes") / tot("plaintext_bytes")
        N[prefix + "_binary_expansion"] = tot("binary_bytes") / tot("plaintext_bytes")
        N[prefix + "_mean_plain"] = tot("plaintext_bytes") / tot("resources")
        N[prefix + "_mean_binary"] = tot("binary_bytes") / tot("resources")

    def sec_e2e():
        e2e = json.load(open(f"{d}/e2e_fabric.json"))
        stages = ["fetch", "side", "build", "endorse", "order", "shares", "verify", "decrypt"]
        med = e2e["single_median"]
        N["e2e"] = med
        N["e2e_p95_total"] = pct([r["total"] for r in e2e["single"]], 95)
        ch = {}
        for r in e2e["charts"]:
            ch.setdefault(r["records"], []).append(r)
        N["chart"] = {m: {s: statistics.median(r.get(s, 0) for r in rs) for s in stages + ["total"]}
                      for m, rs in sorted(ch.items())}
        fig, ax = plt.subplots(1, 2, figsize=(7.0, 2.9), gridspec_kw={"width_ratios": [1.3, 1]})
        names = {"fetch": "FHIR fetch", "side": "side record", "build": "build + sign", "endorse": "endorse",
                 "order": "order + commit", "shares": "key shares", "verify": "verify + combine", "decrypt": "decrypt"}
        left = 0
        # FHIR store (aqua), client work (warm greys), ledger (blues): the ledger share reads at a glance
        greys = ["#00c389", "#7fe8c4", "#ffc21a", "#ff5a1f", "#0066ff", "#5aa9ff", "#b04dff", "#ff4f9a"]
        for s, c in zip(stages, greys):
            ax[0].barh([0], [med[s]], left=left, color=c, edgecolor="white", label=f"{names[s]} {med[s]:.0f}")
            left += med[s]
        ax[0].set(yticks=[], xlabel="ms (median of first accesses)", title="(a) First access to one record")
        ax[0].legend(fontsize=6, ncol=2, loc="upper center", bbox_to_anchor=(0.5, -0.45))
        ms = sorted(N["chart"])
        for s, c in zip(stages, greys):
            pass
        ax[1].plot(ms, [N["chart"][m]["total"] / 1000 for m in ms], marker="o", color=COL["PLEDGE"], label="total")
        ax[1].plot(ms, [(N["chart"][m]["endorse"] + N["chart"][m]["order"]) / 1000 for m in ms], marker="s",
                   color="#ff4f1f", ls="--", label="ledger (one entry)")
        ax[1].set(xlabel="records in the chart (one bundled entry)", ylabel="s", title="(b) Opening a chart")
        ax[1].legend(fontsize=6.5)
        save(fig, d, "fig10_e2e")

    steps = [("crypto", sec_crypto, ("compare_crypto.csv", "micro.csv")),
             ("ledger", sec_ledger, ("n4fine",)),
             ("bundling", sec_bundling, ("bundles",)),
             ("lifecycle", sec_lifecycle, ("compare_lifecycle.csv",)),
             ("fhir (Synthea)", lambda: sec_fhir(f"{d}/fhir_workload.csv", "fhir"), ("fhir_workload.csv",)),
             ("fhir (MIMIC-IV)", lambda: sec_fhir(f"{d}/fhir_workload_mimic.csv", "mimic"),
              ("fhir_workload_mimic.csv",)),
             ("e2e", sec_e2e, ("e2e_fabric.json",))]
    for name, fn, needs in steps:
        missing = [x for x in needs if not os.path.exists(f"{d}/{x}")]
        if missing:
            skipped.append(f"{name} (missing {', '.join(missing)})")
            continue
        try:
            fn()
        except Exception as e:                        # incomplete run: report it, keep the other figures
            skipped.append(f"{name} ({type(e).__name__}: {e})")
    json.dump(N, open(f"{d}/numbers.json", "w"), indent=1, default=float)
    for s in skipped:
        print("skipped:", s)
    print(f"{len(N)} numbers -> {d}/numbers.json")
    return N, skipped


if __name__ == "__main__":
    main(sys.argv[1] if len(sys.argv) > 1 else "results/final")
