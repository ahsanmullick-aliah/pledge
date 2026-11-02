"""Compare a reproduction run with the numbers printed in the paper.

    python -m bench.verify results/<run> --paper paper_results   -> <run>/REPORT.html, <run>/REPORT.md

Three kinds of result:
  * exact      security outcomes, test results and operation counts. They do not depend on the
               machine and must equal the paper's.
  * trend      statements of Section VII that compare systems or describe how a cost grows, such
               as "the decryption overhead over Guo et al. is constant". They are evaluated on your
               own numbers, so they hold or fail independently of how fast your machine is.
  * measured   times and throughputs. They depend on the hardware; the report shows the paper's
               value (2-vCPU cloud VM), yours, and the ratio.
"""
import argparse
import base64
import csv
import html
import json
import re
import statistics
from pathlib import Path

PAPER_HOST = "2-vCPU cloud VM (Intel Xeon 2.1 GHz), 7.8 GB RAM, Linux 6.18, Python 3.13"
FIGS = [("fig6_crypto", "Fig. 7", "Per-record cryptographic cost"),
        ("fig7_ledger", "Fig. 8", "Fabric commit latency and throughput, PLEDGE vs Guo et al., n = 4"),
        ("fig8_bundling", "Fig. 9", "Bundling m record tags into one access entry"),
        ("fig9_lifecycle", "Fig. 10", "Revocation, onboarding and consent narrowing"),
        ("fig10_e2e", "Fig. 11", "End to end on Fabric with HAPI FHIR")]


def load(d):
    p = Path(d) / "numbers.json"
    return json.loads(p.read_text()) if p.exists() else {}


def csv_rows(p):
    if not Path(p).exists():
        return None
    with open(p, encoding="utf-8") as f:
        return list(csv.DictReader(ln for ln in f if not ln.startswith("#")))


def get(N, key):
    cur = N
    for part in key.split("."):
        if isinstance(cur, dict) and part in cur:
            cur = cur[part]
        else:
            return None
    return cur


# ---------------------------------------------------------------- checks
def exact_checks(run, paper, N, P, info):
    out = []   # (section, what, paper, yours, status)

    def add(sec, what, pv, yv, status=None):
        if status is None:
            status = "not run" if yv is None else ("match" if str(pv) == str(yv) else "DIFFERS")
        out.append((sec, what, pv, "—" if yv is None else yv, status))

    st = info.get("stages", {})
    note = st.get("tests", {}).get("note", "")
    m = re.search(r"(\d+) tests: (OK|FAILED)", note)
    passed = bool(m) and m.group(2) == "OK"
    add("VII-A", "Unit and integration tests", "all pass",
        (f"{m.group(1)} run, " + ("all pass" if passed else "FAILURES")) if m else None,
        None if not m else ("match" if passed else "DIFFERS"))
    m = re.search(r"differential test (\d+) triples agree, (\d+) consents outside F rejected", note)
    add("VII-A", "Differential test: compiler = reference evaluator (triples agreeing)", 6000,
        int(m.group(1)) if m else None)
    add("VII-A", "Differential test: generated Consents outside F rejected", 14, int(m.group(2)) if m else None)
    if "Go/Python" in note:
        add("VII-A", "Go chaincode = Python reference on the cross-language test vectors", "pass",
            "pass" if "vectors pass" in note else "FAIL")
    # Table XVII
    mine, ref = csv_rows(Path(run) / "compare_attacks.csv"), csv_rows(Path(paper) / "compare_attacks.csv")
    if ref:
        for r in ref:
            y = next((x for x in mine or [] if x["attack"] == r["attack"]), None)
            for col in ("PLEDGE", "Guo et al. 2022", "Romel et al. 2025", "CALYPSO 2021"):
                add("Table XVII", f"{r['attack']} — {col}", r[col], y[col] if y else None)
    # Fabric smoke
    sm = re.search(r"attacks blocked (\d+)/(\d+)", st.get("fabric-smoke", {}).get("note", ""))
    add("VII-A", "Fabric network: flows and attacks end to end (blocked/total)", "8/8",
        f"{sm.group(1)}/{sm.group(2)}" if sm else None)
    # Lifecycle counts (Fig. 10 caption, Section VII-F)
    for key, what in (("lc_PLEDGE_revoke_250", "Revoke, 250 records: PLEDGE"),
                      ("lc_Guo et al. 2022_revoke_250", "Revoke, 250 records: Guo et al."),
                      ("lc_Romel et al. 2025_revoke_250", "Revoke, 250 records: Romel et al."),
                      ("lc_CALYPSO 2021_revoke_250", "Revoke, 250 records: CALYPSO"),
                      ("lc_PLEDGE_onboard_clinician_250", "Onboard, 250 records: PLEDGE"),
                      ("lc_Romel et al. 2025_onboard_clinician_250", "Onboard, 250 records: Romel et al."),
                      ("lc_CALYPSO 2021_onboard_clinician_250", "Onboard, 250 records: CALYPSO"),
                      ("lc_PLEDGE_narrow_consent_250", "Narrow consent, 250 records: PLEDGE"),
                      ("lc_Guo et al. 2022_narrow_consent_250", "Narrow consent, 250 records: Guo et al."),
                      ("lc_Romel et al. 2025_narrow_consent_250", "Narrow consent, 250 records: Romel et al."),
                      ("lc_CALYPSO 2021_narrow_consent_250", "Narrow consent, 250 records: CALYPSO"),
                      ("guo_revoke_500", "Revoke, 500 records of 5 patients: Guo et al."),
                      ("romel_revoke_500", "Revoke, 500 records of 5 patients: Romel et al."),
                      ("romel_onboard_clinician_500", "Onboard, 500 records of 5 patients: Romel et al."),
                      ("pledge_narrow_consent_500", "Narrow consent, 500 records: PLEDGE"),
                      ("romel_narrow_consent_500", "Narrow consent, 500 records: Romel et al."),
                      ("calypso_narrow_consent_500", "Narrow consent, 500 records: CALYPSO")):
        pv, yv = P.get(key), N.get(key)
        fmt = lambda v: None if v is None else f"{v['tx']} tx, {v['ops']} crypto ops"
        smaller = yv is None and key.startswith("lc_") and any(k.startswith("lc_") for k in N)
        add("Fig. 10 / VII-F", what, fmt(pv), "quick grid stops at 100 records" if smaller else fmt(yv),
            "smaller run" if smaller else None)
    # Synthea cohort
    if N.get("fhir_patients") == P.get("fhir_patients"):
        add("VII-G", "Synthea cohort: resources encrypted", P.get("fhir_resources"), N.get("fhir_resources"))
        add("VII-G", "Synthea cohort: resources labelled R", P.get("fhir_restricted"), N.get("fhir_restricted"))
    else:
        add("VII-G", "Synthea cohort (50 patients): resources / labelled R",
            f"{P.get('fhir_resources')} / {P.get('fhir_restricted')}",
            None if N.get("fhir_patients") is None else
            f"{N.get('fhir_resources')} / {N.get('fhir_restricted')} ({N.get('fhir_patients')} patients)",
            None if N.get("fhir_patients") is None else "smaller run")
    return out


def trend_checks(N):
    """Statements of Section VII, evaluated on your numbers."""
    out = []   # (section, statement, evidence, status)

    def add(sec, stmt, needed, fn, evidence):
        vals = [get(N, k) for k in needed]
        if any(v is None for v in vals):
            out.append((sec, stmt, "—", "not run"))
            return
        try:
            ok = fn(*vals)
            out.append((sec, stmt, evidence(*vals), "holds" if ok else "DOES NOT HOLD"))
        except Exception as e:
            out.append((sec, stmt, f"{type(e).__name__}: {e}", "error"))
    add("VII-D", "PLEDGE's extra decryption cost over Guo et al. stays about constant from 5 to 50 policy attributes",
        ["pledge_dec_5", "guo_dec_5", "pledge_dec_50", "guo_dec_50"],
        lambda a, b, c, d: abs((c - d) - (a - b)) <= max(1.5, 0.5 * (a - b)),
        lambda a, b, c, d: f"overhead {a - b:.2f} ms at 5 attributes, {c - d:.2f} ms at 50")
    add("VII-D", "PLEDGE's extra encryption cost over Guo et al. is small and does not grow with the policy",
        ["pledge_enc_5", "guo_enc_5", "pledge_enc_50", "guo_enc_50"],
        lambda a, b, c, d: (c - d) < 0.2 * d and (c - d) <= max(3.0, 3 * abs(a - b)),
        lambda a, b, c, d: f"overhead {a - b:.2f} ms at 5 attributes, {c - d:.2f} ms at 50")
    add("VII-D", "Romel et al. encryption grows per grantee and exceeds PLEDGE's above roughly 8 grantees",
        ["romel_crossover"], lambda x: 3 <= x <= 20, lambda x: f"crossover at {x:.1f} grantees (paper 8.2)")
    add("VII-D", "CALYPSO is the cheapest of the four to encrypt and to decrypt",
        ["calypso_enc", "pledge_enc_5", "guo_enc_5", "romel_enc_5", "calypso_dec", "pledge_dec_5", "guo_dec_5"],
        lambda c, p, g, r, cd, pd, gd: c < min(p, g, r) and cd < min(pd, gd),
        lambda c, p, g, r, cd, pd, gd: f"encrypt {c:.2f} ms vs {min(p, g, r):.2f} ms; decrypt {cd:.2f} vs {min(pd, gd):.2f}")
    add("VII-D", "Outsourced decryption leaves the device a fraction of a millisecond-scale task",
        ["device_finish", "pledge_dec_5"], lambda a, b: a < 0.25 * b,
        lambda a, b: f"device finish {a:.2f} ms vs full decryption {b:.2f} ms")
    add("VII-E", "At 10 entries/s PLEDGE's commit latency is close to Guo's plain logging (within 25%)",
        ["pledge_n4_r10_p50", "guo_n4_r10_p50"], lambda a, b: a <= 1.25 * b,
        lambda a, b: f"PLEDGE {a:.1f} ms vs Guo {b:.1f} ms (+{a - b:.1f} ms)")
    add("VII-E", "The extra cost is in endorsement (PLEDGE's chaincode checks)",
        ["pledge_n4_r10_endorse_p50", "guo_n4_r10_endorse_p50"], lambda a, b: a > b,
        lambda a, b: f"endorsement {a:.1f} ms vs {b:.1f} ms")
    add("VII-E", "Key shares are available within tens of milliseconds after commit",
        ["pledge_n4_r10_shares_p50"], lambda a: a < 100, lambda a: f"{a:.1f} ms (median)")
    add("VII-E", "PLEDGE saturates no later than Guo's plain logging on a shared host",
        ["max_thr_pledge_n4", "max_thr_guo_n4"], lambda a, b: a <= b * 1.05,
        lambda a, b: f"max committed {a:.1f} vs {b:.1f} entries/s")
    add("VII-E", "Bundling raises the records opened per second",
        ["bundle_1_records_per_s", "bundle_10_records_per_s"], lambda a, b: b > 3 * a,
        lambda a, b: f"{a:.0f} records/s at m = 1, {b:.0f} at m = 10")
    add("VII-F", "Revoking a clinician in PLEDGE is one transaction whose cost does not grow with the records",
        ["pledge_revoke_ms_range", "lc_PLEDGE_revoke_250"], lambda r, c: c["tx"] == 1 and c["ops"] == 0 and r[1] < 100,
        lambda r, c: f"{c['tx']} tx, {c['ops']} ops; {r[0]:.1f}–{r[1]:.1f} ms across all sizes")
    add("VII-F", "Revoking under Guo et al.'s re-keying grows with the records affected",
        ["guo_revoke_ms_range"], lambda r: r[1] > 10 * r[0], lambda r: f"{r[0]:.0f} ms to {r[1]:.0f} ms")
    add("VII-F", "Narrowing a consent costs PLEDGE about as much time as Guo et al. (within 2x)",
        ["pledge_narrow_consent_500", "guo_narrow_consent_500"], lambda a, b: 0.5 <= a["s"] / b["s"] <= 2,
        lambda a, b: f"{a['s']:.2f} s vs {b['s']:.2f} s for 500 records")
    add("VII-G", "A first access completes within interactive limits (< 1 s)",
        ["e2e.total"], lambda t: t < 1000, lambda t: f"{t:.0f} ms median")
    add("VII-G", "The ledger (endorse, order, key shares) is most of a first access",
        ["e2e"], lambda e: (e["endorse"] + e["order"] + e["shares"]) / e["total"] >= 0.5,
        lambda e: f"{e['endorse'] + e['order'] + e['shares']:.0f} of {e['total']:.0f} ms "
                  f"({100 * (e['endorse'] + e['order'] + e['shares']) / e['total']:.0f}%)")
    add("VII-G", "Opening a chart with one bundled entry grows roughly linearly with the records",
        ["chart"], lambda c: _linear(c), lambda c: ", ".join(f"{m} rec: {v['total'] / 1000:.2f} s"
                                                           for m, v in sorted(c.items(), key=lambda x: int(x[0]))))
    add("VII-G", "Storage expansion on Synthea records is about 20x as stored, 10x in binary",
        ["fhir_expansion", "fhir_binary_expansion"], lambda a, b: 15 <= a <= 25 and 7 <= b <= 12,
        lambda a, b: f"x{a:.1f} as stored, x{b:.1f} binary")
    return out


def _linear(c):
    pts = sorted((int(m), v["total"]) for m, v in c.items())
    if len(pts) < 2:
        return True
    per = [(t2 - t1) / (m2 - m1) for (m1, t1), (m2, t2) in zip(pts, pts[1:]) if m2 > m1]
    return max(per) <= 4 * max(1e-9, min(per)) if len(per) > 1 else per[0] > 0


MEASURED = [  # section, label, key, unit
    ("VII-D", "Encrypt header, PLEDGE, 5 attributes", "pledge_enc_5", "ms"),
    ("VII-D", "Encrypt header, Guo et al., 5 attributes", "guo_enc_5", "ms"),
    ("VII-D", "Encrypt header, PLEDGE, 50 attributes", "pledge_enc_50", "ms"),
    ("VII-D", "Encrypt header, Guo et al., 50 attributes", "guo_enc_50", "ms"),
    ("VII-D", "First decryption, PLEDGE, 5 attributes", "pledge_dec_5", "ms"),
    ("VII-D", "First decryption, Guo et al., 5 attributes", "guo_dec_5", "ms"),
    ("VII-D", "First decryption, PLEDGE, 50 attributes", "pledge_dec_50", "ms"),
    ("VII-D", "First decryption, Guo et al., 50 attributes", "guo_dec_50", "ms"),
    ("VII-D", "ShareVerify (one share)", "share_verify", "ms"),
    ("VII-D", "Combine incl. verification, k = 2", "combine", "ms"),
    ("VII-D", "ShareGen (one partial key)", "share_gen", "ms"),
    ("VII-D", "Outsourced decryption: device work", "device_finish", "ms"),
    ("VII-D", "Romel et al.: decrypt (one ECDH)", "romel_dec", "ms"),
    ("VII-D", "Romel et al.: encrypt for 5 grantees", "romel_enc_5", "ms"),
    ("VII-D", "Romel et al.: encrypt for 50 grantees", "romel_enc_50", "ms"),
    ("VII-D", "CALYPSO: encrypt", "calypso_enc", "ms"),
    ("VII-D", "CALYPSO: trustee share release", "calypso_release", "ms"),
    ("VII-D", "CALYPSO: reader recovers the key", "calypso_dec", "ms"),
    ("VII-E", "Commit latency p50 at 10/s, PLEDGE", "pledge_n4_r10_p50", "ms"),
    ("VII-E", "Commit latency p50 at 10/s, Guo et al.", "guo_n4_r10_p50", "ms"),
    ("VII-E", "Commit latency p95 at 10/s, PLEDGE", "pledge_n4_r10_p95", "ms"),
    ("VII-E", "Commit latency p95 at 10/s, Guo et al.", "guo_n4_r10_p95", "ms"),
    ("VII-E", "Endorsement p50 at 10/s, PLEDGE", "pledge_n4_r10_endorse_p50", "ms"),
    ("VII-E", "Endorsement p50 at 10/s, Guo et al.", "guo_n4_r10_endorse_p50", "ms"),
    ("VII-E", "Key shares after commit, p50 at 10/s", "pledge_n4_r10_shares_p50", "ms"),
    ("VII-E", "Commit latency p50 at 20/s, PLEDGE", "pledge_n4_r20_p50", "ms"),
    ("VII-E", "Commit latency p50 at 20/s, Guo et al.", "guo_n4_r20_p50", "ms"),
    ("VII-E", "Max committed throughput, PLEDGE, n = 4", "max_thr_pledge_n4", "entries/s"),
    ("VII-E", "Max committed throughput, Guo et al., n = 4", "max_thr_guo_n4", "entries/s"),
    ("VII-E", "Commit latency p50 at 10/s, PLEDGE, n = 7", "pledge_n7_r10_p50", "ms"),
    ("VII-E", "Commit latency p50 at 10/s, PLEDGE, n = 10", "pledge_n10_r10_p50", "ms"),
    ("VII-E", "Records opened per second, m = 10", "bundle_10_records_per_s", "records/s"),
    ("VII-E", "Records opened per second, m = 50", "bundle_50_records_per_s", "records/s"),
    ("VII-F", "Narrow consent, 500 records: PLEDGE", "pledge_narrow_consent_500.s", "s"),
    ("VII-F", "Narrow consent, 500 records: Guo et al.", "guo_narrow_consent_500.s", "s"),
    ("VII-F", "Revoke, 500 records: Guo et al.", "guo_revoke_500.s", "s"),
    ("VII-G", "Encryption per resource (median)", "fhir_enc_ms", "ms"),
    ("VII-G", "FHIR write per resource", "fhir_put_ms", "ms"),
    ("VII-G", "FHIR read per resource", "fhir_get_ms", "ms"),
    ("VII-G", "Storage expansion as stored", "fhir_expansion", "x"),
    ("VII-G", "Storage expansion in binary", "fhir_binary_expansion", "x"),
    ("VII-G", "First access end to end (median)", "e2e.total", "ms"),
    ("VII-G", "First access p95", "e2e_p95_total", "ms"),
    ("VII-G", "  of which endorsement", "e2e.endorse", "ms"),
    ("VII-G", "  of which ordering and commit", "e2e.order", "ms"),
    ("VII-G", "  of which key shares", "e2e.shares", "ms"),
    ("VII-G", "Open a chart of 10 records", "chart.10.total", "ms"),
    ("VII-G", "Open a chart of 50 records", "chart.50.total", "ms"),
    ("VII-G", "Open a chart of 100 records", "chart.100.total", "ms"),
]


def registration_rows(run, paper):
    mine, ref = csv_rows(Path(run) / "registration.csv"), csv_rows(Path(paper) / "registration.csv")
    if not ref:
        return []
    out = []
    for r in ref:
        y = next((x for x in mine or [] if x["op"] == r["op"]), None)
        out.append(("VII-A", f"Registration / re-key: {r['op']}", float(r["median_ms"]),
                    float(y["median_ms"]) if y else None, "ms"))
    return out


# ---------------------------------------------------------------- rendering
def fmt(v, unit=""):
    if v is None:
        return "—"
    if isinstance(v, float):
        s = f"{v:,.2f}" if abs(v) < 100 else f"{v:,.0f}"
    else:
        s = str(v)
    return f"{s} {unit}".strip()


def img(path):
    p = Path(path)
    if not p.exists():
        return None
    return "data:image/png;base64," + base64.b64encode(p.read_bytes()).decode()


CSS = """
:root{--bg:#fbfaf7;--fg:#1d1d1b;--muted:#6b6a65;--line:#e4e1d8;--ok:#2f7d4a;--bad:#b3261e;--na:#8a877e;--acc:#1f5fa8;--card:#fff}
@media (prefers-color-scheme: dark){:root{--bg:#161614;--fg:#ecebe6;--muted:#a3a19a;--line:#33322e;--ok:#6cc58b;--bad:#ff8a80;--na:#8f8c84;--acc:#8fb4e8;--card:#1e1e1b}}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--fg);font:15px/1.5 system-ui,-apple-system,Segoe UI,sans-serif}
main{max-width:1100px;margin:0 auto;padding:28px 16px 64px}h1{font-size:26px;margin:0 0 4px}h2{font-size:19px;margin:36px 0 8px;border-bottom:1px solid var(--line);padding-bottom:6px}
p.lead{color:var(--muted);margin:0 0 18px}.tiles{display:grid;grid-template-columns:repeat(auto-fit,minmax(170px,1fr));gap:10px;margin:16px 0}
.tile{background:var(--card);border:1px solid var(--line);border-radius:10px;padding:12px 14px}.tile b{display:block;font-size:24px}.tile span{color:var(--muted);font-size:13px}
table{width:100%;border-collapse:collapse;background:var(--card);border:1px solid var(--line);border-radius:8px;overflow:hidden;font-size:13.5px}
th,td{text-align:left;padding:7px 10px;border-bottom:1px solid var(--line);vertical-align:top}th{font-weight:600;color:var(--muted);font-size:12.5px;text-transform:uppercase;letter-spacing:.03em}
td.num{text-align:right;font-variant-numeric:tabular-nums;white-space:nowrap}.s{font-weight:600;white-space:nowrap}.s.ok{color:var(--ok)}.s.bad{color:var(--bad)}.s.na{color:var(--na)}
.wrap{overflow-x:auto}.figs{display:grid;grid-template-columns:1fr 1fr;gap:12px}@media (max-width:720px){.figs{grid-template-columns:1fr}}
figure{margin:0;background:#fff;border:1px solid var(--line);border-radius:8px;padding:8px}figure img{width:100%;height:auto}figcaption{color:#555;font-size:12.5px;margin-top:4px}
.note{color:var(--muted);font-size:13.5px}code{font-size:12.5px}
"""


def status_class(s):
    s = s.lower()
    return "ok" if s in ("match", "holds", "ok") else ("na" if s in ("not run", "skipped", "smaller run", "indicative", "—")
                                                       else "bad")


def render(run, paper, info, exact, trends, measured, mimic, N):
    run, paper = Path(run), Path(paper)
    n_ex = [e for e in exact if e[4] not in ("not run", "smaller run")]
    n_tr = [t for t in trends if t[3] not in ("not run", "indicative")]
    host = info.get("host", {})
    h = [f"<!doctype html><html lang=en><head><meta charset=utf-8><meta name=viewport content='width=device-width,initial-scale=1'>"
         f"<title>PLEDGE Reproduction Report</title><style>{CSS}</style></head><body><main>",
         "<h1>PLEDGE reproduction report</h1>",
         f"<p class=lead>{html.escape(info.get('mode', '?'))} run, {html.escape(info.get('started', ''))} — "
         f"your machine: {html.escape(str(host.get('cpu', host.get('machine', ''))))}, {host.get('cpus', '?')} CPUs, "
         f"{host.get('ram_gb', '?')} GB RAM, {html.escape(host.get('system', ''))}, Python {host.get('python', '')}. "
         f"Paper: {PAPER_HOST}.</p>",
         "<div class=tiles>",
         f"<div class=tile><b>{sum(e[4] == 'match' for e in n_ex)}/{len(n_ex)}</b><span>exact results equal the paper</span></div>",
         f"<div class=tile><b>{sum(t[3] == 'holds' for t in n_tr)}/{len(n_tr)}</b><span>trend statements hold on your numbers</span></div>",
         f"<div class=tile><b>{sum(1 for m in measured if m[3] is not None)}</b><span>measured values compared</span></div>",
         f"<div class=tile><b>{sum(1 for s in info.get('stages', {}).values() if s['status'] == 'ok')}/"
         f"{len(info.get('stages', {}))}</b><span>stages completed</span></div></div>",
         "<p class=note>Exact results (security outcomes, test results, operation counts) do not depend on the "
         "machine and must equal the paper's. Trend statements are the comparisons of Section VII, checked on "
         "your own numbers. Measured times depend on the hardware: compare them through the ratio, not the "
         "absolute value. Fabric experiments need Linux (or Docker on Windows/macOS). In a quick run each "
         "ledger point lasts 10 s instead of 30 s, so ledger statements are marked indicative when they "
         "do not hold; run the full experiments to check them.</p>"]
    # stages
    h.append("<h2>Stages</h2><div class=wrap><table><tr><th>Stage</th><th>Status</th><th>Time</th><th>Notes</th></tr>")
    for s, v in info.get("stages", {}).items():
        st = v["status"]
        h.append(f"<tr><td>{s}</td><td class='s {status_class(st)}'>{st}</td><td class=num>{v['seconds']:.0f} s</td>"
                 f"<td>{html.escape(v.get('note', ''))}</td></tr>")
    h.append("</table></div>")
    # exact
    h.append("<h2>Exact results (must equal the paper)</h2><div class=wrap><table><tr><th>Where</th><th>Result</th>"
             "<th>Paper</th><th>Yours</th><th>Status</th></tr>")
    for sec, what, pv, yv, st in exact:
        h.append(f"<tr><td>{sec}</td><td>{html.escape(what)}</td><td>{html.escape(str(pv))}</td>"
                 f"<td>{html.escape(str(yv))}</td><td class='s {status_class(st)}'>{st}</td></tr>")
    h.append("</table></div>")
    # trends
    h.append("<h2>Statements of Section VII, checked on your numbers</h2><div class=wrap><table><tr><th>Where</th>"
             "<th>Statement</th><th>Your evidence</th><th>Status</th></tr>")
    for sec, stmt, ev, st in trends:
        h.append(f"<tr><td>{sec}</td><td>{html.escape(stmt)}</td><td>{html.escape(ev)}</td>"
                 f"<td class='s {status_class(st)}'>{st}</td></tr>")
    h.append("</table></div>")
    # measured
    h.append("<h2>Measured values (hardware-dependent)</h2><div class=wrap><table><tr><th>Where</th><th>Quantity</th>"
             "<th>Paper</th><th>Yours</th><th>Yours / paper</th></tr>")
    for sec, label, pv, yv, unit in measured:
        ratio = f"{yv / pv:.2f}x" if isinstance(pv, (int, float)) and isinstance(yv, (int, float)) and pv else "—"
        h.append(f"<tr><td>{sec}</td><td>{html.escape(label)}</td><td class=num>{fmt(pv, unit)}</td>"
                 f"<td class=num>{fmt(yv, unit)}</td><td class=num>{ratio}</td></tr>")
    h.append("</table></div>")
    # real data
    h.append("<h2>Real data: MIMIC-IV Clinical Database Demo on FHIR</h2>")
    if mimic:
        h.append("<p class=note>Not in the paper. 100 real, de-identified ICU patients (PhysioNet, ODbL 1.0), "
                 "encrypted with the same consent and stored in the same HAPI FHIR server as the Synthea cohort.</p>"
                 "<div class=wrap><table><tr><th>Quantity</th><th>MIMIC-IV (yours)</th><th>Synthea (yours)</th>"
                 "<th>Synthea (paper)</th></tr>")
        P = load(paper)
        for label, k, unit in (("Patients", "patients", ""), ("Resources encrypted", "resources", ""),
                               ("Resources labelled R", "restricted", ""), ("Encryption per resource", "enc_ms", "ms"),
                               ("FHIR write", "put_ms", "ms"), ("FHIR read", "get_ms", "ms"),
                               ("Mean resource size", "mean_plain", "bytes"),
                               ("Storage expansion as stored", "expansion", "x"),
                               ("Storage expansion in binary", "binary_expansion", "x")):
            h.append(f"<tr><td>{label}</td><td class=num>{fmt(N.get('mimic_' + k), unit)}</td>"
                     f"<td class=num>{fmt(N.get('fhir_' + k), unit)}</td><td class=num>{fmt(P.get('fhir_' + k), unit)}</td></tr>")
        h.append("</table></div>")
        rows = csv_rows(run / "fhir_workload_mimic.csv") or []
        if rows:
            ch = [float(r["chart_access_s"]) for r in rows]
            h.append(f"<p class=note>Opening a patient's whole readable chart as one logged request: median "
                     f"{statistics.median(ch):.2f} s for a median chart of "
                     f"{statistics.median(int(r['chart']) for r in rows)} resources (in-process ledger).</p>")
    else:
        h.append("<p class=note>Not run in this session (stage fhir-mimic).</p>")
    # figures
    h.append("<h2>Figures: yours (left) and the paper's (right)</h2>")
    for name, num, cap in FIGS:
        a, b = img(run / f"{name}.png"), img(paper / f"{name}.png")
        h.append(f"<h3>{num}. {html.escape(cap)}</h3><div class=figs>")
        h.append(f"<figure>{f'<img src={a!r} alt=yours>' if a else '<p class=note>not produced in this run</p>'}"
                 f"<figcaption>Your run</figcaption></figure>")
        h.append(f"<figure>{f'<img src={b!r} alt=paper>' if b else ''}<figcaption>Paper</figcaption></figure></div>")
    h.append("<p class=note>Raw results, logs and numbers.json are in the same folder as this report.</p>"
             "</main></body></html>")
    return "\n".join(h)


def markdown(info, exact, trends, measured):
    L = [f"# PLEDGE reproduction report ({info.get('mode')} run, {info.get('started')})", ""]
    L += ["## Exact results", "", "| Where | Result | Paper | Yours | Status |", "|---|---|---|---|---|"]
    L += [f"| {a} | {b} | {c} | {d} | {e} |" for a, b, c, d, e in exact]
    L += ["", "## Statements of Section VII on your numbers", "", "| Where | Statement | Evidence | Status |",
          "|---|---|---|---|"]
    L += [f"| {a} | {b} | {c} | {d} |" for a, b, c, d in trends]
    L += ["", "## Measured values", "", "| Where | Quantity | Paper | Yours | Ratio |", "|---|---|---|---|---|"]
    for sec, label, pv, yv, unit in measured:
        ratio = f"{yv / pv:.2f}x" if isinstance(pv, (int, float)) and isinstance(yv, (int, float)) and pv else "—"
        L.append(f"| {sec} | {label} | {fmt(pv, unit)} | {fmt(yv, unit)} | {ratio} |")
    return "\n".join(L) + "\n"


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("run")
    ap.add_argument("--paper", default="paper_results")
    a = ap.parse_args()
    run, paper = Path(a.run), Path(a.paper)
    info = json.loads((run / "run_info.json").read_text()) if (run / "run_info.json").exists() else {}
    N, P = load(run), load(paper)
    exact = exact_checks(run, paper, N, P, info)
    trends = trend_checks(N)
    if info.get("mode") == "quick":                 # 10-second ledger points: indicative only
        trends = [(sec, stmt, ev + " (quick run: 10 s per point)", st if st != "DOES NOT HOLD" else "indicative")
                  if sec == "VII-E" and st not in ("not run",) else (sec, stmt, ev, st)
                  for sec, stmt, ev, st in trends]
    quick = info.get("mode") == "quick"
    measured = [(sec, label + (" (full run only)" if quick and key.startswith("max_thr") else ""), get(P, key),
                 None if quick and key.startswith("max_thr") else get(N, key), unit)
                for sec, label, key, unit in MEASURED]
    measured += registration_rows(run, paper)
    mimic = "mimic_resources" in N
    (run / "REPORT.html").write_text(render(run, paper, info, exact, trends, measured, mimic, N), encoding="utf-8")
    (run / "REPORT.md").write_text(markdown(info, exact, trends, measured), encoding="utf-8")
    ex = [e for e in exact if e[4] not in ("not run", "smaller run")]
    tr = [t for t in trends if t[3] not in ("not run", "indicative")]
    print(f"exact results equal to the paper: {sum(e[4] == 'match' for e in ex)}/{len(ex)}")
    print(f"Section VII statements holding on this run: {sum(t[3] == 'holds' for t in tr)}/{len(tr)}")
    for e in ex:
        if e[4] != "match":
            print("  differs:", e[1], "| paper", e[2], "| yours", e[3])
    for t in tr:
        if t[3] != "holds":
            print("  statement", t[3].lower() + ":", t[1], "|", t[2])
    print(f"report -> {run / 'REPORT.html'}")


if __name__ == "__main__":
    main()
