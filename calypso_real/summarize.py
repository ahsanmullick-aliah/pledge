# Usage: python3 summarize.py results/calypso
import json, glob, statistics as st, sys, os
d = sys.argv[1]
def p(v, q):
    v = sorted(v)
    return v[int(q/100*(len(v)-1))] if v else float('nan')
for f in sorted(glob.glob(os.path.join(d, "calypso_bi*.json")), key=lambda x: int(x.split('bi')[1].split('ms')[0])):
    r = json.load(open(f))
    print("==", r["block_interval"], "threshold", r["threshold"], "errors", len(r.get("errors") or []))
    for k in ["encrypt","write_commit","read_commit","read_proof","decrypt_key","recover","first_access"]:
        v = r["seq_ms"].get(k, [])
        print(f"  {k:13s} n={len(v):2d} p50={p(v,50):7.1f} p25={p(v,25):7.1f} p75={p(v,75):7.1f}")
    ev = r.get("evolve_ms") or []
    print(f"  evolve        n={len(ev)} p50={p(ev,50):.1f}")
    for L in r["load"]:
        print(f"  load {L['rate_offered']:5.0f}/s offered {L.get('offered')} done {L['completed']} fail {L['failed']} unfin {L.get('unfinished')} sat {L.get('saturated')} thr {L['throughput']:.1f} commit_p50 {L['read_commit_p50']:.0f} fa_p50 {L['first_access_p50']:.0f} fa_p95 {L['first_access_p95']:.0f}")
    s = r["security"]
    print("  security:", {k: s[k] for k in s if 'key' not in k or 'recovers' in k})
