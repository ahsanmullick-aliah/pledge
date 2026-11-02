"""Micro-benchmarks for the cryptographic layer (planned paper Section VII-C).

    python3 -m bench.micro --reps 20 --out results/micro.csv

Measures, on this machine and curve (BLS12-381 via mcl):
  * LG-ABE encryption / decryption / outsourced finish vs number of policy attributes
  * ShareGen, ShareVerify, Combine vs threshold k
  * purpose proof generation / verification vs size of the allowed set
Reports mean and standard deviation in milliseconds. These are prototype
numbers (Python + ctypes); report them as such in the paper.
"""
import argparse
import csv
import os
import platform
import statistics
import time

from pledge.crypto import lgabe, rw15, sigma
from pledge.crypto.pairing import gt_rand


def timeit(fn, reps):
    xs = []
    for _ in range(reps):
        t = time.perf_counter()
        fn()
        xs.append((time.perf_counter() - t) * 1000)
    return statistics.mean(xs), (statistics.stdev(xs) if len(xs) > 1 else 0.0)


def bench_abe(reps, sizes):
    council = rw15.Authority.setup("council")
    pub, secrets, _ = lgabe.run_dkg(4, 2)
    pks = {"council": council.pk, lgabe.LEDGER_AUTHORITY: pub.pk}
    owner = lambda a: lgabe.LEDGER_AUTHORITY if lgabe.is_ledger_attr(a) else "council"
    rows = []
    for n in sizes:
        attrs = [f"a{i}" for i in range(n - 1)]
        tau = "bench"
        policy = "(" + " AND ".join(attrs) + f") AND {lgabe.access_attr(tau)}"
        key = rw15.UserKey("u")
        for a in attrs:
            key.add(a, council.keygen("u", a))
        parts = [lgabe.share_gen(secrets[i - 1], "u", lgabe.access_attr(tau), (1, 2)) for i in (1, 2)]
        key.add(lgabe.access_attr(tau), lgabe.combine(pub, parts))
        M = gt_rand()
        ct = rw15.encrypt(M, policy, pks, owner)
        tk, z = rw15.make_transform_key(key)
        partial = rw15.transform(ct, tk)
        for name, fn in (("encrypt", lambda: rw15.encrypt(M, policy, pks, owner)),
                         ("decrypt", lambda: rw15.decrypt(ct, key)),
                         ("proxy_transform", lambda: rw15.transform(ct, tk)),
                         ("device_finish", lambda: rw15.finish(ct, partial, z))):
            m, s = timeit(fn, reps)
            rows.append(("abe", name, "policy_attrs", n, m, s))
        rows.append(("abe", "ciphertext_bytes", "policy_attrs", n, ct.size_bytes(), 0))
    return rows


def bench_threshold(reps, ks):
    rows = []
    for k in ks:
        n = 3 * (k - 1) + 1
        pub, secrets, _ = lgabe.run_dkg(n, k)
        S = tuple(range(1, k + 1))
        parts = [lgabe.share_gen(secrets[i - 1], "u", "acc:t", S) for i in S]
        for name, fn in (("share_gen", lambda: lgabe.share_gen(secrets[0], "u", "acc:t", S)),
                         ("share_verify", lambda: lgabe.share_verify(pub, parts[0])),
                         ("combine_verified", lambda: lgabe.combine(pub, parts)),
                         ("combine_unverified", lambda: lgabe.combine(pub, parts, verify=False))):
            m, s = timeit(fn, reps)
            rows.append(("threshold", name, "k", k, m, s))
    return rows


def bench_purpose(reps, sizes):
    P, R = sigma.ElGamalKey.generate(), sigma.ElGamalKey.generate()
    rows = []
    for n in sizes:
        allowed = list(range(1, n + 1))
        ct, pr = sigma.encrypt_purpose(1, P.pk, R.pk, allowed, b"c")
        m, s = timeit(lambda: sigma.encrypt_purpose(1, P.pk, R.pk, allowed, b"c"), reps)
        rows.append(("purpose", "prove", "allowed_set", n, m, s))
        m, s = timeit(lambda: sigma.verify_purpose(ct, pr, P.pk, R.pk, allowed, b"c"), reps)
        rows.append(("purpose", "verify", "allowed_set", n, m, s))
    return rows


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--reps", type=int, default=20)
    ap.add_argument("--out", default="results/micro.csv")
    ap.add_argument("--quick", action="store_true")
    a = ap.parse_args()
    sizes = [5, 10] if a.quick else [5, 10, 20, 30, 40, 50]
    ks = [2, 3] if a.quick else [2, 3, 4, 5]
    rows = bench_abe(a.reps, sizes) + bench_threshold(a.reps, ks) + bench_purpose(a.reps, [2, 4, 7])
    os.makedirs(os.path.dirname(a.out) or ".", exist_ok=True)
    with open(a.out, "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(["# host", platform.node(), platform.processor() or platform.machine(), platform.python_version()])
        w.writerow(["group", "operation", "param", "value", "mean_ms_or_bytes", "std_ms"])
        w.writerows(rows)
    for r in rows:
        print(f"{r[0]:9s} {r[1]:18s} {r[2]}={r[3]:<3} {r[4]:10.2f} ± {r[5]:.2f}")


if __name__ == "__main__":
    main()
