"""Check and summarise the triage in docs/triage_userland.csv and docs/triage_kernel.csv.

Usage: triage_check.py TRIAGE.csv PACKAGES.csv OUTDIR [KERNEL.csv]

With KERNEL.csv (docs/triage_kernel.csv) the kernel rows are checked the same way
and counted against the linux-yocto Unpatched figure in PACKAGES.csv.

AI-assisted: drafted with Claude, checked by the author.
"""
import csv
import json
import os
import sys
from collections import Counter

STATUSES = ("affected", "not_affected", "unknown")
FIELDS = ["id", "package", "version", "cvss", "summary", "detail",
          "description", "link", "status", "reason"]
KERNEL = "linux-yocto"
EM_DASH = "\u2014"


class TriageError(ValueError):
    pass


def load(path):
    with open(path, newline="", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        if reader.fieldnames != FIELDS:
            raise TriageError("columns differ: %s" % reader.fieldnames)
        return list(reader)


def check(rows):
    seen = set()
    for n, r in enumerate(rows, 2):
        key = (r["package"], r["id"])
        if key in seen:
            raise TriageError("line %d: duplicate %s %s" % (n, key[0], key[1]))
        seen.add(key)
        if r["status"] not in STATUSES:
            raise TriageError("line %d: bad status %r" % (n, r["status"]))
        if not r["reason"].strip():
            raise TriageError("line %d: empty reason" % n)
        for v in r.values():
            if EM_DASH in v:
                raise TriageError("line %d: em dash" % n)
    return rows


def expected_unpatched(path):
    out = {}
    with open(path, newline="", encoding="utf-8") as f:
        for r in csv.DictReader(f):
            n = int(r["unpatched"])
            if r["name"] != KERNEL and n > 0:
                out[r["name"]] = n
    return out


def compare(rows, expected):
    got = dict(Counter(r["package"] for r in rows))
    if got != expected:
        diff = {k: (got.get(k, 0), expected.get(k, 0))
                for k in set(got) | set(expected) if got.get(k, 0) != expected.get(k, 0)}
        raise TriageError("package counts differ (triaged, expected): %s" % diff)


def compare_kernel(rows, expected):
    wrong = sorted({r["package"] for r in rows if r["package"] != KERNEL})
    if wrong:
        raise TriageError("kernel csv has other packages: %s" % wrong)
    if len(rows) != expected:
        raise TriageError("kernel rows differ (triaged, expected): (%d, %d)" % (len(rows), expected))


def summarise(rows, kernel_unpatched, kernel_rows=()):
    s = {
        "userland_rows": len(rows),
        "by_status": dict(sorted(Counter(r["status"] for r in rows).items())),
        "by_package": dict(sorted(Counter(r["package"] for r in rows).items())),
        "kernel_unpatched_not_triaged": kernel_unpatched - len(kernel_rows),
    }
    if kernel_rows:
        s["kernel_rows"] = len(kernel_rows)
        s["kernel_by_status"] = dict(sorted(Counter(r["status"] for r in kernel_rows).items()))
    return s


def kernel_unpatched(path):
    with open(path, newline="", encoding="utf-8") as f:
        for r in csv.DictReader(f):
            if r["name"] == KERNEL:
                return int(r["unpatched"])
    return 0


def main(argv):
    if len(argv) not in (4, 5):
        print(__doc__)
        return 2
    triage, packages, outdir = argv[1:4]
    krows = []
    try:
        rows = check(load(triage))
        compare(rows, expected_unpatched(packages))
        if len(argv) == 5:
            krows = check(load(argv[4]))
            compare_kernel(krows, kernel_unpatched(packages))
    except TriageError as e:
        print("FAIL:", e)
        return 1
    s = summarise(rows, kernel_unpatched(packages), krows)
    os.makedirs(outdir, exist_ok=True)
    with open(os.path.join(outdir, "triage_totals.json"), "w") as f:
        json.dump(s, f, indent=2, sort_keys=True)
        f.write("\n")
    print("OK:", json.dumps(s, sort_keys=True))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
