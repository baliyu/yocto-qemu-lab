"""Check and summarise the userland triage in docs/triage_userland.csv.

Usage: triage_check.py TRIAGE.csv PACKAGES.csv OUTDIR

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


def summarise(rows, kernel_unpatched):
    return {
        "userland_rows": len(rows),
        "by_status": dict(sorted(Counter(r["status"] for r in rows).items())),
        "by_package": dict(sorted(Counter(r["package"] for r in rows).items())),
        "kernel_unpatched_not_triaged": kernel_unpatched,
    }


def kernel_unpatched(path):
    with open(path, newline="", encoding="utf-8") as f:
        for r in csv.DictReader(f):
            if r["name"] == KERNEL:
                return int(r["unpatched"])
    return 0


def main(argv):
    if len(argv) != 4:
        print(__doc__)
        return 2
    triage, packages, outdir = argv[1:]
    try:
        rows = check(load(triage))
        compare(rows, expected_unpatched(packages))
    except TriageError as e:
        print("FAIL:", e)
        return 1
    s = summarise(rows, kernel_unpatched(packages))
    os.makedirs(outdir, exist_ok=True)
    with open(os.path.join(outdir, "triage_totals.json"), "w") as f:
        json.dump(s, f, indent=2, sort_keys=True)
        f.write("\n")
    print("OK:", json.dumps(s, sort_keys=True))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
