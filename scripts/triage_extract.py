#!/usr/bin/env python3
"""Extract non-kernel Unpatched issues from the sbom-cve-check manifest
into a triage CSV template (status and reason left blank).

Usage: triage_extract.py MANIFEST.json OUT.csv
Refuses to overwrite OUT.csv so finished triage is never lost.
"""
import csv
import json
import os
import sys
from collections import Counter

KERNEL = "linux-yocto"
EXPECTED = {
    "openssl": 12, "glibc": 5, "busybox": 4, "acl": 2, "tar": 2,
    "attr": 1, "util-linux": 1, "util-linux-libuuid": 1, "zlib": 1,
}
# Allowed values for the status column when triaging by hand:
#   affected | not_affected | unknown
FIELDS = ["id", "package", "version", "cvss", "summary", "detail",
          "description", "link", "status", "reason"]


def clean(x):
    s = "" if x is None else str(x)
    s = s.replace("\u2014", "-").replace("\u2013", "-")
    return " ".join(s.split())


def packages(data):
    p = data["package"]
    if isinstance(p, dict):
        for k, v in p.items():
            v = dict(v)
            v.setdefault("name", k)
            yield v
    else:
        yield from p


def issues(pkg):
    for key in ("issue", "issues"):
        if key in pkg:
            return pkg[key]
    raise KeyError("no issue list, package keys: %s" % sorted(pkg))


def cvss(i):
    for k in ("scorev3", "scorev4", "scorev2"):
        v = i.get(k)
        if v not in (None, "", 0, "0", "0.0"):
            return "%s:%s" % (k[5:], v)
    return ""


def main(argv):
    if len(argv) != 3:
        print(__doc__)
        return 2
    man, out = argv[1], argv[2]
    if os.path.exists(out):
        print("FAIL: %s exists, not overwriting" % out)
        return 1
    with open(man) as f:
        data = json.load(f)
    rows, counts = [], Counter()
    for pkg in packages(data):
        name = pkg.get("name", "?")
        for i in issues(pkg):
            if i.get("status") != "Unpatched":
                continue
            counts[name] += 1
            if name == KERNEL:
                continue
            rows.append({
                "id": clean(i.get("id")), "package": clean(name),
                "version": clean(pkg.get("version")), "cvss": cvss(i),
                "summary": clean(i.get("summary")),
                "detail": clean(i.get("detail")),
                "description": clean(i.get("description")),
                "link": clean(i.get("link")), "status": "", "reason": "",
            })
    kernel = counts.pop(KERNEL, 0)
    print("kernel Unpatched (not written):", kernel)
    print("non-kernel by package:", dict(sorted(counts.items())))
    if dict(counts) != EXPECTED:
        print("FAIL: counts differ from the CVE report, nothing written")
        print("expected:", dict(sorted(EXPECTED.items())))
        return 1
    rows.sort(key=lambda r: (r["package"], r["id"]))
    with open(out, "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=FIELDS)
        w.writeheader()
        w.writerows(rows)
    print("wrote %d rows to %s" % (len(rows), out))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
