"""Summarise a Yocto sbom-cve-check manifest (yocto-cve-check-manifest format).

AI-assisted: drafted with Claude, checked by the author.
"""
import collections
import csv
import hashlib
import json
import os
import sys

STATUSES = ("Patched", "Unpatched", "Ignored")


def summarise(manifest):
    rows = []
    for p in manifest.get("package", []):
        c = collections.Counter(i.get("status", "Other") for i in p.get("issue", []))
        rows.append({
            "name": p.get("name", ""),
            "version": p.get("version", ""),
            "patched": c["Patched"],
            "unpatched": c["Unpatched"],
            "ignored": c["Ignored"],
            "other": sum(v for k, v in c.items() if k not in STATUSES),
        })
    rows.sort(key=lambda r: (-r["unpatched"], r["name"]))
    return rows


def totals(rows):
    t = {k: sum(r[k] for r in rows) for k in ("patched", "unpatched", "ignored", "other")}
    t["packages"] = len(rows)
    t["packages_with_unpatched"] = sum(1 for r in rows if r["unpatched"])
    return t


def main(argv):
    if len(argv) != 3:
        print("usage: analyze_manifest.py MANIFEST.json OUT_DIR")
        return 2
    path, out = argv[1], argv[2]
    with open(path, "rb") as f:
        raw = f.read()
    rows = summarise(json.loads(raw))
    tot = totals(rows)
    tot["manifest_file"] = os.path.basename(os.path.realpath(path))
    tot["manifest_bytes"] = len(raw)
    tot["manifest_sha256"] = hashlib.sha256(raw).hexdigest()
    os.makedirs(out, exist_ok=True)
    with open(os.path.join(out, "packages.csv"), "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=["name", "version", "patched", "unpatched", "ignored", "other"])
        w.writeheader()
        w.writerows(rows)
    with open(os.path.join(out, "totals.json"), "w") as f:
        json.dump(tot, f, indent=2, sort_keys=True)
        f.write("\n")
    print(json.dumps(tot, indent=2, sort_keys=True))
    for r in rows[:5]:
        print(r)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
