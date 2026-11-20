#!/usr/bin/env python3
"""Triage the linux-yocto Unpatched matches of the sbom-cve-check manifest.

Usage: triage_kernel.py MANIFEST.json CVELIST_DIR KERNEL_BUILD_DIR ROOTFS OUT.csv

For each match it reads the kernel CVE record (version ranges and the source
files the fix touched), checks 6.18.59 against the ranges, then checks the
kernel build: is each source file compiled, and is it built in or a module.
Refuses to overwrite OUT.csv. One image, one build: not a security assessment.
"""
import csv
import json
import os
import re
import subprocess
import sys
from collections import Counter

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from triage_extract import FIELDS, KERNEL, clean, cvss, issues, packages  # noqa: E402

TARGET = (6, 18, 59)
INF = (10 ** 6,)
EXPECTED_KERNEL = 116
DEVICE = (
    ("drivers/nvme/", "an NVMe controller"),
    ("drivers/usb/", "a USB controller"),
    ("drivers/acpi/", "the ACPI platform devices"),
    ("arch/x86/events/", "the CPU performance counters"),
    ("drivers/video/fbdev/", "a framebuffer device"),
    ("drivers/net/virtio_net.c", "a virtio network device"),
    ("drivers/tty/serial/", "a serial port"),
)
MODULE_CFG = (
    ("net/netfilter/", "NF_CONNTRACK"), ("net/sched/", "NET_SCH_TEQL"),
    ("net/8021q/", "VLAN_8021Q"), ("net/wireless/", "CFG80211"),
    ("net/mac80211/", "MAC80211"), ("drivers/net/tun.c", "TUN"),
    ("net/sctp/", "IP_SCTP"), ("drivers/net/bonding/", "BONDING"),
    ("fs/fuse/", "FUSE_FS"), ("fs/nfsd/", "NFSD"), ("sound/core/", "SND_HWDEP"),
)
NOT_BUILT = (
    ("fs/erofs/", "CONFIG_EROFS_FS is not set"),
    ("kernel/sched/ext.c", "CONFIG_SCHED_CLASS_EXT is absent"),
)


def first_prefix(table, name):
    for prefix, value in table:
        if name.startswith(prefix):
            return value
    return None


def parse(v):
    v = str(v)
    if v == "*":
        return INF
    if not re.fullmatch(r"\d+(\.\d+)*(\.\*)?", v):
        return None
    return tuple(int(x) for x in v.replace(".*", ".9999").split("."))


def cover(e):
    s = parse(e.get("version", ""))
    if s is None:
        return False
    if "lessThan" in e:
        t = parse(e["lessThan"])
        return t is not None and s <= TARGET < t
    if "lessThanOrEqual" in e:
        t = parse(e["lessThanOrEqual"])
        return t is not None and s <= TARGET <= t
    return s <= TARGET


def sem(container):
    return [e for e in container.get("versions", []) or []
            if parse(e.get("version", "")) is not None]


def compact(e):
    end = e.get("lessThan") or e.get("lessThanOrEqual") or ""
    op = "<" if "lessThan" in e else ("<=" if end else "")
    return "%s..%s%s" % (e.get("version"), op, end)


def version_verdict(aff):
    """Return (code, text). A1 explicit range, A2 introduced and not fixed,
    B unaffected range covers 6.18.59, D no version ranges, ? unusable."""
    c1 = [c for c in aff if c.get("defaultStatus") == "unaffected"]
    c2 = [c for c in aff if c.get("defaultStatus") == "affected"]
    if not any(sem(c) for c in aff):
        return "D", "the record has no version ranges"
    a1 = [e for c in c1 for e in sem(c) if e.get("status") == "affected" and cover(e)]
    if a1:
        return "A1", "the record lists %s as affected" % compact(a1[0])
    una = [e for c in c2 for e in sem(c) if e.get("status") == "unaffected" and cover(e)]
    if una:
        return "B", "the record lists %s as unaffected" % compact(una[0])
    affs = [e for c in c2 for e in sem(c) if e.get("status") == "affected" and cover(e)]
    if affs:
        fix = next((e["version"] for c in c2 for e in sem(c)
                    if e.get("status") == "unaffected" and str(e["version"]).startswith("6.18.")), None)
        if fix:
            return "A2", "introduced in %s and fixed in %s, after 6.18.59" % (affs[0]["version"], fix)
        return "A2", "introduced in %s with no 6.18 fix listed" % affs[0]["version"]
    return "?", "no usable version range"


def classify(verdict, ev, files, cstates, rootfs_kos=frozenset(), dir_kos=None):
    """cstates: list of (c_file, state, exists_in_source), state in
    builtin, module, none, unk. Returns (status, reason)."""
    dir_kos = dir_kos or (lambda d: set())
    if verdict == "D":
        return "unknown", ("The CVE record has no version ranges, so I cannot tell whether "
                           "6.18.59 is in the vulnerable range. Only the summary is available.")
    if verdict == "?":
        return "unknown", "The CVE record has no usable version range for 6.18.59."
    if verdict == "B":
        return "not_affected", "Version: %s, which covers 6.18.59." % ev
    others = [f for f in files if f.startswith("rust/")
              or (f.startswith("arch/") and not f.startswith("arch/x86/"))]
    if files and len(others) == len(files):
        if files[0].startswith("rust/"):
            return "not_affected", ("Rust support is not enabled: CONFIG_RUST is absent from the "
                                    "kernel .config. Version: %s." % ev)
        return "not_affected", ("The code is for the %s architecture and this kernel is x86-64. "
                                "Version: %s." % (files[0].split("/")[1], ev))
    if not cstates:
        return "unknown", ("The record names only header or non-C files (%s), so I could not tell "
                           "which code uses them. Version: %s." % (", ".join(files[:2]), ev))
    existing = [c for c in cstates if c[2]]
    if not existing:
        return "unknown", ("The record names %s, which does not exist in the 6.18.59 source (the "
                           "code was probably moved there later), so I did not locate the "
                           "vulnerable code. Version: %s." % (cstates[0][0], ev))
    built = [c for c in existing if c[1] == "builtin"]
    if built:
        f = built[0][0]
        what = first_prefix(DEVICE, f)
        if what:
            return "unknown", ("The code in %s is built into the kernel, but I did not check whether "
                               "this QEMU machine has %s. Version: %s." % (f, what, ev))
        return "affected", ("Version: %s. The code in %s is built into this kernel. Reachable from "
                            "user space in principle; exploitability not assessed." % (ev, f))
    mods = [c for c in existing if c[1] == "module"]
    if mods:
        f = mods[0][0]
        cfg = first_prefix(MODULE_CFG, f)
        cfg_txt = " (CONFIG_%s=m)" % cfg if cfg else ""
        if dir_kos(os.path.dirname(f)) & set(rootfs_kos):
            return "affected", ("Version: %s. The code in %s is a module%s and that module is in "
                                "the image." % (ev, f, cfg_txt))
        return "not_affected", ("The code in %s is compiled as a module%s and the module is not in "
                                "the image: its root filesystem holds %d kernel module file(s) (%s). "
                                "Version: %s." % (f, cfg_txt, len(rootfs_kos),
                                                  ", ".join(sorted(rootfs_kos)), ev))
    if all(c[1] == "none" for c in existing):
        f = existing[0][0]
        why = first_prefix(NOT_BUILT, f)
        extra = " (%s)" % why if why else ""
        return "not_affected", ("The source file %s exists in the 6.18.59 source but has no object "
                                "file in the build, so it is not compiled into this kernel%s. "
                                "Version: %s." % (f, extra, ev))
    return "unknown", "I could not tell whether %s is built in or a module. Version: %s." % (existing[0][0], ev)


_members = {}


def members(kb, dirpath):
    if dirpath not in _members:
        p = os.path.join(kb, dirpath, "built-in.a")
        try:
            _members[dirpath] = subprocess.run(["ar", "t", p], capture_output=True,
                                               text=True, check=True).stdout.split()
        except Exception:
            _members[dirpath] = None
    return _members[dirpath]


def kos_in(kb, d):
    full = os.path.join(kb, d)
    if not os.path.isdir(full):
        return set()
    return {n for n in os.listdir(full) if n.endswith(".ko")}


def c_states(files, kb):
    out = []
    for f in sorted({x for x in files if x.endswith(".c")}):
        exists = os.path.exists(os.path.join(kb, "source", f))
        if not os.path.exists(os.path.join(kb, f[:-2] + ".o")):
            out.append((f, "none", exists))
            continue
        mem = members(kb, os.path.dirname(f))
        name = os.path.basename(f[:-2]) + ".o"
        if mem is None:
            out.append((f, "module" if kos_in(kb, os.path.dirname(f)) else "unk", exists))
        else:
            out.append((f, "builtin" if any(m == name or m.endswith("/" + name) for m in mem)
                        else "module", exists))
    return out


def record_path(cvelist, cid):
    _, year, num = cid.split("-")
    return os.path.join(cvelist, "cves", year, "%dxxx" % (int(num) // 1000), cid + ".json")


def main(argv):
    if len(argv) != 6:
        print(__doc__)
        return 2
    man, cvelist, kb, rootfs, out = argv[1:]
    if os.path.exists(out):
        print("FAIL: %s exists, not overwriting" % out)
        return 1
    with open(man) as f:
        data = json.load(f)
    kp = [p for p in packages(data) if p.get("name") == KERNEL]
    if len(kp) != 1:
        print("FAIL: expected one %s package" % KERNEL)
        return 1
    unp = [i for i in issues(kp[0]) if i.get("status") == "Unpatched"]
    if len(unp) != EXPECTED_KERNEL:
        print("FAIL: %d kernel Unpatched issues, expected %d" % (len(unp), EXPECTED_KERNEL))
        return 1
    rootfs_kos = set()
    for _root, _dirs, names in os.walk(os.path.join(rootfs, "lib", "modules")):
        for n in names:
            if ".ko" in n:
                rootfs_kos.add(re.sub(r"\.(zst|xz|gz)$", "", n))
    rows, tally = [], Counter()
    for i in sorted(unp, key=lambda x: str(x.get("id"))):
        cid = clean(i.get("id"))
        rec = record_path(cvelist, cid)
        aff = []
        if os.path.exists(rec):
            with open(rec) as f:
                aff = json.load(f).get("containers", {}).get("cna", {}).get("affected") or []
        verdict, ev = version_verdict(aff)
        files = [x for c in aff for x in (c.get("programFiles") or [])]
        status, reason = classify(verdict, ev, files, c_states(files, kb), rootfs_kos,
                                  lambda d: kos_in(kb, d))
        assert reason.strip(), cid
        tally[status] += 1
        rows.append({
            "id": cid, "package": KERNEL, "version": clean(kp[0].get("version")),
            "cvss": cvss(i), "summary": clean(i.get("summary")), "detail": clean(i.get("detail")),
            "description": clean(i.get("description")), "link": clean(i.get("link")),
            "status": status, "reason": clean(reason),
        })
    with open(out, "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=FIELDS)
        w.writeheader()
        w.writerows(rows)
    print("wrote %d rows to %s" % (len(rows), out))
    print("statuses:", dict(sorted(tally.items())))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
