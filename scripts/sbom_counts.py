"""Count what two SBOMs contain: a Yocto SPDX 3 JSON file and an SPDX 2.3 tag-value file.

AI-assisted: drafted with Claude, checked by the author.
"""
import collections
import hashlib
import json
import os
import sys

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt  # noqa: E402


def _read(path):
    with open(path, "rb") as f:
        raw = f.read()
    return raw, {
        "file": os.path.basename(os.path.realpath(path)),
        "bytes": len(raw),
        "sha256": hashlib.sha256(raw).hexdigest(),
    }


def count_spdx3(path):
    raw, info = _read(path)
    graph = json.loads(raw).get("@graph", [])
    c = collections.Counter(str(e.get("type")) for e in graph if isinstance(e, dict))
    info.update({
        "format": "SPDX 3.x JSON",
        "elements": len(graph),
        "packages": c["software_Package"],
        "files": c["software_File"],
        "vulnerability_elements": c["security_Vulnerability"],
    })
    return info


def count_spdx2(path):
    raw, info = _read(path)
    lines = raw.decode("utf-8").splitlines()
    version = next((x.split(":", 1)[1].strip() for x in lines if x.startswith("SPDXVersion:")), "")
    info.update({
        "format": version + " tag-value",
        "packages": sum(1 for x in lines if x.startswith("PackageName:")),
        "files": sum(1 for x in lines if x.startswith("FileName:")),
        "relationships": sum(1 for x in lines if x.startswith("Relationship:")),
        "vulnerability_elements": 0,
    })
    return info


def plot(yocto, mcu, out_png):
    fig, axes = plt.subplots(1, 2, figsize=(8, 3.5))
    labels = ["mcuboot-lab\n(SPDX 2.3)", "Yocto image\n(SPDX 3)"]
    for ax, key, title in zip(axes, ("packages", "files"), ("Package entries", "Files listed")):
        vals = [mcu[key], yocto[key]]
        ax.bar(labels, vals)
        for x, v in enumerate(vals):
            ax.text(x, v, str(v), ha="center", va="bottom")
        ax.set_title(title)
    fig.suptitle("What each SBOM lists (counts read from the files)")
    fig.tight_layout()
    fig.savefig(out_png, dpi=150)
    plt.close(fig)


def main(argv):
    if len(argv) != 4:
        print("usage: sbom_counts.py YOCTO.spdx.json MCUBOOT.spdx OUT_DIR")
        return 2
    yocto, mcu = count_spdx3(argv[1]), count_spdx2(argv[2])
    os.makedirs(argv[3], exist_ok=True)
    with open(os.path.join(argv[3], "sbom_counts.json"), "w") as f:
        json.dump({"yocto": yocto, "mcuboot_lab": mcu}, f, indent=2, sort_keys=True)
        f.write("\n")
    plot(yocto, mcu, os.path.join(argv[3], "fig_sbom_scale.png"))
    print(json.dumps({"yocto": yocto, "mcuboot_lab": mcu}, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
