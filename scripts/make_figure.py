"""Draw unpatched sbom-cve-check matches per package from results/packages.csv.

AI-assisted: drafted with Claude, checked by the author.
"""
import csv
import sys

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt  # noqa: E402


def load_rows(path):
    with open(path, newline="") as f:
        rows = list(csv.DictReader(f))
    for r in rows:
        for k in ("patched", "unpatched", "ignored", "other"):
            r[k] = int(r[k])
    return rows


def plot(rows, out_png):
    shown = [r for r in rows if r["unpatched"] > 0]
    shown.sort(key=lambda r: (r["unpatched"], r["name"]))
    labels = [r["name"] + " " + r["version"] for r in shown]
    values = [r["unpatched"] for r in shown]
    fig, ax = plt.subplots(figsize=(7, 4))
    ax.barh(labels, values)
    for y, v in enumerate(values):
        ax.text(v + 1, y, str(v), va="center")
    ax.set_xlabel("Unpatched database matches (count)")
    ax.set_title("core-image-minimal on qemux86-64: matches awaiting triage,\nnot confirmed vulnerabilities")
    fig.tight_layout()
    fig.savefig(out_png, dpi=150)
    plt.close(fig)
    return [r["name"] for r in shown]


def main(argv):
    if len(argv) != 3:
        print("usage: make_figure.py packages.csv out.png")
        return 2
    names = plot(load_rows(argv[1]), argv[2])
    print("plotted", len(names), "packages:", names)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
