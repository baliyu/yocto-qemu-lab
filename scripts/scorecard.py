"""Check and summarise the prediction record in docs/scorecard.csv.

AI-assisted: drafted with Claude, checked by the author.
"""
import csv
import json
import os
import sys

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt  # noqa: E402

OUTCOMES = ("hit", "miss", "not_scored")
BUCKETS = [(0, 40), (41, 60), (61, 75), (76, 85), (86, 100)]
EM_DASH = "\u2014"


class ScorecardError(ValueError):
    pass


def load(path):
    with open(path, newline="") as f:
        rows = list(csv.DictReader(f))
    seen = set()
    for n, r in enumerate(rows, start=2):
        if None in r:
            raise ScorecardError("line %d: too many fields (quote a comma in a note)" % n)
        if any(v is None for v in r.values()):
            raise ScorecardError("line %d: too few fields" % n)
        if r["id"] in seen:
            raise ScorecardError("line %d: duplicate id %s" % (n, r["id"]))
        seen.add(r["id"])
        if r["outcome"] not in OUTCOMES:
            raise ScorecardError("line %d: bad outcome %r" % (n, r["outcome"]))
        if r["outcome"] in ("miss", "not_scored") and not r["note"].strip():
            raise ScorecardError("line %d: %s needs a note" % (n, r["id"]))
        if EM_DASH in "".join(r.values()):
            raise ScorecardError("line %d: contains an em dash" % n)
        if r["chance"] == "":
            r["chance"] = None
        else:
            try:
                c = int(r["chance"])
            except ValueError:
                raise ScorecardError("line %d: chance is not a number" % n)
            if not 0 <= c <= 100:
                raise ScorecardError("line %d: chance outside 0 to 100" % n)
            r["chance"] = c
    return rows


def _scored_with_chance(rows):
    return [r for r in rows if r["chance"] is not None and r["outcome"] != "not_scored"]


def totals(rows):
    hits = sum(1 for r in rows if r["outcome"] == "hit")
    misses = sum(1 for r in rows if r["outcome"] == "miss")
    ns = sum(1 for r in rows if r["outcome"] == "not_scored")
    wc = _scored_with_chance(rows)
    return {
        "rows": len(rows),
        "hits": hits,
        "misses": misses,
        "not_scored": ns,
        "hit_rate_percent": round(100.0 * hits / (hits + misses), 1) if hits + misses else None,
        "scored_with_chance": len(wc),
        "mean_stated_chance": round(sum(r["chance"] for r in wc) / len(wc), 1) if wc else None,
    }


def calibration(rows):
    out = []
    wc = _scored_with_chance(rows)
    for lo, hi in BUCKETS:
        b = [r for r in wc if lo <= r["chance"] <= hi]
        if b:
            out.append({
                "bucket": "%d-%d" % (lo, hi),
                "n": len(b),
                "mean_chance": round(sum(r["chance"] for r in b) / len(b), 1),
                "hit_rate": round(100.0 * sum(1 for r in b if r["outcome"] == "hit") / len(b), 1),
            })
    return out


def plot(cal, out_png):
    fig, ax = plt.subplots(figsize=(5, 5))
    ax.plot([0, 100], [0, 100], linestyle="--", color="gray", label="perfect calibration")
    ax.scatter([b["mean_chance"] for b in cal], [b["hit_rate"] for b in cal],
               s=[20 + 6 * b["n"] for b in cal], label="my predictions")
    for b in cal:
        ax.annotate("n=%d" % b["n"], (b["mean_chance"], b["hit_rate"]),
                    textcoords="offset points", xytext=(6, -12))
    ax.set_xlabel("Stated chance that the prediction is true (%)")
    ax.set_ylabel("Share that came true (%)")
    ax.set_title("Yocto work: stated chance against outcome")
    ax.set_xlim(0, 100)
    ax.set_ylim(0, 100)
    ax.legend(loc="upper left")
    fig.tight_layout()
    fig.savefig(out_png, dpi=150)
    plt.close(fig)


def main(argv):
    if len(argv) != 3:
        print("usage: scorecard.py scorecard.csv OUT_DIR")
        return 2
    try:
        rows = load(argv[1])
    except ScorecardError as e:
        print("scorecard error:", e)
        return 1
    os.makedirs(argv[2], exist_ok=True)
    t, cal = totals(rows), calibration(rows)
    with open(os.path.join(argv[2], "scorecard_totals.json"), "w") as f:
        json.dump({"totals": t, "calibration": cal}, f, indent=2, sort_keys=True)
        f.write("\n")
    plot(cal, os.path.join(argv[2], "fig_calibration.png"))
    print(json.dumps({"totals": t, "calibration": cal}, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
