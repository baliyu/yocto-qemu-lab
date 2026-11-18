import csv

import pytest

import scorecard as s


def write(tmp_path, rows):
    p = tmp_path / "s.csv"
    with open(p, "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=["id", "phase", "statement", "chance", "outcome", "note"])
        w.writeheader()
        w.writerows(rows)
    return str(p)


def row(i, chance, outcome, note=""):
    return {"id": i, "phase": "x", "statement": "y", "chance": chance, "outcome": outcome, "note": note}


def test_load_converts_chance_and_blank(tmp_path):
    r = s.load(write(tmp_path, [row("a", "70", "hit"), row("b", "", "hit")]))
    assert r[0]["chance"] == 70 and r[1]["chance"] is None


def test_duplicate_id_rejected(tmp_path):
    with pytest.raises(s.ScorecardError):
        s.load(write(tmp_path, [row("a", "70", "hit"), row("a", "60", "hit")]))


def test_miss_needs_note(tmp_path):
    with pytest.raises(s.ScorecardError):
        s.load(write(tmp_path, [row("a", "70", "miss")]))


def test_totals(tmp_path):
    rows = s.load(write(tmp_path, [row("a", "80", "hit"), row("b", "60", "miss", "n"),
                                   row("c", "50", "not_scored", "n")]))
    t = s.totals(rows)
    assert (t["hits"], t["misses"], t["not_scored"]) == (1, 1, 1)
    assert t["hit_rate_percent"] == 50.0 and t["mean_stated_chance"] == 70.0


def test_calibration_buckets_and_png(tmp_path):
    rows = s.load(write(tmp_path, [row("a", "80", "hit"), row("b", "85", "miss", "n"),
                                   row("c", "30", "miss", "n")]))
    cal = {b["bucket"]: b for b in s.calibration(rows)}
    assert cal["76-85"]["n"] == 2 and cal["76-85"]["hit_rate"] == 50.0 and cal["0-40"]["n"] == 1
    out = tmp_path / "c.png"
    s.plot(s.calibration(rows), str(out))
    assert out.read_bytes()[:4] == b"\x89PNG"


def test_too_many_fields_rejected(tmp_path):
    p = tmp_path / "bad.csv"
    p.write_text("id,phase,statement,chance,outcome,note\na,x,y,70,miss,one, two\n")
    with pytest.raises(s.ScorecardError):
        s.load(str(p))
