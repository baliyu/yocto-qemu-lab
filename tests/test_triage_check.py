import csv

import pytest

import triage_check as t


def row(pkg="a", cid="CVE-1", status="unknown", reason="why"):
    r = {k: "" for k in t.FIELDS}
    r.update(id=cid, package=pkg, status=status, reason=reason)
    return r


def write(tmp_path, rows, name="t.csv"):
    p = tmp_path / name
    with open(p, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=t.FIELDS)
        w.writeheader()
        w.writerows(rows)
    return str(p)


def test_load_and_check_ok(tmp_path):
    rows = t.check(t.load(write(tmp_path, [row(), row(cid="CVE-2")])))
    assert len(rows) == 2


def test_wrong_columns(tmp_path):
    p = tmp_path / "bad.csv"
    p.write_text("id,package\nx,y\n")
    with pytest.raises(t.TriageError):
        t.load(str(p))


def test_bad_status_and_empty_reason():
    with pytest.raises(t.TriageError):
        t.check([row(status="maybe")])
    with pytest.raises(t.TriageError):
        t.check([row(reason="  ")])


def test_same_cve_in_two_packages_is_allowed_but_not_twice_in_one():
    t.check([row(pkg="a", cid="CVE-1"), row(pkg="b", cid="CVE-1")])
    with pytest.raises(t.TriageError):
        t.check([row(pkg="a", cid="CVE-1"), row(pkg="a", cid="CVE-1")])


def test_em_dash_rejected():
    with pytest.raises(t.TriageError):
        t.check([row(reason="a \u2014 b")])


def test_compare_counts():
    rows = [row(cid="1"), row(cid="2"), row(pkg="b", cid="3")]
    t.compare(rows, {"a": 2, "b": 1})
    with pytest.raises(t.TriageError):
        t.compare(rows, {"a": 3, "b": 1})


def test_expected_unpatched_skips_kernel_and_zero(tmp_path):
    p = tmp_path / "p.csv"
    p.write_text("name,version,patched,unpatched,ignored,other\n"
                 "linux-yocto,1,0,9,0,0\nx,1,0,2,0,0\ny,1,5,0,0,0\n")
    assert t.expected_unpatched(str(p)) == {"x": 2}
    assert t.kernel_unpatched(str(p)) == 9


def test_summarise_and_main(tmp_path):
    tri = write(tmp_path, [row(status="affected"), row(cid="2", status="not_affected")])
    pk = tmp_path / "p.csv"
    pk.write_text("name,version,patched,unpatched,ignored,other\nlinux-yocto,1,0,7,0,0\na,1,0,2,0,0\n")
    assert t.main(["x", tri, str(pk), str(tmp_path / "out")]) == 0
    s = (tmp_path / "out" / "triage_totals.json").read_text()
    assert '"kernel_unpatched_not_triaged": 7' in s and '"affected": 1' in s


def test_main_fails_on_count_mismatch(tmp_path):
    tri = write(tmp_path, [row()])
    pk = tmp_path / "p.csv"
    pk.write_text("name,version,patched,unpatched,ignored,other\na,1,0,2,0,0\n")
    assert t.main(["x", tri, str(pk), str(tmp_path / "out")]) == 1
