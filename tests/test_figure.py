import make_figure as m

ROWS = [
    {"name": "a", "version": "1", "patched": 5, "unpatched": 3, "ignored": 0, "other": 0},
    {"name": "b", "version": "2", "patched": 0, "unpatched": 1, "ignored": 0, "other": 0},
    {"name": "c", "version": "3", "patched": 9, "unpatched": 0, "ignored": 0, "other": 0},
]


def test_plots_only_packages_with_unpatched_in_ascending_order(tmp_path):
    out = tmp_path / "f.png"
    assert m.plot(ROWS, str(out)) == ["b", "a"]
    assert out.read_bytes()[:4] == b"\x89PNG"


def test_load_rows_converts_counts_to_int(tmp_path):
    p = tmp_path / "p.csv"
    p.write_text("name,version,patched,unpatched,ignored,other\nx,1,2,3,4,5\n")
    r = m.load_rows(str(p))[0]
    assert (r["patched"], r["unpatched"], r["ignored"], r["other"]) == (2, 3, 4, 5)
