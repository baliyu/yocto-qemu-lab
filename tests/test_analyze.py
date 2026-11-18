import analyze_manifest as a

M = {"version": "1", "package": [
    {"name": "b", "version": "1", "issue": [{"status": "Patched"}, {"status": "Unpatched"}]},
    {"name": "a", "version": "2", "issue": [{"status": "Unpatched"}, {"status": "Unpatched"},
                                             {"status": "Ignored"}, {"status": "Weird"}]},
    {"name": "c", "version": "3"},
]}


def test_counts_per_package():
    rows = {r["name"]: r for r in a.summarise(M)}
    assert rows["a"]["unpatched"] == 2 and rows["a"]["ignored"] == 1 and rows["a"]["other"] == 1
    assert rows["b"]["patched"] == 1 and rows["b"]["unpatched"] == 1
    assert rows["c"]["patched"] == 0


def test_sorted_by_unpatched_then_name():
    assert [r["name"] for r in a.summarise(M)] == ["a", "b", "c"]


def test_totals():
    t = a.totals(a.summarise(M))
    assert t["packages"] == 3 and t["packages_with_unpatched"] == 2
    assert t["unpatched"] == 3 and t["patched"] == 1 and t["ignored"] == 1 and t["other"] == 1


def test_empty_manifest():
    assert a.summarise({}) == []
    assert a.totals([])["packages"] == 0
