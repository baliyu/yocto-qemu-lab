import json

import sbom_counts as s

G = {"@context": "x", "@graph": [
    {"type": "software_Package"}, {"type": "software_Package"},
    {"type": "software_File"}, {"type": "software_File"}, {"type": "software_File"},
    {"type": "security_Vulnerability"},
]}
T = ("SPDXVersion: SPDX-2.3\nPackageName: a\nPackageName: b\nPackageName: c\n"
     "Relationship: x DESCRIBES y\nRelationship: y CONTAINS z\n")


def test_spdx3_counts(tmp_path):
    p = tmp_path / "a.json"
    p.write_text(json.dumps(G))
    r = s.count_spdx3(str(p))
    assert (r["packages"], r["files"], r["vulnerability_elements"], r["elements"]) == (2, 3, 1, 6)


def test_spdx3_without_graph_is_zero(tmp_path):
    p = tmp_path / "b.json"
    p.write_text("{}")
    assert s.count_spdx3(str(p))["packages"] == 0


def test_spdx2_counts_and_version(tmp_path):
    p = tmp_path / "c.spdx"
    p.write_text(T)
    r = s.count_spdx2(str(p))
    assert (r["packages"], r["relationships"], r["files"]) == (3, 2, 0)
    assert r["format"] == "SPDX-2.3 tag-value"


def test_plot_writes_png(tmp_path):
    y = {"packages": 5, "files": 9}
    m = {"packages": 1, "files": 0}
    out = tmp_path / "f.png"
    s.plot(y, m, str(out))
    assert out.read_bytes()[:4] == b"\x89PNG"
