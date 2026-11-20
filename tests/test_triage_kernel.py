import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "scripts"))
import triage_kernel as tk  # noqa: E402


def sem(version, status, **kw):
    e = {"version": version, "status": status, "versionType": "semver"}
    e.update(kw)
    return e


def test_explicit_range_covering_the_version_is_a1():
    aff = [{"defaultStatus": "unaffected",
            "versions": [sem("6.18.53", "affected", lessThan="6.19")]}]
    v, ev = tk.version_verdict(aff)
    assert v == "A1" and "6.18.53" in ev


def test_introduced_earlier_with_later_fix_is_a2():
    aff = [{"defaultStatus": "unaffected", "versions": []},
           {"defaultStatus": "affected",
            "versions": [sem("5.7", "affected"), sem("0", "unaffected", lessThan="5.7"),
                         sem("6.18.60", "unaffected", lessThanOrEqual="6.18.*")]}]
    v, ev = tk.version_verdict(aff)
    assert v == "A2" and "6.18.60" in ev


def test_introduced_later_is_b():
    aff = [{"defaultStatus": "affected",
            "versions": [sem("6.19", "affected"), sem("0", "unaffected", lessThan="6.19")]}]
    assert tk.version_verdict(aff)[0] == "B"


def test_git_only_record_is_d():
    aff = [{"defaultStatus": "unaffected",
            "versions": [{"version": "a" * 40, "status": "affected", "versionType": "git"}]}]
    assert tk.version_verdict(aff)[0] == "D"


def test_fix_before_the_version_is_not_affected_range():
    aff = [{"defaultStatus": "affected",
            "versions": [sem("5.7", "affected"),
                         sem("6.18.50", "unaffected", lessThanOrEqual="6.18.*")]}]
    assert tk.version_verdict(aff)[0] == "B"


def test_core_code_built_in_is_affected():
    s, r = tk.classify("A2", "e", ["kernel/futex/core.c"], [("kernel/futex/core.c", "builtin", True)])
    assert s == "affected" and "built into this kernel" in r


def test_device_code_built_in_is_unknown():
    s, r = tk.classify("A2", "e", ["drivers/nvme/host/core.c"],
                       [("drivers/nvme/host/core.c", "builtin", True)])
    assert s == "unknown" and "NVMe" in r


def test_module_not_in_the_image_is_not_affected():
    s, r = tk.classify("A2", "e", ["fs/fuse/dev.c"], [("fs/fuse/dev.c", "module", True)],
                       rootfs_kos={"uvesafb.ko"}, dir_kos=lambda d: {"fuse.ko"})
    assert s == "not_affected" and "uvesafb.ko" in r and "FUSE_FS" in r


def test_module_in_the_image_is_affected():
    s, _ = tk.classify("A2", "e", ["fs/fuse/dev.c"], [("fs/fuse/dev.c", "module", True)],
                       rootfs_kos={"fuse.ko"}, dir_kos=lambda d: {"fuse.ko"})
    assert s == "affected"


def test_file_missing_from_the_source_is_unknown():
    s, r = tk.classify("A2", "e", ["kernel/bpf/fixups.c"], [("kernel/bpf/fixups.c", "none", False)])
    assert s == "unknown" and "does not exist" in r


def test_not_compiled_file_is_not_affected():
    s, r = tk.classify("A2", "e", ["fs/erofs/data.c"], [("fs/erofs/data.c", "none", True)])
    assert s == "not_affected" and "EROFS" in r


def test_other_architecture_and_rust_are_not_affected():
    assert tk.classify("A2", "e", ["arch/mips/Kconfig"], [])[0] == "not_affected"
    assert tk.classify("A2", "e", ["rust/kernel/irq.rs"], [])[0] == "not_affected"


def test_header_only_is_unknown():
    assert tk.classify("A2", "e", ["include/net/codel.h"], [])[0] == "unknown"


def test_no_version_ranges_is_unknown():
    assert tk.classify("D", "e", [], [])[0] == "unknown"
