# CVE triage

The CVE report had 145 Unpatched matches. 116 are in `linux-yocto` and 29 are in nine other packages. I triaged all of them the way I triaged 7 advisories in mcuboot-lab: one status and one reason per row. The userland record is `docs/triage_userland.csv` and the kernel record is `docs/triage_kernel.csv`. The sections down to the results table cover the 29 userland rows, and the kernel rows have their own section after it.

## Statuses

- `affected`: the vulnerable code is present and some program in the image can reach it. It does not mean the flaw is exploitable in practice.
- `not_affected`: the vulnerable code or feature is not present or not reachable in this image. It does not mean the library is fixed. For example libcrypto is still 3.5.9, below the fixed 3.5.10.
- `unknown`: I could not settle it from the evidence I had. The reason says what is missing.

## Method

1. `scripts/triage_extract.py` pulls the 29 non-kernel Unpatched issues from the 34 MB manifest into a CSV template and fails if the per-package counts differ from the CVE report.
2. For each package I read the NVD summary, then checked the image: the image manifest, file listings of the root filesystem, the build configuration, the functions each program imports (`readelf` over 53 ELF files), and the source of the version in the image.
3. I wrote each status and reason into the CSV with a guarded script, with a backup restored on failure.
4. `scripts/triage_check.py` checks the CSV (columns, allowed statuses, a reason on every row, no duplicates) and compares the counts with `results/packages.csv`. It writes `results/triage_totals.json`.

## Results

| Package | Version | Rows | Status | What decided it |
|---|---|---|---|---|
| openssl | 3.5.9 | 12 | 12 not affected | libssl is not installed, which covers the QUIC, Suite B, DANE and DTLS rows. The other five are in libcrypto, whose only users here are kmod and libkmod, and they import none of the affected functions |
| glibc | 2.43+git | 5 | 1 affected, 3 not affected, 1 unknown | regcomp is used by busybox and kmod (affected). No wide scanf, no gconv modules, glob only in tar. gettext callers exist and the image is probably in the C locale (unknown) |
| busybox | 1.37.0 | 4 | 4 unknown | The awk, ash and archive applets are installed, but NVD names v1.38.0 and I did not compare the 1.37.0 code with the fix |
| acl | 2.3.2 | 2 | 1 affected, 1 not affected | tar imports the libacl pathname functions. getfacl and setfacl are not installed |
| attr | 2.5.2 | 1 | 1 not affected | The attr tools are not installed. getfattr is a link to busybox |
| tar | 1.35 | 2 | 2 affected | GNU tar is the installed tar and has both options named |
| util-linux | 2.41.6 | 1 | 1 not affected | No util-linux mount. `/bin/mount` is busybox |
| util-linux-libuuid | 2.41.6 | 1 | 1 not affected | Same CVE, and no libuuid files |
| zlib | 1.3.2 | 1 | 1 not affected | No file imports a gz write function |

Total: 4 affected, 20 not affected, 5 unknown (`results/triage_totals.json`).

## Kernel matches

The 116 `linux-yocto` rows rest on a different kind of evidence, because the kernel is one package built from one configuration. `scripts/triage_kernel.py` reads each CVE record from the cvelist database, which lists the affected kernel versions and the source files the fix touched. It checks 6.18.59 against the ranges, then checks the build of this kernel: is each source file compiled, and is it built in or a module. The record is `docs/triage_kernel.csv`. The rules, in order:

1. The record has no version ranges: `unknown`.
2. A range in the record lists 6.18.59 as unaffected (the flaw came later): `not_affected`. No row was settled this way. Every match that has a range is inside it.
3. Every named file is Rust or another architecture: `not_affected`.
4. The code is a module that is not in the image: `not_affected`. The root filesystem holds one module, `uvesafb.ko`.
5. The source file exists but has no object file in the build: `not_affected`.
6. The code is built into the kernel: `affected`. For device drivers (NVMe, USB, ACPI, framebuffer, serial, virtio net, CPU counters) it is `unknown`, because I did not check that this QEMU machine has the device.
7. The named file is not in the 6.18.59 source, or only headers are named: `unknown`.

For the kernel, `affected` means the version range includes 6.18.59 and the code is built into this kernel (or is a module that is in the image). It does not mean any program can reach it.

| What decided it | Rows | Status |
|---|---|---|
| Core code built into the kernel | 69 | affected |
| Module that is not in the image | 16 | not affected |
| Source file not compiled (EROFS, sched_ext) | 2 | not affected |
| Rust code, `CONFIG_RUST` absent | 1 | not affected |
| Code for another architecture | 1 | not affected |
| Device driver built in, hardware not checked | 12 | unknown |
| The record has no version ranges (old entries) | 13 | unknown |
| File not in the 6.18.59 source | 1 | unknown |
| Header files only | 1 | unknown |

Total: 69 affected, 20 not affected, 27 unknown (`results/triage_totals.json`). `scripts/triage_check.py` checks this file the same way as the userland one and compares the row count with the 116 in `results/packages.csv`.

## What I did not check

- Programs that load libraries at run time with `dlopen`. The import scan sees only static imports.
- Files outside `bin`, `sbin`, `lib`, `usr/bin`, `usr/sbin`, `usr/lib` and `usr/libexec`.
- Upstream patches and backports. glibc 2.43+git is a stable-branch snapshot and busybox 1.37.0 is older than the version NVD names, so version matching alone can mislead in both directions.
- Behaviour inside the running QEMU image.
- Kernel rows: whether the code marked `affected` can be reached from a running program, the kernel command line, or the devices this image has. The 69 is a count of built-in matches, many of them for features this small image never uses. It is not a count of risks.
- Kernel rows: backports. The version ranges are what each CVE record says, and a fix applied by a stable release that the record does not list is not seen.
- Kernel rows: the 12 device-driver rows, the 13 with no version data, and the 2 others left `unknown`.
- Kernel build evidence is one build: the object files and `built-in.a` lists in this build directory, and the one module in the root filesystem.

One image, one build, one day. This is not a security assessment, and nothing was run on real hardware.

AI-assisted: drafted with Claude, checked by the author.
