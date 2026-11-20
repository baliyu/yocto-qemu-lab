# Userland CVE triage

The CVE report had 145 Unpatched matches. 116 are in `linux-yocto` and 29 are in nine other packages. This page covers the 29, which I triaged the way I triaged 7 advisories in mcuboot-lab: one status and one reason per row. The record is `docs/triage_userland.csv`. The kernel matches are not triaged.

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

## What I did not check

- Programs that load libraries at run time with `dlopen`. The import scan sees only static imports.
- Files outside `bin`, `sbin`, `lib`, `usr/bin`, `usr/sbin`, `usr/lib` and `usr/libexec`.
- Upstream patches and backports. glibc 2.43+git is a stable-branch snapshot and busybox 1.37.0 is older than the version NVD names, so version matching alone can mislead in both directions.
- Behaviour inside the running QEMU image.
- The 116 kernel matches.

One image, one build, one day. This is not a security assessment, and nothing was run on real hardware.

AI-assisted: drafted with Claude, checked by the author.
