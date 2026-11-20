# Two SBOMs side by side

Built with AI assistance (Claude); checked by the author. Counts come from `results/sbom_counts.json` and `results/totals.json`. The two files were produced for different things, so this page compares what they contain and does not rank them.

| | mcuboot-lab SBOM (mine) | Yocto image SBOM |
|---|---|---|
| Format | SPDX 2.3 tag-value | SPDX 3.x JSON |
| Size | 2,511 bytes | 46,786,519 bytes |
| Package entries | 5 (2 image entries, 3 components: zephyr 4.4.2, hal_nordic, mcuboot) | 257 |
| Files listed | 0 | 37,122 |
| Licence data | every licence field is NOASSERTION | 152 licence expression elements |
| Vulnerability data inside the file | none | 292 vulnerability elements with VEX status |
| Version pinning | components pinned to a commit hash | recipe versions |
| How findings are produced | my checker asks OSV about the commit of each component | `sbom-cve-check` 1.3.5 matches package names and versions against NVD and the CVE List, fetched at build time |
| What I did with the findings | 7 advisories triaged with a reason each (`docs/triage.csv` in mcuboot-lab) | All 145 Unpatched matches triaged with a reason each (`docs/triage_userland.csv` for the 29 userland rows, `docs/triage_kernel.csv` for the 116 kernel rows) |

## What this shows

1. **Scale.** My SBOM lists the 3 components that compile code in a build whose manifest names 66 modules. The Yocto SBOM lists 257 packages, which includes build tools that never reach the image, and 37,122 source files. The CVE manifest covers 36 packages.
2. **The vulnerability numbers cannot be compared.** 7 triaged advisories and 145 matches (29 triaged, 116 not) come from different methods: commit lookups against OSV, and package-version matching against NVD and the CVE List. 7 against 145 says nothing about which build is safer.
3. **Gaps on each side.** My SBOM has no files and no licence data. The Yocto triage covers all 145 matches, but the 116 kernel statuses rest on version ranges and build files, and 27 of them stay unknown.

## Limits

One image and one build. I counted elements from the files and did not check them against the build itself. I did not change the scan scope setting; the common class defaults it to `target`.
