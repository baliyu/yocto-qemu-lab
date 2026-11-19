# yocto-qemu-lab

A Yocto Project 6.0 ("Wrynose") `core-image-minimal` for `qemux86-64`, built on WSL2 and booted in QEMU, with what its SBOM and CVE report contain set beside the hand-made SBOM from my [mcuboot-lab](https://github.com/baliyu/mcuboot-lab).

Built with AI assistance (Claude). I chose the project, ran every command and build myself, wrote predictions with percentages before each run, and kept the misses. The scripts and documents were drafted with Claude and checked by me. This is a learning project on my own PC. It is not a security assessment of Yocto or of any product.

## Results

Every number below comes from a script in `scripts/` run on the real files, and the output is in `results/`.

| Area | Result | Where |
|---|---|---|
| The image | `core-image-minimal` for `qemux86-64`. The resumed build finished with all 4,349 tasks attempted and all succeeded (after the failure described below). It boots in QEMU under KVM to a Poky 6.0.4 login prompt with a 6.18.59 kernel | docs/SETUP.md |
| Yocto image SBOM | SPDX 3.x JSON, 46.8 MB: 257 packages, 37,122 files, 292 vulnerability elements | results/sbom_counts.json |
| MCUboot SBOM (mine) | SPDX 2.3 tag-value, 2,511 bytes: 5 package entries (2 image entries and 3 components), 0 files, 7 relationships | results/sbom_counts.json |
| CVE report | 36 packages scanned, 20 with database matches: 22,246 Patched, 145 Unpatched, 112 Ignored; 10 packages carry Unpatched matches, and `linux-yocto` holds 116 of the 145 | results/totals.json, results/packages.csv |
| My predictions | 113 rows: 75 hit, 31 missed, 7 not scored; 70.8% of scored predictions came true against a mean stated chance of 72.2% (102 rows with a stated chance) | results/scorecard_totals.json |

Figures: `results/fig_unpatched_by_package.png`, `results/fig_sbom_scale.png`, `results/fig_calibration.png`.

The two SBOMs are not like for like, and the comparison says why: [docs/COMPARISON.md](docs/COMPARISON.md).

## What went wrong, and is kept

The build was killed by a laptop restart at task 3875 of 4349 and left six zero-byte object files, which failed the final link of `gcc`. `runqemu` refused the setup's machine fragment, then the compressed image, and then the first root login. Each cause and fix is in [docs/SETUP.md](docs/SETUP.md). 31 of my predictions missed, and every miss has a note in [docs/scorecard.csv](docs/scorecard.csv).

## Limits

- One image, one machine, one build, one day. The vulnerability databases were fetched on 18 November 2026 at their latest revision, so another day gives different counts.
- "Unpatched" means a database match with no fix recorded. I have not triaged the 145, so none of them is a confirmed vulnerability. The kernel list includes very old entries, and the 22,246 "Patched" figure is a count of matched database entries, not a count of risks.
- The scorecard was rebuilt from my record of the session, one row per stated prediction. Earlier predictions that are not in that record are missing from it, and some stated chances are blank because I did not have them. The predictions are not independent: several misses share one cause.
- The image has an empty root password for QEMU testing. It is a lab image and must never go on a real device.
- Not done: running the image on real hardware, and reasoning about which kernel CVEs apply to this kernel configuration.

## Reproduce

Setup, commands and timings: [docs/SETUP.md](docs/SETUP.md). The analysis uses a Python venv with `requirements.txt`:

```
python -m pytest -q
python scripts/analyze_manifest.py MANIFEST.sbom-cve-check.yocto.json results
python scripts/make_figure.py results/packages.csv results/fig_unpatched_by_package.png
python scripts/sbom_counts.py IMAGE.spdx.json mcuboot-lab.spdx results
python scripts/scorecard.py docs/scorecard.csv results
```

The 34 MB manifest and the 47 MB SPDX file are not in this repository. `results/totals.json` and `results/sbom_counts.json` record their file names, sizes and SHA-256 hashes.
