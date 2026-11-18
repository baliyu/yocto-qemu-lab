# Setup, timeline and problems

Built with AI assistance (Claude); checked by the author. Commands are the ones I ran, shown as they were used.

## Environment

- Windows PC with WSL2 Ubuntu 24.04.3. The build lives in the Linux home folder, not under `/mnt/c`.
- WSL limits raised for the build (`config/wslconfig.txt`): 10 GB memory and 16 GB swap. The WSL machine then showed 9 GB RAM and 8 threads.
- Yocto Project 6.0 "Wrynose", set up with `bitbake-setup` using the `poky-wrynose` configuration and the fragments `distro/poky` and `machine/qemux86-64`. The `poky` repository itself stops at an older release, so the Wrynose layers come from `openembedded-core` and `bitbake`.
- Build settings I added to `build/conf/local.conf` are in `config/local.conf.additions`: 6 parallel jobs, and (later) the lab-only root login features.
- Yocto commands run with a clean `PATH` (`/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin`) and `LANG=en_US.UTF-8`, because the conda `python3`, `xz` and other tools on my usual `PATH` shadow the system ones.

## Commands

```
bitbake core-image-minimal
bitbake-config-build enable-fragment core/yocto/sbom-cve-check
runqemu core-image-minimal-qemux86-64.rootfs.qemuboot.conf nographic slirp snapshot
```

`runqemu` needs the `.qemuboot.conf` file path, and `snapshot` because the image is compressed (`.ext4.zst`). The `snapshot` mode boots from a temporary copy, so the build output is not changed.

## Timeline (17 and 18 November 2026, local time, from build log file times)

| When | What |
|---|---|
| 17 Nov 22:18 | First build started (4,349 tasks) |
| 18 Nov 04:58 | First build log stops here (build killed by a laptop restart for an update, at task 3875 of 4349) |
| 10:09 to 11:27 | Build resumed; `gcc do_compile` failed at the last link (this log stops at 11:27) |
| 13:00 | Six zero-byte object files deleted; build resumed |
| 15:42 | Build finished, all tasks succeeded |
| 17:08 to 17:28 | Four QEMU boot attempts; the fourth booted, logged in and powered down |
| 17:22 to 17:23 | Image rebuilt with root login enabled (between boots 3 and 4) |
| 17:34 to 18:52 | `sbom-cve-check` fragment enabled and rebuilt; CVE reports written (two database repositories of about 4.5 GB each were fetched first) |

## Problems and fixes

| Problem | Cause | Fix |
|---|---|---|
| `bitbake-setup init` failed on missing host tools | `pzstd`, `bzip2`, `lz4` and `xz` were being supplied by conda, not by Ubuntu | Installed `zstd`, `bzip2`, `lz4`, `xz-utils`; used the clean `PATH` |
| Build needs more RAM than WSL gave | WSL default of 7 GB | `.wslconfig` with 10 GB memory and 16 GB swap |
| `gcc do_compile` failed at link with undefined `print_gimple_stmt` | The kill left six zero-byte object files (`gimple-pretty-print.o` and five more); `make` treated them as up to date | Deleted those six objects and resumed; `make` rebuilt only them |
| `runqemu` failed on `bitbake -e` | It sets `MACHINE` in the environment, and the `machine/qemux86-64` fragment refuses a value set that way | Gave `runqemu` the image's `.qemuboot.conf` path |
| `runqemu` refused the image | Compressed `.zst` images need snapshot mode | Added `snapshot` |
| `root` login refused (`Login incorrect`) | The image does not allow an empty root password by default | Added `empty-root-password allow-empty-password allow-root-login` to `EXTRA_IMAGE_FEATURES`; image-only rebuild log times 17:22 to 17:23 |
| No CVE report after the first build | Not enabled by default in this release | Enabled the `core/yocto/sbom-cve-check` fragment (it fetches the NVD and CVE List repositories at their latest revision) |
