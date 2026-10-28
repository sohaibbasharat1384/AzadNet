# Runtime resources

Git tracks the small license/provenance files and the exact upstream core source
archive. Compiled cores, Wintun, Electron archives and GeoIP data remain local
build inputs. Obtain these before packaging a fresh checkout.

1. Run `scripts/prepare-build.ps1` to install npm dependencies, download both
   pinned Electron runtimes and verify their published checksums.
2. Build the pinned custom core with `scripts/build-custom-core.ps1` and run
   `scripts/stage-custom-core.ps1`. This creates:
   - `resources/core/mihomo.exe` and `build.json` for Windows;
   - `resources/linux-core/mihomo` and `build.json` for Linux.
3. For Windows TUN, obtain the official signed Wintun **0.14.1** archive from
   [wintun.net](https://www.wintun.net/), verify its SHA256 is
   `07c256185d6ee3652e09fa55c0b673e2624b565e02c4b9091c79ca7d2f24ef51`,
   and copy its AMD64 `wintun.dll` into `resources/core/`. Its redistribution
   license is included in `licenses/Wintun-LICENSE.txt`.
4. Optionally supply a compatible Mihomo `GEOIP.dat` in both `resources/core/`
   and `resources/linux-core/`. Without it the client omits the GeoIP-based Iran
   bypass rule; domain-based and explicit private-network rules still work.
   Obtain data with known provenance and suitable redistribution terms.
5. Build the official Windscribe tunnel helper from the pinned clean commit:
   `git clone https://github.com/Windscribe/wstunnel.git .tools/windscribe-wstunnel`,
   `git -C .tools/windscribe-wstunnel checkout --detach e6c325eed099e746ee98f80de7b827e942416d20`,
   then run `scripts/build-windscribe-tunnel.ps1` with the Go toolchain. This emits
   Windows/Linux binaries and their hash manifests under `resources/windscribe/`.
   The packager requires the platform binary to match its manifest and includes
   the unmodified source archive and license. Linux helper mode is executable.

The local development packages used GeoIP data from the supplied Android APK.
That dataset's upstream provenance was not established, so it is not published
in this source repository. The packager excludes it from new runtime packages as
well; add your own compatible dataset after installation if desired. No original
APK or vendor activation code is included.

Recorded manifests describe the locally built artifacts, which are not tracked
in Git. A fresh build regenerates manifests for the actual output; the app only
enables custom Fragment support when the staged executable matches its manifest.
See [custom-core/BUILD.md](custom-core/BUILD.md) and
[../scripts/custom-core-desktop.patch](../scripts/custom-core-desktop.patch).
