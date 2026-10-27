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

The local development packages used GeoIP data from the supplied Android APK.
That dataset's upstream provenance was not established, so it is not published
in this source repository. No original APK or vendor activation code is included.

Recorded manifests describe the locally built artifacts, which are not tracked
in Git. A fresh build regenerates manifests for the actual output; the app only
enables custom Fragment support when the staged executable matches its manifest.
See [custom-core/BUILD.md](custom-core/BUILD.md) and
[../scripts/custom-core-desktop.patch](../scripts/custom-core-desktop.patch).
