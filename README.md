# AzadNet Desktop

Independent Persian desktop VPN/proxy client for Windows x64 and Ubuntu/Debian
amd64. Built with Electron and a pinned, patched Mihomo core. Current application
version: **0.2.1**.

[راهنمای فارسی](README.fa.md) · [تاریخچهٔ مراحل](CHANGELOG.fa.md) ·
[Runtime resources](resources/README.md) · [Third-party notices](THIRD_PARTY_NOTICES.md)

This is a community reconstruction informed by the supplied InternetAzad369
Android application and public WhiteVPN sources. It is not an official product
or a complete reproduction of every Android feature.

## Downloads

Use [v0.2.1, the latest desktop release](https://github.com/sohaibbasharat1384/AzadNet/releases/tag/v0.2.1).

| Platform | Package |
| --- | --- |
| Windows x64 | [Portable ZIP](https://github.com/sohaibbasharat1384/AzadNet/releases/download/v0.2.1/AzadNet-0.2.1-windows-x64.zip) |
| Ubuntu/Debian amd64 | [DEB installer](https://github.com/sohaibbasharat1384/AzadNet/releases/download/v0.2.1/azadnet_0.2.1_amd64.deb) |
| Linux x64 | [Portable tar.gz](https://github.com/sohaibbasharat1384/AzadNet/releases/download/v0.2.1/AzadNet-0.2.1-linux-x64.tar.gz) |

Verify downloads against [SHA256SUMS.txt](https://github.com/sohaibbasharat1384/AzadNet/releases/download/v0.2.1/SHA256SUMS.txt).
The four older releases retain their tagged source and change descriptions;
ready-to-run packages are provided only for the latest version.

Public packages omit the APK-derived GeoIP dataset and Python bytecode caches.
Without an optional compatible GeoIP dataset, IP-based Iran bypass is omitted;
domain/private-network rules still apply. See [resources/README.md](resources/README.md).

## Features

- Persian, right-to-left desktop interface; server selection, latency checks,
  traffic counters and a bounded HTTPS speed test through the local proxy.
- Clash YAML/JSON, Xray JSON, Base64 subscriptions and common connection URIs.
- HTTP/SOCKS5 local proxy, TUN routing, encrypted DNS and optional Iran bypass.
- Authenticated VPN proxy sharing on private IPv4 LAN interfaces.
- Fragment support using a hash-verified compatible custom core; manual IP
  fronting and Amnezia WireGuard options.
- Integration with an already activated official Windows installation. It calls
  the installed vendor checker; vendor license keys and server credentials are
  not distributed with this repository.
- Encrypted, installation-bound offline transfer to Ubuntu, retaining the
  original subscription expiry. This is local client interoperability, not a
  vendor-issued Linux license. Offline revocation before expiry cannot be checked.

## Development

Use Node.js 22, npm and Python 3.12 or newer. Desktop execution also needs Electron
and a staged core; unit tests do not require a core binary.

```sh
npm ci
npm test
npm start
```

On Electron installations without an automatically downloaded runtime, follow
the preparation instructions below before `npm start`.

The renderer is sandboxed with context isolation and uses a restricted IPC
bridge. Configuration import treats profiles as data rather than executable code.
Keep personal profiles and offline-transfer keys private: they contain the
credentials needed to use your own servers.

## Build Windows and Ubuntu packages

The packaging workflow currently runs on Windows/PowerShell. It creates a
Windows portable ZIP, a Linux tarball and an Ubuntu/Debian package. It verifies
downloaded Electron archives against their published SHA256 manifest.

```powershell
./scripts/prepare-build.ps1
git clone --no-checkout https://github.com/WhiteDNS/mihomo.git .tools/custom-core
git -C .tools/custom-core checkout --detach 05fb40f89637aa27d81b638bff765a6d57797cdb
./scripts/build-custom-core.ps1 -GoExecutable C:/path/to/compatible-go/bin/go.exe
./scripts/stage-custom-core.ps1
```

The core build needs a compatible Go 1.26 toolchain. See
[the recorded build identity](resources/custom-core/BUILD.md) for the exact
compiler used for the local builds, source pin and standalone desktop patch.
Then prepare the optional/required platform assets described in
[resources/README.md](resources/README.md) and run:

```powershell
python scripts/package.py
```

The packager deliberately refuses to overwrite an existing version directory.
Use a fresh build output directory or move the previous generated output before
rebuilding the same version. No compiled runtime binaries are tracked in Git.
The matching upstream core source archive, patch, manifests and licenses are
included for provenance and rebuilds.

To run local real-core integration tests after staging the Windows core:

```powershell
$env:AZADNET_TEST_REAL_CORE = '1'
node --test --test-concurrency=1 tests/*.test.cjs
```

## Runtime permissions

Local proxy mode listens on `127.0.0.1:2080` by default. Configure the browser or
application to use it; it does not automatically change the system proxy.

For Windows TUN, completely close the previous instance and run `AzadNet.exe`
with **Run as administrator**. An optional administrator launcher is generated
in Windows packages. The app verifies actual TUN startup and selected-server
HTTPS response before reporting a successful connection.

For Ubuntu TUN, install the generated `.deb`, run the following once after
installation or a core update, then launch the desktop application without sudo:

```sh
sudo /opt/azadnet/enable-tun.sh
```

The helper checks `/dev/net/tun` and grants network capabilities to the installed
core. The package depends on `libcap2-bin`; the Electron UI does not run as root.

## Validation and limits

The final local suite has **59 passing tests**, including real-core local
HTTP/SOCKS5 forwarding, license integration mocks, offline transfer integrity,
expiry enforcement and TUN failure regressions. A live Windows local-proxy HTTPS
download was also verified. The user reported successful operation of both
desktop versions; an automated Ubuntu runtime test was not performed here.

Complete imported routing groups/providers, automatic clean-IP scanning,
per-application split tunneling, camera QR import and a kill switch remain
unimplemented. A successful health check does not guarantee every destination
is reachable. The repository intentionally excludes personal profiles,
activation records, transfer bundles, private keys, raw reverse-engineering
output, APKs, caches, runtime executables and generated packages.

## History and license

The version commits were reconstructed from the actual `source/` snapshots
inside locally produced packages. They were committed when this public Git
repository was prepared; they are not backdated original development commits.
See [CHANGELOG.fa.md](CHANGELOG.fa.md) for the stages.

GPL-3.0; third-party components retain their own licenses. See [LICENSE](LICENSE)
and [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md).
