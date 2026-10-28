# AzadNet Desktop

Independent Persian desktop VPN/proxy client for Windows x64 and Ubuntu/Debian
amd64. Built with Electron and a pinned, patched Mihomo core. Current application
version: **0.3.3** (local Windscribe CAPTCHA improvements; direct account login still fails with1337 for the reported real account; published downloads below are 0.2.1).

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

- A separate Windscribe provider with WireGuard, OpenVPN UDP, OpenVPN TCP,
  IKEv2, Stealth and WStunnel. Import your own generated configuration files;
  this does not sign in to, purchase or generate a Windscribe subscription.
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
git clone https://github.com/Windscribe/wstunnel.git .tools/windscribe-wstunnel
git -C .tools/windscribe-wstunnel checkout --detach e6c325eed099e746ee98f80de7b827e942416d20
./scripts/build-windscribe-tunnel.ps1 -GoExecutable C:/path/to/compatible-go/bin/go.exe
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

The tunnel build applies `scripts/windscribe-tunnel.patch` to the pinned source.
It keeps randomized TLS 1.3 hybrid groups consistent with their initial key
shares, avoiding uTLS 1.8.2 failures on HelloRetryRequest. A generated-spec test
covers both randomized ClientHello variants; the original source archive plus
this patch describe the shipped helper. The build restores its source checkout.

To run local real-core integration tests after staging the Windows core:

```powershell
$env:AZADNET_TEST_REAL_CORE = '1'
node --test --test-concurrency=1 tests/*.test.cjs
```

## Windscribe setup

Direct account login is on the Windscribe page. Enter your account
username/password in the **account** form, complete the provider's CAPTCHA
yourself if requested, and enter a six-digit 2FA code when required. Persian and
Arabic digits in the 2FA field are converted to ASCII. Login errors are not
automatically retried. The account summary shows plan, traffic and expiry when
the provider returns those fields.

Version 0.3.2 prefers the provider's image/puzzle CAPTCHA in a separate large
dialog. Move the handle yourself with the mouse, touch or arrow keys, then
confirm. Zoom controls and fit-to-width help with small screens. The app displays
the provider's original PNGs and forwards the user's chosen offset and actual
coordinate trail; it does not identify a target or generate a solution. Text
mode remains available with a monospace font, preserved spacing, scrolling and
zoom. **Fresh CAPTCHA** / the mode switch request another challenge only when
clicked. A rejected/expired CAPTCHA waits for that explicit action instead of
automatically retrying authentication. The original short-lived login challenge
deadline still applies.

Unknown provider errors now include a numeric code. Connection logs/export also
include bounded account diagnostics (operation, API code and HTTP status), without
usernames, passwords, session/security tokens, CAPTCHA content or raw response
messages. These diagnostics make further failures reviewable without credentials.

Version 0.3.3 separates AzadNet's version from the API compatibility reference
**2.25.5**, matching the
[pinned upstream integration configuration](https://github.com/Windscribe/Desktop-App/blob/c64bb6f46065a11a2bdbbfd880565e996ee57146/cmake/integrations/windscribe.cmake);
AzadNet's own version remains explicit in `User-Agent` and `X-AzadNet-Version`.
A negative request without a security token reached error708. This did **not**
validate the complete login path: the user subsequently reported1337 after a
manual CAPTCHA in0.3.3. The underlying incompatibility remains unresolved.
Source diagnostics now record only allowlisted provider-reason identifiers and
the login phase, without raw error bodies or credentials. No controls are disabled.

The account password is used only during login; it is not saved in settings or
logs. **Remember me** stores only the session token and an account identifier,
encrypted by Electron safeStorage. On Windows this uses DPAPI. On Linux a
working system secret store is required; the app refuses the `basic_text`
fallback and offers memory-only login instead. A restored session is checked
with the API before the UI calls it logged in. Tokens and connection credentials
are never returned in renderer state.

After login, **use connection credentials from the signed-in account** is
selected for OpenVPN UDP/TCP, IKEv2, Stealth and WStunnel. The main process fetches
the applicable OpenVPN/IKEv2 credentials when you import a configuration. You can
turn this off and enter configuration credentials manually. WireGuard still uses
the keys in its `.conf` file. Login does not automatically import server locations;
the generated file or IKEv2 hostname is still required, and access remains subject
to Windscribe's plan/location permissions. Imported VPN configuration credentials
remain in private profiles as before; they are separate from the account password.

**Log out** attempts to revoke the current API session and removes the locally
saved token. If remote revocation cannot be confirmed, the UI says so. Manually
imported profiles and their active connection remain available after account
logout; remove/disconnect them separately when desired.

The original interoperability code follows the public request/response contracts
in [Windscribe/wsnet 1.5.43](https://github.com/Windscribe/wsnet/tree/544a5365cf5123a73b344c69e7a393c81c8fb622)
and the public client-authentication parameters in
[Windscribe's extension SDK](https://github.com/Windscribe/browser-extension/blob/ed83749ad1a4163f24e39572fc9597a4091a0ee7/modules/ws-api-client/src/api/getMandatoryParams.ts).
The published client/signature salts are protocol constants, not a user's
credentials or a private developer API key. Requests identify this app as AzadNet,
use only HTTPS to `api.windscribe.com`, retain certificate validation, and refuse
redirects. This is not an official Windscribe client or a guaranteed stable API.

Open the **Windscribe** page and use its Config Generator button. Manual
configurations require an eligible paid Windscribe plan and access to the chosen
location. Use the generated configuration credentials, not your account password.
See [Windscribe's configuration generators](https://windscribe.com/features/config-generators).

| Mode | Input | Connection backend |
| --- | --- | --- |
| WireGuard | One or more native `.conf` files | Mihomo WireGuard |
| OpenVPN UDP / TCP | Matching `.ovpn` files plus configuration username/password | Mihomo OpenVPN |
| IKEv2 | Generator hostname and IKEv2 credentials | Windows user VPN / Ubuntu NetworkManager strongSwan |
| Stealth | OpenVPN TCP file, credentials, outer hostname/port and optional SNI | Official Windscribe tunnel helper, TLS mode |
| WStunnel | OpenVPN TCP file, credentials, outer hostname/port and optional SNI | Official Windscribe tunnel helper, WebSocket mode |

The app accepts up to 32 files at once. Reimporting the same profile filename
updates that profile and preserves its selected server name. Use different
filenames to retain the same location under multiple protocols. Script directives
and external credential/key paths are rejected; unsupported settings fail with
their line number rather than executing profile code.

WireGuard and OpenVPN modes use the existing local proxy or TUN settings.
IKEv2 always establishes a system VPN; Mihomo TUN is disabled for that connection.
Its system traffic does not follow the app's domain/Iran split rules, and the
displayed counters only cover the local proxy. Ubuntu needs NetworkManager,
`network-manager-strongswan`, `libcharon-extra-plugins`, Python 3 and `python3-dbus`;
the DEB declares these dependencies. Run the Electron interface without sudo.
Both native backends validate the server through the system certificate trust
store and only create/remove their own randomly named profile.

Stealth and WStunnel must point to an endpoint supporting that transport; a TCP
OpenVPN server is not automatically a TLS/WebSocket endpoint. The official helper
does not authenticate the outer TLS certificate. Authentication remains in the
inner OpenVPN CA/server certificate checks; the importer preserves inline CA and
`verify-x509-name` constraints, and the patched core enforces the name constraint.
The resolved outer address is excluded from TUN routing to prevent a tunnel loop.

Bulk latency tests skip unselected IKEv2/Stealth/WStunnel profiles so a test does
not change system VPN routes. Select and connect each such profile individually;
connection succeeds only after an HTTPS response through that selected route.
Windscribe profiles are independent of InternetAzad license expiry.

Validation used synthetic configs for all six import modes, mocked native VPN
lifecycle tests, actual local TLS/WebSocket byte transfers through the packaged
helper, real Mihomo local proxy tests, and an isolated Electron UI smoke test.
The login security-token preflight was also accepted by the real API with a
synthetic identifier; no password or account Session login was sent. No live
Windscribe credentials were supplied. Live account login/provider compatibility and
native IKEv2 on Windows/Ubuntu remain to be verified with a user's configuration;
the Linux executables were cross-compiled, not executed on this Windows host.

Optional local helper integration test (no provider account):

```powershell
go build -o .tools/windscribe-echo.exe tests/fixtures/windscribe-echo.go
$env:AZADNET_TEST_REAL_TUNNEL = '1'
$env:AZADNET_ECHO_FIXTURE = "$PWD/.tools/windscribe-echo.exe"
node --test tests/windscribe-runtime.test.cjs
node_modules/electron/dist/electron.exe tests/ui/windscribe-smoke.cjs
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
