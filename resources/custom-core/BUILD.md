The custom source is WhiteDNS/mihomo commit
`05fb40f89637aa27d81b638bff765a6d57797cdb`:
https://github.com/WhiteDNS/mihomo/tree/05fb40f89637aa27d81b638bff765a6d57797cdb

`source-05fb40f89637.tar.gz` is an unmodified `git archive` of that commit,
including its GPL-3.0 license and exact Go module declarations/checksums.

Build from the repository root on Windows:

```powershell
git clone --no-checkout https://github.com/WhiteDNS/mihomo.git .tools/custom-core
git -C .tools/custom-core checkout --detach 05fb40f89637aa27d81b638bff765a6d57797cdb
./scripts/build-custom-core.ps1 -GoExecutable C:/path/to/go/bin/go.exe
```

Use a compatible Go 1.26 toolchain. The build performed during this investigation
uses the maintainer's patched Go 1.26 distribution, reporting Go1.26.10. The exact
archive digest, compiler executable digest, compiler version, source commit,
target flags, tests and output hashes are recorded in `build-manifest.json` after
a successful build. The Android APK reported Go1.26.8; these are compatible
desktop builds, not byte-identical Android library reproductions.

The script keeps dependency/build caches under `.tools`, verifies module content,
runs the source's Fragment and OpenVPN certificate identity tests, then builds standalone Windows and Linux amd64
CLI executables with CGO disabled, `with_gvisor`, baseline `GOAMD64=v1` and
`-trimpath`. Windows can execute/test the Windows output; the Linux executable
is cross-compiled and must additionally be tested on Ubuntu. The custom CLI
uses Mihomo's regular HTTP controller; the FlClash wrapper is not included.

Local development also checked malformed fragment rejection and observed TLS
record rewriting plus staged writes through a CONNECT tunnel to a local TCP
receiver. That investigation helper and raw output remain outside the public
repository. The application integration tests in `tests/` use local fixtures and
do not change the system proxy or routing.

The desktop patch also adds `verify-x509-name` / `verify-x509-name-type` to the
OpenVPN outbound. CA chain, validity and server-authentication EKU validation run
before an exact (`name`) or prefix (`name-prefix`) match against the leaf CN.
Local Go tests generate temporary certificates and cover matching names, rejected
names, prefix matching and an untrusted CA. The binary manifest advertises
`supportsOpenVPNIdentity`; the app verifies the executable SHA256 before enabling
profiles with this constraint. No fixture private keys are distributed.
