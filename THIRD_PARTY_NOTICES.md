# Third-party components and source identity

AzadNet Desktop is an independent local reconstruction, licensed under GPL-3.0. It is not an official release of InternetAzad369 or WhiteVPN.

* Electron 45.0.0: MIT and Chromium third-party licenses, included in each runtime distribution. Source: https://github.com/electron/electron/tree/v45.0.0 . Runtime downloads verified against the official SHASUMS256.txt.
* YAML 2.9.1: ISC, included in resources/licenses/YAML-LICENSE. Source: https://github.com/eemeli/yaml . npm integrity recorded in package-lock.json.
* Mihomo public baseline v1.19.30: GPL-3.0. Windows download SHA256 289fde5e29d37a5b3326480590d8b3551c5bf7f8737290355c19bce74d57a563; Linux download db214c7a2517e63c150d123178d16d102e03a241ccdae4e5e07ffbe9cf56c6f9. Source: https://github.com/MetaCubeX/mihomo/tree/v1.19.30 . The baseline does not implement the APK's custom fragments.
* Compatible custom core source: WhiteDNS/mihomo commit 05fb40f89637aa27d81b638bff765a6d57797cdb, GPL-3.0. Source: https://github.com/WhiteDNS/mihomo/tree/05fb40f89637aa27d81b638bff765a6d57797cdb . Corresponding source archive is included when this core is bundled. See core/build.json for the actual binary SHA256 and build identity. Build script: scripts/build-custom-core.ps1.
* WhiteVPN-Desktop source was consulted for protocol mappings and the pinned custom-core identity. GPL-3.0: https://github.com/WhiteDNS/WhiteVPN-Desktop . The supplied Android APK's Go VCS revision matches its pinned FlClash revision 8f08f6e2d732c58bcbb9d13771af4456c039fe46; this does not prove every app modification matches upstream.
* Vazirmatn font files extracted from the supplied APK: SIL Open Font License 1.1, included as resources/licenses/Vazirmatn-OFL.txt. Source: https://github.com/rastikerdar/vazirmatn . Font content was not modified.
* Wintun 0.14.1 signed AMD64 DLL: binary redistribution license included as resources/licenses/Wintun-LICENSE.txt. Official download SHA256 07c256185d6ee3652e09fa55c0b673e2624b565e02c4b9091c79ca7d2f24ef51. Source and signed builds: https://www.wintun.net/ . The driver is bundled for Windows TUN and was not installed during testing.
* Local runtime packages used GEOIP.dat extracted from the user-supplied APK (SHA256 6701aa3d9a9ea6c5e2026c8e73f199a9d6abe06257d9364e2bbf0874d5ccaa3f); its separate upstream data provenance has not been established. This dataset is excluded from the public source repository. See resources/README.md for optional compatible data inputs.

Runtime packages include the desktop source under source/. Analysis evidence and decompiled output remain in the local workspace and are excluded from the public repository and runtime packages. No original app credentials or license signing material are bundled. Compiled runtimes and drivers are excluded from Git; their recorded identities and applicable licenses remain available.

The shipped custom core restores standalone listener/TUN initialization through scripts/custom-core-desktop.patch. This patch is distributed with the application source; its SHA256 is recorded in core/build.json. The unmodified upstream source archive and the patch together describe the corresponding core source.
