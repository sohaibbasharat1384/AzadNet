param(
  [string]$GoExecutable = '',
  [string]$SourceDirectory = '',
  [switch]$SkipTests
)
$ErrorActionPreference = 'Stop'
$workspacePath = Split-Path -Parent $PSScriptRoot
if (-not $GoExecutable) { $GoExecutable = Join-Path $workspacePath '.tools\go\bin\go.exe' }
if (-not $SourceDirectory) { $SourceDirectory = Join-Path $workspacePath '.tools\custom-core' }
$sourceCommit = '05fb40f89637aa27d81b638bff765a6d57797cdb'
$sourceRepo = 'https://github.com/WhiteDNS/mihomo.git'
$outputDirectory = Join-Path $workspacePath 'resources\custom-core'
if (-not (Test-Path -LiteralPath $GoExecutable)) { throw "Go compiler missing: $GoExecutable. Use a compatible Go1.26 toolchain; do not install globally." }
if (-not (Test-Path -LiteralPath (Join-Path $SourceDirectory 'go.mod'))) { throw "Missing source: clone $sourceRepo at $sourceCommit into $SourceDirectory" }
$actualCommit = (& git -C $SourceDirectory rev-parse HEAD).Trim()
if ($LASTEXITCODE -ne 0 -or $actualCommit -ne $sourceCommit) { throw "Source identity must be exactly $sourceCommit" }
if ((& git -C $SourceDirectory status --porcelain)) { throw 'Pinned source must be clean before a build' }
$desktopPatch=Join-Path $PSScriptRoot 'custom-core-desktop.patch'
& git -C $SourceDirectory apply --check $desktopPatch
if ($LASTEXITCODE -ne 0) { throw 'Desktop listener patch does not match pinned source' }
New-Item -ItemType Directory -Force -Path $outputDirectory | Out-Null
$savedEnvironment = @{}
$buildEnvironment = @{
  GOTOOLCHAIN = 'local'; CGO_ENABLED = '0'; GOARCH = 'amd64'; GOAMD64 = 'v1'; GOOS = 'windows';
  GOPATH = (Join-Path $workspacePath '.tools\go-work');
  GOMODCACHE = (Join-Path $workspacePath '.tools\go-mod-cache');
  GOCACHE = (Join-Path $workspacePath '.tools\go-cache');
  GOTMPDIR = (Join-Path $workspacePath '.tools\go-temp');
  GOPROXY = 'https://proxy.golang.org|direct'; GOSUMDB = 'sum.golang.org'; GOFLAGS = '-mod=readonly';
}
foreach ($key in $buildEnvironment.Keys) {
  $savedEnvironment[$key] = [Environment]::GetEnvironmentVariable($key, 'Process')
  [Environment]::SetEnvironmentVariable($key, $buildEnvironment[$key], 'Process')
}
New-Item -ItemType Directory -Force -Path $env:GOTMPDIR | Out-Null
$compilerVersion = (& $GoExecutable version).Trim()
  $version = 'v1.19.30-azadnet-windscribe-05fb40f89637'
try {
  Push-Location $SourceDirectory
  try {
    & git apply $desktopPatch
    if ($LASTEXITCODE -ne 0) { throw 'Could not enable standalone desktop listeners' }
    & $GoExecutable mod download
    if ($LASTEXITCODE -ne 0) { throw 'Dependency download failed' }
    & $GoExecutable mod verify
    if ($LASTEXITCODE -ne 0) { throw 'Dependency verification failed' }
    if (-not $SkipTests) {
      Write-Host 'Compiling and running fragment tests (parallelism 2)...'
      & $GoExecutable test '-p=2' '-tags=with_gvisor' './adapter/outbound' './transport/openvpn' '-run' 'Fragment|OpenVPN.*Identity' '-count=1' '-v'
      if ($LASTEXITCODE -ne 0) { throw 'Fragment runtime unit tests failed' }
    }
    foreach ($target in @('windows','linux')) {
      $env:GOOS = $target
      Write-Host "Building standalone core for $target/amd64..."
      $fileName = if ($target -eq 'windows') { 'mihomo-windows-amd64.exe' } else { 'mihomo-linux-amd64' }
      & $GoExecutable build '-p=2' '-tags=with_gvisor' '-trimpath' '-buildvcs=true' '-ldflags' "-X github.com/metacubex/mihomo/constant.Version=$version -w -s" '-o' (Join-Path $outputDirectory $fileName) '.'
      if ($LASTEXITCODE -ne 0) { throw "Build failed: $target/amd64" }
      $builtPath = Join-Path $outputDirectory $fileName
      & $GoExecutable version '-m' $builtPath | Set-Content -LiteralPath "$builtPath.buildinfo.txt" -Encoding utf8
      @{
        schemaVersion=1; sha256=(Get-FileHash -LiteralPath $builtPath -Algorithm SHA256).Hash.ToLowerInvariant();
        supportsFragments=$true; supportsOpenVPNIdentity=$true; sourceRepo=$sourceRepo; sourceCommit=$sourceCommit; compiler=$compilerVersion;
        version=$version; platform=$target; arch='amd64'; goamd64='v1'; cgoEnabled=$false;
        tags=@('with_gvisor'); fragmentTestsPassed=(-not $SkipTests); linuxExecutionVerified=$false;
        desktopPatchSha256=(Get-FileHash -LiteralPath $desktopPatch -Algorithm SHA256).Hash.ToLowerInvariant();
      } | ConvertTo-Json -Depth 4 | Set-Content -LiteralPath (Join-Path $outputDirectory "$target-build.json") -Encoding utf8
    }
    & git archive '--format=tar.gz' "--output=$(Join-Path $outputDirectory 'source-05fb40f89637.tar.gz')" $sourceCommit
    if ($LASTEXITCODE -ne 0) { throw 'Source archive export failed' }
    $artifacts = @('mihomo-windows-amd64.exe','mihomo-linux-amd64','source-05fb40f89637.tar.gz') | ForEach-Object {
      $artifactPath = Join-Path $outputDirectory $_
      @{file=$_; sha256=(Get-FileHash -LiteralPath $artifactPath -Algorithm SHA256).Hash.ToLowerInvariant(); bytes=(Get-Item -LiteralPath $artifactPath).Length}
    }
    @{
      schemaVersion=1; sourceRepo=$sourceRepo; sourceCommit=$sourceCommit;
      matchingAndroidWrapperCommit='8f08f6e2d732c58bcbb9d13771af4456c039fe46';
      compiler=$compilerVersion; version=$version; cgoEnabled=$false;
      desktopPatchSha256=(Get-FileHash -LiteralPath $desktopPatch -Algorithm SHA256).Hash.ToLowerInvariant();
      compilerExecutableSha256=(Get-FileHash -LiteralPath $GoExecutable -Algorithm SHA256).Hash.ToLowerInvariant();
      tags=@('with_gvisor'); goamd64='v1'; supportsFragments=$true; supportsOpenVPNIdentity=$true;
      fragmentTestsPassed=(-not $SkipTests); linuxExecutionVerified=$false;
      toolchainDistribution='https://github.com/MetaCubeX/go/releases/download/build/go1.26.windows-amd64.zip';
      toolchainArchiveSha256='2483b14ce111fa89ac671cdb00073c5b19670198be1334f491a8f3fe36affeb0';
      artifacts=$artifacts
    } | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath (Join-Path $outputDirectory 'build-manifest.json') -Encoding utf8
  } finally { & git apply -R $desktopPatch; Pop-Location }
} finally {
  foreach ($key in $savedEnvironment.Keys) { [Environment]::SetEnvironmentVariable($key, $savedEnvironment[$key], 'Process') }
}
