param([string]$GoExecutable='', [string]$SourceDirectory='')
$ErrorActionPreference='Stop'
$taskRoot=Split-Path -Parent $PSScriptRoot
if(-not $GoExecutable){$GoExecutable=Join-Path $taskRoot '.tools/go/bin/go.exe'}
if(-not $SourceDirectory){$SourceDirectory=Join-Path $taskRoot '.tools/windscribe-wstunnel'}
$taskPin='e6c325eed099e746ee98f80de7b827e942416d20'
$taskPatch=Join-Path $taskRoot 'scripts/windscribe-tunnel.patch'
if((-not (Test-Path -LiteralPath $GoExecutable)) -or (-not (Test-Path -LiteralPath (Join-Path $SourceDirectory 'go.mod')))){throw 'Go compiler and pinned Windscribe/wstunnel source are required.'}
$taskCommit=(& git -C $SourceDirectory rev-parse HEAD).Trim()
if($LASTEXITCODE -ne 0 -or $taskCommit -ne $taskPin -or (& git -C $SourceDirectory status --porcelain)){throw 'Tunnel source must be clean at the pinned commit.'}
$taskOutput=Join-Path $taskRoot 'resources/windscribe'
New-Item -ItemType Directory -Force -Path $taskOutput | Out-Null
$taskEnv=@{GOTOOLCHAIN='local';CGO_ENABLED='0';GOARCH='amd64';GOAMD64='v1';GOOS='windows';GOPATH=(Join-Path $taskRoot '.tools/go-work');GOMODCACHE=(Join-Path $taskRoot '.tools/go-mod-cache');GOCACHE=(Join-Path $taskRoot '.tools/go-cache');GOTMPDIR=(Join-Path $taskRoot '.tools/go-temp');GOPROXY='https://proxy.golang.org|direct';GOSUMDB='sum.golang.org';GOFLAGS='-mod=readonly'}
$taskSaved=@{}
foreach($taskKey in $taskEnv.Keys){$taskSaved[$taskKey]=[Environment]::GetEnvironmentVariable($taskKey,'Process');[Environment]::SetEnvironmentVariable($taskKey,$taskEnv[$taskKey],'Process')}
New-Item -ItemType Directory -Force -Path $env:GOTMPDIR | Out-Null
Push-Location -LiteralPath $SourceDirectory
$taskPatched=$false
try {
  & git apply --check $taskPatch
  if($LASTEXITCODE -ne 0){throw 'Tunnel patch does not apply cleanly.'}
  & git apply $taskPatch
  if($LASTEXITCODE -ne 0){throw 'Tunnel patch failed.'}
  $taskPatched=$true
  & $GoExecutable mod download
  if($LASTEXITCODE -ne 0){throw 'Dependency download failed.'}
  & $GoExecutable mod verify
  if($LASTEXITCODE -ne 0){throw 'Dependency verification failed.'}
  $taskLicenseRoot=Join-Path $taskRoot 'resources/licenses/Windscribe-Tunnel-dependencies'
  New-Item -ItemType Directory -Force -Path $taskLicenseRoot | Out-Null
  $taskModules=@()
  foreach($taskDependencyTarget in @('windows','linux')){
    $env:GOOS=$taskDependencyTarget
    $taskModules+=& $GoExecutable list -deps '-f={{with .Module}}{{.Path}}|{{.Version}}|{{.Dir}}{{end}}' '.'
    if($LASTEXITCODE -ne 0){throw 'Dependency inventory failed.'}
  }
  $env:GOOS='windows'
  $taskModules=@($taskModules | Where-Object {$_} | Sort-Object -Unique)
  $taskLicenseIndex=@()
  foreach($taskModule in $taskModules){
    $taskParts=$taskModule.Split('|')
    if($taskParts[0] -eq 'github.com/Windscribe/wstunnel'){continue}
    if(-not $taskParts[2]){throw 'Dependency source directory missing.'}
    $taskLicenseName=($taskParts[0]+'@'+$taskParts[1]) -replace '[^A-Za-z0-9._@-]','_'
    $taskLicenseDirectory=Join-Path $taskLicenseRoot $taskLicenseName
    New-Item -ItemType Directory -Force -Path $taskLicenseDirectory | Out-Null
    $taskLicenseFiles=@(Get-ChildItem -LiteralPath $taskParts[2] -File | Where-Object {$_.Name -match '^(LICENSE|COPYING|NOTICE)'} )
    if(-not $taskLicenseFiles.Count){throw "Dependency license missing: $($taskParts[0])"}
    foreach($taskLicenseFile in $taskLicenseFiles){Copy-Item -LiteralPath $taskLicenseFile.FullName -Destination $taskLicenseDirectory}
    $taskLicenseIndex+=@{module=$taskParts[0];version=$taskParts[1];directory=$taskLicenseName;files=@($taskLicenseFiles.Name)}
  }
  ConvertTo-Json -InputObject $taskLicenseIndex -Depth 5 | Set-Content -LiteralPath (Join-Path $taskLicenseRoot 'index.json') -Encoding utf8
  & $GoExecutable test './cli' '-run' 'TestAzadNetRandomizedHybridShares' '-count=1'
  if($LASTEXITCODE -ne 0){throw 'TLS compatibility tests failed.'}
  foreach($taskTarget in @('windows','linux')){
    $env:GOOS=$taskTarget
    $taskPlatform=Join-Path $taskOutput $taskTarget
    New-Item -ItemType Directory -Force -Path $taskPlatform | Out-Null
    $taskName=if($taskTarget -eq 'windows'){'windscribe-tunnel.exe'}else{'windscribe-tunnel'}
    $taskBinary=Join-Path $taskPlatform $taskName
    & $GoExecutable build '-p=2' '-trimpath' '-buildvcs=true' '-ldflags=-w -s' '-o' $taskBinary '.'
    if($LASTEXITCODE -ne 0){throw "Tunnel build failed for $taskTarget."}
    $taskIdentity=@{schemaVersion=1;sourceRepo='https://github.com/Windscribe/wstunnel.git';sourceCommit=$taskPin;platform=$taskTarget;arch='amd64';compiler=((& $GoExecutable version).Trim());sha256=(Get-FileHash -LiteralPath $taskBinary -Algorithm SHA256).Hash.ToLowerInvariant();cgoEnabled=$false;tunnelPatchSha256=(Get-FileHash -LiteralPath $taskPatch -Algorithm SHA256).Hash.ToLowerInvariant();tlsCompatibilityTestsPassed=$true}
    $taskIdentity | ConvertTo-Json | Set-Content -LiteralPath (Join-Path $taskPlatform 'build.json') -Encoding utf8
    Write-Output "Windscribe tunnel built: $taskTarget"
  }
  & git archive '--format=tar.gz' "--output=$(Join-Path $taskOutput 'source-e6c325eed099.tar.gz')" $taskPin
  if($LASTEXITCODE -ne 0){throw 'Source archive failed.'}
  Copy-Item -LiteralPath 'LICENSE' -Destination (Join-Path $taskRoot 'resources/licenses/Windscribe-Tunnel-LICENSE.txt')
} finally {
  if($taskPatched){& git apply --reverse $taskPatch;if($LASTEXITCODE -ne 0){Write-Warning 'Tunnel source patch could not be reversed; inspect the build checkout.'}}
  Pop-Location
  foreach($taskKey in $taskSaved.Keys){[Environment]::SetEnvironmentVariable($taskKey,$taskSaved[$taskKey],'Process')}
}
