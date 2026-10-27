param([switch]$SkipDownloads)
$ErrorActionPreference='Stop'
$projectRoot=Split-Path -Parent $PSScriptRoot
Set-Location -LiteralPath $projectRoot
New-Item -ItemType Directory -Force -Path '.tools','resources\core','resources\linux-core' | Out-Null
$env:npm_config_cache=Join-Path $projectRoot '.cache\npm'
& npm.cmd ci --no-audit --no-fund
if($LASTEXITCODE -ne 0){throw 'npm ci failed'}
$electronVersion=(Get-Content -LiteralPath 'node_modules\electron\package.json' -Raw | ConvertFrom-Json).version
if(-not $SkipDownloads){
    $base="https://github.com/electron/electron/releases/download/v$electronVersion"
    & curl.exe -fL --retry 2 -o '.tools\electron-win.zip' "$base/electron-v$electronVersion-win32-x64.zip"
    if($LASTEXITCODE -ne 0){throw 'Windows runtime download failed'}
    & curl.exe -fL --retry 2 -o '.tools\electron-linux.zip' "$base/electron-v$electronVersion-linux-x64.zip"
    if($LASTEXITCODE -ne 0){throw 'Linux runtime download failed'}
    & curl.exe -fL --retry 2 -o '.tools\electron-SHASUMS256.txt' "$base/SHASUMS256.txt"
    if($LASTEXITCODE -ne 0){throw 'Runtime checksum download failed'}
}
foreach($entry in @(@('win32-x64','electron-win.zip'),@('linux-x64','electron-linux.zip'))){
    $name="electron-v$electronVersion-$($entry[0]).zip"
    $line=(Select-String -LiteralPath '.tools\electron-SHASUMS256.txt' -SimpleMatch "  $name").Line
    if(-not $line){throw "Missing checksum: $name"}
    $expected=($line -split '\s+')[0]
    $actual=(Get-FileHash -LiteralPath (Join-Path '.tools' $entry[1]) -Algorithm SHA256).Hash.ToLower()
    if($actual -ne $expected){throw "Runtime checksum mismatch: $name"}
}
Expand-Archive -LiteralPath '.tools\electron-win.zip' -DestinationPath 'node_modules\electron\dist' -Force
[IO.File]::WriteAllText((Join-Path $projectRoot 'node_modules\electron\path.txt'),'electron.exe')
Write-Output 'Electron dependencies ready. Build or stage the pinned custom cores before packaging.'
