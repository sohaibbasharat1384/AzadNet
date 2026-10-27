$ErrorActionPreference='Stop'
$projectRoot=Split-Path -Parent $PSScriptRoot
$builtRoot=Join-Path $projectRoot 'resources\custom-core'
foreach($target in @('windows','linux')){
  $targetIsWindows=$target -eq 'windows'
  $sourceFile=Join-Path $builtRoot $(if($targetIsWindows){'mihomo-windows-amd64.exe'}else{'mihomo-linux-amd64'})
  $metadataFile=Join-Path $builtRoot "$target-build.json"
  $metadata=Get-Content -LiteralPath $metadataFile -Raw | ConvertFrom-Json
  $actual=(Get-FileHash -LiteralPath $sourceFile -Algorithm SHA256).Hash.ToLower()
  if($actual -ne $metadata.sha256){throw "Core identity mismatch: $target"}
  $targetRoot=Join-Path $projectRoot $(if($targetIsWindows){'resources\core'}else{'resources\linux-core'})
  New-Item -ItemType Directory -Force -Path $targetRoot | Out-Null
  Copy-Item -LiteralPath $sourceFile -Destination (Join-Path $targetRoot $(if($targetIsWindows){'mihomo.exe'}else{'mihomo'}))
  $json=$metadata | ConvertTo-Json -Depth 8
  [IO.File]::WriteAllText((Join-Path $targetRoot 'build.json'),$json,[Text.UTF8Encoding]::new($false))
}
Write-Output 'Verified platform cores staged.'
