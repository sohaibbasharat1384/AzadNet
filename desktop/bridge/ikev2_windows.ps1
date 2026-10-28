$ErrorActionPreference='Stop'
$ProgressPreference='SilentlyContinue'
[Console]::InputEncoding=[Text.UTF8Encoding]::new($false)
[Console]::OutputEncoding=[Text.UTF8Encoding]::new($false)
try {
  $taskInput=[Console]::In.ReadToEnd() | ConvertFrom-Json
  $taskName=[string]$taskInput.name
  if($taskName -notmatch '^AzadNet-Windscribe-[a-f0-9]{32}$'){throw 'Invalid owned profile identifier'}
  switch([string]$taskInput.operation){
    'available' {
      $taskReady=[bool](Get-Command Add-VpnConnection -ErrorAction SilentlyContinue)
      @{available=$taskReady} | ConvertTo-Json -Compress | Write-Output
    }
    'create' {
      if(Get-VpnConnection -Name $taskName -ErrorAction SilentlyContinue){throw 'Profile already exists'}
      $taskServer=[string]$taskInput.server
      if($taskServer -notmatch '^[A-Za-z0-9][A-Za-z0-9.-]{0,252}$'){throw 'Invalid server hostname'}
      [xml]$taskEap=@'
<EapHostConfig xmlns="http://www.microsoft.com/provisioning/EapHostConfig"><EapMethod><Type xmlns="http://www.microsoft.com/provisioning/EapCommon">26</Type><VendorId xmlns="http://www.microsoft.com/provisioning/EapCommon">0</VendorId><VendorType xmlns="http://www.microsoft.com/provisioning/EapCommon">0</VendorType><AuthorId xmlns="http://www.microsoft.com/provisioning/EapCommon">0</AuthorId></EapMethod><Config xmlns="http://www.microsoft.com/provisioning/EapHostConfig"><Eap xmlns="http://www.microsoft.com/provisioning/BaseEapConnectionPropertiesV1"><Type>26</Type><EapType xmlns="http://www.microsoft.com/provisioning/MsChapV2ConnectionPropertiesV1"><UseWinLogonCredentials>false</UseWinLogonCredentials></EapType></Eap></Config></EapHostConfig>
'@
      Add-VpnConnection -Name $taskName -ServerAddress $taskServer -TunnelType Ikev2 -AuthenticationMethod Eap -EapConfigXmlStream $taskEap -EncryptionLevel Maximum -SplitTunneling:$false -Force | Out-Null
      try {
        Set-VpnConnectionIPsecConfiguration -ConnectionName $taskName -AuthenticationTransformConstants GCMAES256 -CipherTransformConstants GCMAES256 -EncryptionMethod GCMAES256 -IntegrityCheckMethod SHA384 -DHGroup ECP384 -PfsGroup ECP384 -Force | Out-Null
      } catch {
        Remove-VpnConnection -Name $taskName -Force -ErrorAction SilentlyContinue
        throw
      }
      @{created=$true} | ConvertTo-Json -Compress | Write-Output
    }
    'connect' {
      $taskProfile=Get-VpnConnection -Name $taskName -ErrorAction Stop
      if($taskProfile.TunnelType -ne 'Ikev2'){throw 'Not an owned IKEv2 profile'}
      Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
public static class AzadNetRas {
 [StructLayout(LayoutKind.Sequential,CharSet=CharSet.Unicode)]
 public struct Params {
  public uint dwSize;
  [MarshalAs(UnmanagedType.ByValTStr,SizeConst=257)] public string entry;
  [MarshalAs(UnmanagedType.ByValTStr,SizeConst=129)] public string phone;
  [MarshalAs(UnmanagedType.ByValTStr,SizeConst=129)] public string callback;
  [MarshalAs(UnmanagedType.ByValTStr,SizeConst=257)] public string user;
  [MarshalAs(UnmanagedType.ByValTStr,SizeConst=257)] public string password;
  [MarshalAs(UnmanagedType.ByValTStr,SizeConst=16)] public string domain;
  public uint subEntry;
  public UIntPtr callbackId;
  public uint interfaceIndex;
 }
 [DllImport("rasapi32.dll",CharSet=CharSet.Unicode,ExactSpelling=true)]
 public static extern uint RasDialW(IntPtr extensions,string phonebook,ref Params parameters,uint notifierType,IntPtr notifier,out IntPtr connection);
}
'@
      $taskUser=[string]$taskInput.username
      $taskPassword=[string]$taskInput.password
      if(-not $taskUser -or -not $taskPassword -or $taskUser.Length -gt 256 -or $taskPassword.Length -gt 256 -or $taskUser -match '[\x00-\x1f]' -or $taskPassword -match '[\x00-\x1f]'){throw 'Invalid configuration credentials'}
      $taskParams=[AzadNetRas+Params]::new()
      $taskParams.dwSize=[Runtime.InteropServices.Marshal]::SizeOf($taskParams)
      $taskParams.entry=$taskName; $taskParams.phone=''; $taskParams.callback=''; $taskParams.user=$taskUser; $taskParams.password=$taskPassword; $taskParams.domain=''; $taskParams.subEntry=1
      $taskHandle=[IntPtr]::Zero
      $taskResult=[AzadNetRas]::RasDialW([IntPtr]::Zero,$null,[ref]$taskParams,0,[IntPtr]::Zero,[ref]$taskHandle)
      $taskParams.password=''; $taskPassword=''; $taskInput.password=''
      if($taskResult -ne 0){@{error='ikev2_connect_failed';code=$taskResult} | ConvertTo-Json -Compress | Write-Output; exit 0}
      for($taskTry=0;$taskTry -lt 20;$taskTry++){
        $taskState=Get-VpnConnection -Name $taskName -ErrorAction Stop
        if($taskState.ConnectionStatus -eq 'Connected'){break}
        Start-Sleep -Milliseconds 250
      }
      @{connected=($taskState.ConnectionStatus -eq 'Connected')} | ConvertTo-Json -Compress | Write-Output
    }
    'status' {
      $taskProfile=Get-VpnConnection -Name $taskName -ErrorAction SilentlyContinue
      @{connected=($taskProfile -and $taskProfile.ConnectionStatus -eq 'Connected')} | ConvertTo-Json -Compress | Write-Output
    }
    'stop' {
      $taskProfile=Get-VpnConnection -Name $taskName -ErrorAction SilentlyContinue
      if($taskProfile){
        if($taskProfile.TunnelType -ne 'Ikev2'){throw 'Not an owned IKEv2 profile'}
        & (Join-Path $env:SystemRoot 'System32/rasdial.exe') $taskName /disconnect *> $null
        for($taskTry=0;$taskTry -lt 40;$taskTry++){
          $taskState=Get-VpnConnection -Name $taskName -ErrorAction SilentlyContinue
          if(-not $taskState -or $taskState.ConnectionStatus -eq 'Disconnected'){break}
          Start-Sleep -Milliseconds 250
        }
        if($taskState -and $taskState.ConnectionStatus -ne 'Disconnected'){throw 'Native connection is still active'}
        Remove-VpnConnection -Name $taskName -Force -ErrorAction Stop
      }
      @{stopped=$true} | ConvertTo-Json -Compress | Write-Output
    }
    default {throw 'Unknown operation'}
  }
} catch {
  @{error='ikev2_system_operation_failed';kind=$_.Exception.GetType().Name} | ConvertTo-Json -Compress | Write-Output
}
