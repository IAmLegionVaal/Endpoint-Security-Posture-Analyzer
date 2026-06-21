[CmdletBinding(SupportsShouldProcess=$true,ConfirmImpact='High')]
param(
 [switch]$EnableFirewall,
 [switch]$EnableDefender,
 [switch]$DisableRemoteDesktop,
 [switch]$DisableSmb1,
 [ValidatePattern('^[A-Z]$')][string]$ResumeBitLocker,
 [switch]$RunQuickScan,
 [switch]$DryRun,
 [switch]$Yes,
 [string]$OutputPath=(Join-Path $env:ProgramData 'EndpointSecurityPostureRepair')
)
$ErrorActionPreference='Stop';$script:Failures=0;$script:Actions=0
$run=Join-Path $OutputPath (Get-Date -Format yyyyMMdd_HHmmss);New-Item -ItemType Directory $run -Force|Out-Null
$log=Join-Path $run 'repair.log';$before=Join-Path $run 'before.json';$after=Join-Path $run 'after.json'
function Log($m){"$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') $m"|Tee-Object -FilePath $log -Append}
function Admin{$p=[Security.Principal.WindowsPrincipal]::new([Security.Principal.WindowsIdentity]::GetCurrent());$p.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)}
function State{[pscustomobject]@{Collected=Get-Date;Firewall=Get-NetFirewallProfile|Select-Object Name,Enabled;Defender=Get-MpComputerStatus -ErrorAction SilentlyContinue|Select-Object AntivirusEnabled,RealTimeProtectionEnabled,QuickScanAge;Rdp=(Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server').fDenyTSConnections;Smb=Get-SmbServerConfiguration|Select-Object EnableSMB1Protocol,EnableSMB2Protocol;BitLocker=Get-BitLockerVolume -ErrorAction SilentlyContinue|Select-Object MountPoint,VolumeStatus,ProtectionStatus}}
function Act($d,[scriptblock]$a){$script:Actions++;Log $d;if($DryRun){Log "DRY-RUN: $d";return};try{&$a;Log "SUCCESS: $d"}catch{$script:Failures++;Log "FAILED: $d - $($_.Exception.Message)"}}
State|ConvertTo-Json -Depth 6|Set-Content $before -Encoding UTF8
if(-not($EnableFirewall -or $EnableDefender -or $DisableRemoteDesktop -or $DisableSmb1 -or $ResumeBitLocker -or $RunQuickScan)){Write-Error 'Choose at least one repair action.';exit 2}
if(-not $DryRun -and -not(Admin)){Write-Error 'Run from elevated PowerShell.';exit 4}
if(-not $Yes -and -not $DryRun){if((Read-Host 'Apply selected endpoint security repairs? Type YES') -ne 'YES'){Log 'Cancelled.';exit 10}}
if($EnableFirewall){Act 'Enabling Windows Firewall profiles' {Set-NetFirewallProfile -Profile Domain,Private,Public -Enabled True}}
if($EnableDefender){Act 'Enabling Microsoft Defender real-time monitoring' {Set-MpPreference -DisableRealtimeMonitoring $false}}
if($RunQuickScan){Act 'Starting Microsoft Defender quick scan' {Start-MpScan -ScanType QuickScan}}
if($DisableRemoteDesktop){Act 'Disabling Remote Desktop connections' {Set-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server' fDenyTSConnections 1;Get-NetFirewallRule -DisplayGroup 'Remote Desktop' -ErrorAction SilentlyContinue|Disable-NetFirewallRule}}
if($DisableSmb1){Act 'Disabling SMB1 and enabling SMB2' {Set-SmbServerConfiguration -EnableSMB1Protocol $false -EnableSMB2Protocol $true -Force}}
if($ResumeBitLocker){$mount="${ResumeBitLocker}:";$v=Get-BitLockerVolume -MountPoint $mount -ErrorAction Stop;if($v.ProtectionStatus -ne 'On'){Act "Resuming BitLocker on $mount" {Resume-BitLocker -MountPoint $mount}}}
Start-Sleep 2;State|ConvertTo-Json -Depth 6|Set-Content $after -Encoding UTF8
if($script:Failures){exit 20};Log "Repair completed. Actions: $script:Actions";exit 0
