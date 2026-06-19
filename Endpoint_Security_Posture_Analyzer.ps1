#requires -Version 5.1
[CmdletBinding()]
param([string]$OutputPath)

$stamp=Get-Date -Format 'yyyyMMdd_HHmmss'
if([string]::IsNullOrWhiteSpace($OutputPath)){$OutputPath=Join-Path ([Environment]::GetFolderPath('Desktop')) 'Endpoint_Security_Posture_Reports'}
New-Item -Path $OutputPath -ItemType Directory -Force|Out-Null

$findings=[System.Collections.Generic.List[object]]::new()
function Add-PostureFinding{param([string]$Area,[string]$Status,[string]$Detail,[int]$Weight)
    $findings.Add([PSCustomObject]@{Area=$Area;Status=$Status;Detail=$Detail;Weight=$Weight})
}

$os=Get-CimInstance Win32_OperatingSystem
$cs=Get-CimInstance Win32_ComputerSystem
$defender=Get-MpComputerStatus -ErrorAction SilentlyContinue
Add-PostureFinding 'Defender' $(if($defender.AntivirusEnabled -and $defender.RealTimeProtectionEnabled){'Pass'}else{'Review'}) "AV=$($defender.AntivirusEnabled); RealTime=$($defender.RealTimeProtectionEnabled)" 20

$firewall=Get-NetFirewallProfile -ErrorAction SilentlyContinue
$fwEnabled=@($firewall|Where-Object Enabled).Count
Add-PostureFinding 'Firewall' $(if($fwEnabled -eq @($firewall).Count){'Pass'}else{'Review'}) "Enabled profiles=$fwEnabled of $(@($firewall).Count)" 15

$tpm=Get-Tpm -ErrorAction SilentlyContinue
Add-PostureFinding 'TPM' $(if($tpm.TpmPresent -and $tpm.TpmReady){'Pass'}else{'Review'}) "Present=$($tpm.TpmPresent); Ready=$($tpm.TpmReady)" 10

$secureBoot=$null
try{$secureBoot=Confirm-SecureBootUEFI -ErrorAction Stop}catch{}
Add-PostureFinding 'Secure Boot' $(if($secureBoot -eq $true){'Pass'}elseif($null -eq $secureBoot){'Info'}else{'Review'}) "Enabled=$secureBoot" 10

$bitlocker=Get-BitLockerVolume -ErrorAction SilentlyContinue
$osVolume=$bitlocker|Where-Object VolumeType -eq 'OperatingSystem'|Select-Object -First 1
Add-PostureFinding 'BitLocker' $(if($osVolume.ProtectionStatus -eq 'On'){'Pass'}else{'Review'}) "OS volume protection=$($osVolume.ProtectionStatus)" 15

$admins=Get-LocalGroupMember -Group 'Administrators' -ErrorAction SilentlyContinue
Add-PostureFinding 'Local Administrators' 'Info' "Members=$(@($admins).Count)" 0

$latestHotfix=Get-HotFix -ErrorAction SilentlyContinue|Sort-Object InstalledOn -Descending|Select-Object -First 1
$recent=$false
if($latestHotfix.InstalledOn){$recent=$latestHotfix.InstalledOn -ge (Get-Date).AddDays(-45)}
Add-PostureFinding 'Update Recency' $(if($recent){'Pass'}else{'Review'}) "Latest=$($latestHotfix.HotFixID) on $($latestHotfix.InstalledOn)" 15

$psLog=Get-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging' -ErrorAction SilentlyContinue
Add-PostureFinding 'PowerShell Logging' $(if($psLog.EnableScriptBlockLogging -eq 1){'Pass'}else{'Review'}) "ScriptBlockLogging=$($psLog.EnableScriptBlockLogging)" 10

$smb1=Get-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -ErrorAction SilentlyContinue
Add-PostureFinding 'SMBv1' $(if($smb1.State -eq 'Disabled'){'Pass'}else{'Review'}) "State=$($smb1.State)" 5

$possibleScore=($findings|Measure-Object Weight -Sum).Sum
$earned=($findings|Where-Object Status -eq 'Pass'|Measure-Object Weight -Sum).Sum
$score=if($possibleScore -gt 0){[math]::Round(($earned/$possibleScore)*100,0)}else{0}
$summary=[PSCustomObject]@{Computer=$env:COMPUTERNAME;OS=$os.Caption;Build=$os.BuildNumber;Manufacturer=$cs.Manufacturer;Model=$cs.Model;PostureScore=$score;Pass=@($findings|Where-Object Status -eq 'Pass').Count;Review=@($findings|Where-Object Status -eq 'Review').Count;Generated=Get-Date}

$findings|Export-Csv (Join-Path $OutputPath "posture_findings_$stamp.csv") -NoTypeInformation -Encoding UTF8
$admins|Select-Object Name,ObjectClass,PrincipalSource,SID|Export-Csv (Join-Path $OutputPath "local_administrators_$stamp.csv") -NoTypeInformation -Encoding UTF8
$firewall|Select-Object Name,Enabled,DefaultInboundAction,DefaultOutboundAction|Export-Csv (Join-Path $OutputPath "firewall_profiles_$stamp.csv") -NoTypeInformation -Encoding UTF8
@{Summary=$summary;Findings=$findings;Administrators=$admins;FirewallProfiles=$firewall}|ConvertTo-Json -Depth 8|Set-Content (Join-Path $OutputPath "endpoint_posture_$stamp.json") -Encoding UTF8
$html="<h1>Endpoint Security Posture - $env:COMPUTERNAME</h1><p>Generated $(Get-Date)</p><h2>Summary</h2>$(@($summary)|ConvertTo-Html -Fragment)<h2>Findings</h2>$($findings|ConvertTo-Html -Fragment)"
$html|ConvertTo-Html -Title 'Endpoint Security Posture'|Set-Content (Join-Path $OutputPath "endpoint_posture_$stamp.html") -Encoding UTF8
$summary|Format-List
Write-Host "Reports saved to: $OutputPath" -ForegroundColor Green
