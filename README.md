# Endpoint Security Posture Analyzer

PowerShell tools for summarising Windows endpoint security posture and applying guarded defensive repairs.

## Analyze

```powershell
powershell.exe -ExecutionPolicy Bypass -File .\Endpoint_Security_Posture_Analyzer.ps1
```

## Repair

```powershell
powershell.exe -ExecutionPolicy Bypass -File .\Endpoint_Security_Posture_Repair_Toolkit.ps1 -EnableFirewall -DryRun
```

Examples:

```powershell
.\Endpoint_Security_Posture_Repair_Toolkit.ps1 -EnableFirewall -EnableDefender
.\Endpoint_Security_Posture_Repair_Toolkit.ps1 -RunQuickScan
.\Endpoint_Security_Posture_Repair_Toolkit.ps1 -DisableRemoteDesktop
.\Endpoint_Security_Posture_Repair_Toolkit.ps1 -DisableSmb1
.\Endpoint_Security_Posture_Repair_Toolkit.ps1 -ResumeBitLocker C
```

The repair script captures firewall, Defender, RDP, SMB and BitLocker state before and after repair. It supports `-DryRun`, confirmation, logs and clear exit codes. Remote Desktop disablement may interrupt remote support sessions.

## Author

Dewald Pretorius — L2 IT Support Engineer
