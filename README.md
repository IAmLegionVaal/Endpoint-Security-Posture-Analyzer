# Endpoint Security Posture Analyzer

A read-only PowerShell toolkit that summarizes important Windows endpoint security controls.

## Coverage

- Operating-system and device context
- Microsoft Defender status
- Windows Firewall profiles
- BitLocker, TPM, and Secure Boot
- Local administrator membership summary
- Windows Update recency
- PowerShell logging configuration
- SMB and Remote Desktop status
- Prioritized findings and a simple posture score

## Run

```powershell
powershell.exe -ExecutionPolicy Bypass -File .\Endpoint_Security_Posture_Analyzer.ps1
```

## Output

CSV findings, JSON evidence, HTML report, and supporting inventory files.

## Safety

Read-only reporting. No endpoint settings are changed.
