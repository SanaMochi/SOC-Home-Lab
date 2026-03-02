# Detection Coverage Matrix

## Overview

This matrix maps implemented detections to:

- Windows Event Sources
- Sysmon Telemetry
- MITRE ATT&CK Techniques

## Detection Coverage Table

| Technique | Event ID / Signal | Data Source | Detection File |
|----------|--------------------|-------------|----------------|
| Brute Force | 4625 | Windows Security Log | brute-force-detection.md |
| Encoded PowerShell Execution | Sysmon Event ID 1 | Sysmon | encoded-powershell-detection.md |
| Privilege Escalation (Group Modification) | 4728 / 4729 | Windows Security Log | privilege-escalation-detection.md |
| Service Execution / Lateral Movement | 7045 | Windows System Log | service-creation-detection.md |
| Credential Dumping (LSASS Access) | Sysmon Event ID 10 | Sysmon | lsass-access-detection.md |

## MITRE ATT&CK Coverage

| Technique ID | Technique Name | Detection File |
|-------------|----------------|----------------|
| T1110 | Brute Force | brute-force-detection.md |
| T1059.001 | PowerShell | encoded-powershell-detection.md |
| T1098 | Account Manipulation | privilege-escalation-detection.md |
| T1569.002 | Service Execution | service-creation-detection.md |
| T1003.001 | LSASS Memory Access | lsass-access-detection.md |

## Detection Pipeline Model

The detections implemented in this lab simulate a realistic attack chain:

1. Initial Access – Brute Force
2. Execution – PowerShell
3. Privilege Escalation – Group Modification
4. Lateral Movement – Service Creation
5. Credential Access – LSASS Dumping

This layered structure mirrors real SOC detection workflows.
