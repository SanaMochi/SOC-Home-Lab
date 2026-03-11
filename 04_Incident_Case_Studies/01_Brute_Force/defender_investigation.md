# Brute Force — Microsoft Defender for Endpoint Investigation

## Overview

While Splunk provided log-based detection of the brute force pattern, Microsoft Defender 
for Endpoint provided behavioral telemetry that revealed the execution context on the 
endpoint — specifically what was running on CLIENT01 at the time the failures were generated.

## Device Timeline Investigation

**Device:** CLIENT01  
**Time Window Investigated:** Mar 10, 2026 22:30–23:00

<p align="center">
  <img src="https://github.com/SanaMochi/SOC-Home-Lab/blob/main/04_Incident_Case_Studies/01_Brute_Force/Screenshots/defender.png" 
    width=110% />
</p>

### Key Timeline Events Observed

| Time | Event | User | Process Chain |
|------|-------|------|---------------|
| 22:56:10 | PowerShell ran command | corp\administrator | wt.exe → WindowsTerminal.exe → powershell.exe |
| 22:57:00 | Interactive logon succeeded | corp\asmith | window manager/dwm-10 |
| 22:57:00 | Logon using explicit credentials | NT AUTHORITY\SYSTEM | smss.exe → winlogon.exe |

### Process Tree Analysis

Defender captured the full process tree for the PowerShell execution:
```
wt.exe [452]
└── WindowsTerminal.exe [15780]
    └── powershell.exe [4024]
        └── PowerShell Command:
            Start-Process -FilePath "cmd.exe" -Credential $cred -ArgumentList "/c exit"
```

<p align="center">
  <img src="https://github.com/SanaMochi/SOC-Home-Lab/blob/main/04_Incident_Case_Studies/01_Brute_Force/Screenshots/process_tree.png" 
    width=50% />
</p>

**Key observations from process tree:**

- Parent process is Windows Terminal — indicates interactive admin session
- The captured command explicitly constructs a credential object (`$cred`) and passes 
  it to Start-Process — this is the exact pattern of a PowerShell-based credential 
  stuffing or brute force loop
- Running as corp\administrator — the attacker (or simulation) already had Administrator 
  access to CLIENT01 and was using it to test credentials for lateral movement

### Defender Behavioral Signals

Defender did not generate a dedicated brute force alert for this activity because the 
authentication attempts were local (loopback) rather than network-based. However the 
timeline captures:

- The PowerShell execution with credential manipulation
- The explicit credentials logon event
- The full process ancestry from terminal to command execution

In a real investigation, these Defender signals would be the pivot point from "we see 
failed logons in the SIEM" to "we know exactly what ran on the endpoint and who ran it."

## Splunk vs Defender — Complementary Visibility

| Capability | Splunk | Defender |
|------------|--------|---------|
| Failed logon count and pattern | Primary source | Not captured |
| Successful logon confirmation | Via 4624 events | Via timeline |
| What executed on the endpoint | Not available | Full process tree |
| Command line arguments | Not in auth logs | Captured verbatim |
| Who was logged in | Partial (account name) | Full user context |
| Response actions available | Detection only | Isolate, disable, contain |

This case study demonstrates why neither tool alone provides complete visibility. 
Splunk identified the pattern at scale across the environment. Defender revealed what 
was actually executing on the compromised machine.

## Response Capability

From the Defender portal, the following response actions are available directly from 
the CLIENT01 device page:

- **Isolate device** — immediately cuts CLIENT01 off from the network while preserving 
  Defender connectivity for continued investigation
- **Run antivirus scan** — scan for any malware dropped during the session
- **Collect investigation package** — pull forensic artifacts from the endpoint

In a confirmed compromise scenario, device isolation would be the first response action 
to prevent lateral movement using the successfully guessed credentials.

## MITRE ATT&CK Mapping

| Tactic | Technique | ID | Evidence |
|--------|-----------|-----|---------|
| Credential Access | Brute Force: Password Guessing | T1110.001 | 32 failed logons against jdoe |
| Execution | Command and Scripting Interpreter: PowerShell | T1059.001 | PowerShell credential loop captured by Defender |
