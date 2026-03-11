# Encoded PowerShell — Microsoft Defender for Endpoint Investigation

## Overview

Microsoft Defender for Endpoint generated a Medium severity alert for this attack,
making this the first case study in this lab where both Splunk and Defender independently
detected the same activity. The two tools provide complementary visibility — Splunk
captured the raw execution event in real time via Sysmon, while Defender performed
behavioral analysis and surfaced an enriched alert with automatic MITRE tagging and
decoded command line content.

## Defender Alert

**Alert:** Suspicious PowerShell download or encoded command execution  
**Severity:** Medium  
**Device:** CLIENT01  
**User:** CORP\Administrator  
**Detection technology:** Behavior  
**Detection source:** Microsoft Defender for Endpoint  

MITRE ATT&CK Techniques automatically applied:
- T1059.001 — Command and Scripting Interpreter: PowerShell
- T1027 — Obfuscated Files or Information
- T1078.002 — Valid Accounts: Domain Accounts
- T1057 — Process Discovery
- T1106 — Native API

<p align="center">
  <img src="https://github.com/SanaMochi/SOC-Home-Lab/blob/main/04_Incident_Case_Studies/02_Encoded_Powershell/Screenshots/alert.png" 
    width=100% />
</p>

## Process Tree Analysis

Defender captured the full process ancestry for both encoded PowerShell executions:

```
wt.exe [13640]
└── WindowsTerminal.exe [10360]
    └── powershell.exe [14248]
        ├── powershell.exe [5040]  -nop -w hidden -enc [Base64]
        │   └── ⚠ Suspicious PowerShell download or encoded command execution
        └── powershell.exe [8248]  -nop -w hidden -enc [Base64]
            └── ⚠ Suspicious PowerShell download or encoded command execution
```

The parent chain `wt.exe → WindowsTerminal.exe → powershell.exe` confirms interactive
execution by a logged-in user via Windows Terminal. The child PowerShell processes
spawned with encoded flags are the malicious executions.

## Defender Auto-Decoded Command Line

A standout capability visible in this investigation: Defender automatically decoded
the Base64 command line and displayed both versions in the alert details.

<p align="center">
  <img src="https://github.com/SanaMochi/SOC-Home-Lab/blob/main/04_Incident_Case_Studies/02_Encoded_Powershell/Screenshots/process_tree.png" 
    width=100% />
</p>

| Field | Value |
|-------|-------|
| Command line (encoded) | VwByAGkAdABlAC0ATwB1AHQAcAB1... |
| Command line (decoded) | Write-Output 'Simulated malicious payload executed' \| Out-File C:\Temp\payload_executed.txt |
| Process ID | 8248 |
| Execution details | Token elevation: Default, Integrity level: High |
| Signer | Microsoft Windows (legitimate binary) |
| VirusTotal | 0/71 |

The automatic decoding means that even without manually running the decode step in
PowerShell, Defender surfaces the plaintext payload directly in the alert. This
significantly accelerates triage — an analyst can confirm what the command did in
seconds rather than having to copy the string and decode it manually.

The VirusTotal score of 0/71 is expected and worth understanding — this is a benign
simulation payload. In a real attack, a novel payload would also likely score 0/71
on VirusTotal initially. Low VT scores do not indicate benign activity and should
never be used as the sole indicator of safety.

## Splunk vs Defender — Complementary Visibility

| Capability | Splunk (Sysmon) | Defender |
|------------|----------------|---------|
| Process creation captured | Event ID 1, real time | Via behavioral engine |
| Full CommandLine logged | Raw field in event | With auto-decode |
| Automatic Base64 decode | Manual decode required | Done automatically |
| MITRE technique tagging | Analyst must apply | Automatic |
| Alert generated | None - Detection only | Medium severity alert |
| Parent process chain | ParentImage field | Visual process tree |
| Response actions | None - Detection only | Isolate, scan, collect |

This attack demonstrates a case where Defender adds meaningful value beyond what
Splunk provides alone — specifically the automatic decode and behavioral alert.
In a real SOC, the Defender alert would be the initial notification, with Splunk
used for broader environment-wide hunting to determine if the same payload executed
elsewhere.

## Key Observations for This Attack

**Defender decoded the payload automatically.** This is not always the case — more
sophisticated obfuscation (double-encoded, XOR-encoded, or fragmented payloads) can
evade automatic decoding. Analysts should always be capable of manual decoding.

**Both executions were detected.** Defender caught both the full-flag variant and the
abbreviated `-nop -w hidden -enc` variant, confirming its detection logic covers
common abbreviations.

## MITRE ATT&CK Mapping

| Tactic | Technique | ID | Evidence |
|--------|-----------|-----|---------|
| Execution | Command and Scripting Interpreter: PowerShell | T1059.001 | powershell.exe with encoded command, High integrity |
| Defense Evasion | Obfuscated Files or Information | T1027 | Base64 encoding of command payload |
| Defense Evasion | Obfuscated Files or Information | T1027 | -WindowStyle Hidden, -NonInteractive flags |
| Privilege Escalation / Defense Evasion | Valid Accounts: Domain Accounts | T1078.002 | Execution as CORP\Administrator |
| Discovery | Process Discovery | T1057 | Defender observed process enumeration in LSASS dump file |
| Execution | Native API | T1106 | Defender detected direct Native API calls by PowerShell |
