# Case Study 02 — Encoded PowerShell Execution

## Attack Summary

Encoded PowerShell is one of the most common obfuscation techniques used by attackers
to hide malicious commands from casual inspection, endpoint defenses, and log analysis.
By Base64-encoding a command and passing it via the `-EncodedCommand` flag, an attacker
can execute arbitrary code without the plaintext payload ever appearing directly in a
process command line — unless the analyst knows to decode it.

In this simulation, a benign payload was Base64-encoded and executed using both the full
flag syntax (`-EncodedCommand`) and the abbreviated syntax (`-enc`), replicating two
common real-world variants. The payload wrote a file to disk to confirm execution.

## Why Attackers Use This Technique

- Hides the true intent of a command from basic log review
- Bypasses simple string-matching detections looking for keywords like "malware"
- Allows delivery of complex multi-line scripts as a single command line argument
- Combined with `-WindowStyle Hidden` and `-NonInteractive`, leaves no visible window
- Commonly used in phishing payload delivery, C2 execution, and post-exploitation stages

## Attack Chain Position

This technique typically appears after initial access has been established:

Initial Access → Execution → (Encoded PS delivers next stage) → Persistence / C2

MITRE ATT&CK: T1059.001 — Command and Scripting Interpreter: PowerShell  
MITRE ATT&CK: T1027 — Obfuscated Files or Information
MITRE ATT&CK: T1057 — Process Discovery  
MITRE ATT&CK: T1106 — Native API

## Simulation Details

| Field | Value |
|-------|-------|
| Source Host | CLIENT01 (192.168.113.20) |
| Attacker Account | CORP\Administrator |
| Execution Method | powershell.exe -EncodedCommand / -enc |
| Payload | Write-Output to C:\Temp\payload_executed.txt |
| Variants Executed | 2 (full flags + abbreviated flags) |
| Working Directory | C:\Temp |

## Obfuscation Flags Used

| Flag | Purpose |
|------|---------|
| `-NoProfile` | Skip loading PowerShell profile — faster, less logging |
| `-NonInteractive` | No user prompts — suitable for automated execution |
| `-WindowStyle Hidden` | No visible window — execution is invisible to the user |
| `-ExecutionPolicy Bypass` | Ignore execution policy restrictions |
| `-EncodedCommand` / `-enc` | Pass Base64-encoded command string |

## Telemetry Sources

| Source | Events Generated |
|--------|-----------------|
| Sysmon (Event ID 1) | Process creation with full CommandLine captured |
| Splunk (sysmon index) | Detection via CommandLine field matching |
| Microsoft Defender for Endpoint | Alert: Suspicious PowerShell download or encoded command execution |
