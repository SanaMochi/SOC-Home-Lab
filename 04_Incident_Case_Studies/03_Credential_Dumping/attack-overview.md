# Case Study 03 — Credential Dumping (LSASS Memory Access)

## Attack Summary

Credential dumping via LSASS memory access is one of the most impactful post-exploitation
techniques available to an attacker. The Windows Local Security Authority Subsystem Service
(lsass.exe) holds authentication material in memory — including NTLM password hashes,
Kerberos tickets, and in older configurations, plaintext passwords. By reading LSASS memory,
an attacker can extract credentials for every account that has authenticated on that machine,
enabling immediate lateral movement and privilege escalation without touching the network.

In this simulation, ProcDump (a legitimate Microsoft Sysinternals tool) was used to attempt
a full memory dump of lsass.exe. Microsoft Defender for Endpoint detected and blocked the
attempt before the dump could complete, identifying ProcDump by signature as
HackTool:Win32/DumpLsass.A. This case study documents both the attack attempt and the
full defensive response across multiple detection layers.

## Why Attackers Use This Technique

- Extracts credentials for every account that has authenticated on the machine
- NTLM hashes can be used directly in Pass-the-Hash attacks without cracking
- Kerberos tickets enable Pass-the-Ticket and Golden Ticket attacks
- ProcDump is a signed Microsoft tool — historically trusted by security products
- Mimikatz is now widely detected; ProcDump is commonly used as a living-off-the-land alternative
- Credentials obtained enable lateral movement to high-value targets including domain controllers

## Attack Chain Position

Credential dumping occurs after initial access and local execution are established:

Initial Access → Execution → **Credential Access** → Lateral Movement → Privilege Escalation

MITRE ATT&CK: T1003.001 — OS Credential Dumping: LSASS Memory

## Simulation Details

| Field | Value |
|-------|-------|
| Source Host | CLIENT01 (192.168.113.20) |
| Attacker Account | CORP\Administrator |
| Tool Used | ProcDump64 (Microsoft Sysinternals) |
| Command | procdump64.exe -ma lsass.exe C:\Temp\lsass.dmp |
| Target Process | lsass.exe |
| Outcome | Blocked by Defender before execution completed |
| Dump File Created | No — process terminated before memory access |

## Detection vs Prevention

This simulation produced a **prevention** rather than a detection-only outcome. Defender
identified ProcDump by signature before it could open a handle to LSASS memory, terminated
the process, and removed the binary. This demonstrates an important distinction:

- **Detection controls** identify malicious activity and alert — the attack may still succeed
- **Prevention controls** stop the attack before it completes — the attacker gets nothing

| Control Layer | Outcome |
|--------------|---------|
| Sysmon Event ID 10 | Not generated — process killed before handle opened |
| Defender AV signature | HackTool:Win32/DumpLsass.A matched and blocked |
| Defender behavioral | T1003.001 LSASS Memory technique flagged |
| Remediation action | Binary removed, execution blocked, alert generated |

## Telemetry Sources

| Source | Events Generated |
|--------|-----------------|
| Sysmon (Event ID 10) | None — prevention occurred at execution layer |
| Splunk sysmon index | Zero results for procdump → lsass access |
| Microsoft Defender for Endpoint | Medium alert, T1003.001, remediation success |
 