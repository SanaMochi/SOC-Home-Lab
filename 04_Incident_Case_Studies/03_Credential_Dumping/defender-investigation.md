# Credential Dumping — Microsoft Defender for Endpoint Investigation

## Overview

This attack was stopped entirely by Microsoft Defender for Endpoint before any credential
material was accessed. Unlike the previous two case studies where Splunk provided the
primary detection signal, this case study demonstrates a scenario where the EDR is the
sole detection and response platform — Sysmon generated no Event ID 10, and Splunk
returned zero results for the attack.

This is a realistic scenario. In environments with strong endpoint protection, many
attacks are prevented before SIEM telemetry is generated. Knowing how to investigate
and document a prevention event is as important as investigating a successful attack.

## Defender Alert

**Alert:** An active 'DumpLsass' hacktool in a command line was prevented from executing  
**Severity:** Medium  
**Device:** CLIENT01  
**User:** CORP\Administrator  
**Category:** Credential Access  
**Detection status:** Blocked  
**Detection source:** Microsoft Defender for Endpoint  
**Detection technology:** Client, Heuristic  
**MITRE ATT&CK:** T1003.001 — LSASS Memory  

![Defender alert process tree and alert details panel](../screenshots/alert.png)

---

## Device Timeline Analysis

The CLIENT01 timeline was filtered to the attack window (8:38 PM, March 11, 2026).

![Full Defender CLIENT01 timeline showing detection and prevention sequence](../screenshots/timeline.png)

### Key Timeline Events

| Time | Event | Tag | Significance |
|------|-------|-----|-------------|
| 8:38:52 PM | Defender prevented execution of HackTool:Win32/DumpLsass.A | Malware | procdump64.exe blocked |
| 8:38:52 PM | Defender prevented execution of HackTool:Win32/DumpLsass.A | Malware | PROCDU~1.EXE (8.3 name) also blocked |
| 8:39:51 PM | Detection of HackTool:Win32/DumpLsass.A by Antivirus | — | Signature confirmed twice |
| 8:39:51 PM | An active DumpLsass hacktool was prevented | — | Alert generated |
| 8:53:51 PM | powershell.exe observed using LSASS Memory technique | T1003.001 | Behavioral detection logged |

### Notable Observation — Dual Filename Detection

Defender blocked the tool under two different filenames at the same timestamp:
- `procdump64.exe` — the actual filename
- `PROCDU~1.EXE` — the Windows 8.3 short filename representation

Attackers sometimes reference tools by their 8.3 short names to evade detections
that match only the full filename. Defender correctly identified and blocked both
representations, demonstrating robust signature coverage.

## Prevention Event Detail

The expanded prevention event shows the complete remediation record.

![Expanded Defender prevention events showing threat name, command line, and remediation](../screenshots/proc_tree.png)

### Remediation Details

| Field | Value |
|-------|-------|
| Threat name | HackTool:Win32/DumpLsass.A |
| Command line | procdump64.exe -ma lsass.exe C:\Temp\lsass.dmp |
| Is runtime packed | False |
| Remediation action | remove |
| Remediation result | Success |
| Remediation time | Mar 11, 2026 8:38:52 PM |
| MITRE technique | T1003.001: LSASS Memory |

The `-ma` flag confirms a full memory dump was requested — the most comprehensive
dump type, capturing all memory regions. A successful dump would have extracted
NTLM hashes and Kerberos tickets for every account that authenticated on CLIENT01.

## Attacker Terminal Evidence

The attacker's PowerShell session confirms the attempt and the prevention outcome.

![PowerShell terminal showing ProcDump download, extraction, and access denied error](../screenshots/cli.png)

The terminal shows:
1. ProcDump downloaded from live.sysinternals.com via `Invoke-WebRequest`
2. Archive extracted to C:\Temp\procdump
3. Command executed: `.\procdump64.exe -ma lsass.exe C:\Temp\lsass.dmp`
4. Result: "Program 'procdump64.exe' failed to run: Access is denied"

The access denied error is Defender's prevention response. The attacker receives
no credential material and no useful diagnostic information about why it failed.

## Multi-Layer Defense Analysis

This attack demonstrates defense-in-depth working as intended across multiple layers:

| Layer | Control | Outcome |
|-------|---------|---------|
| Network | Outbound web access allowed | ProcDump successfully downloaded — gap identified |
| Endpoint AV | Signature: HackTool:Win32/DumpLsass.A | Execution blocked |
| Endpoint behavioral | T1003.001 LSASS Memory heuristic | Behavioral alert generated |
| LSASS protection | Windows Defender Credential Guard | Provides additional protection layer |
| Sysmon | Event ID 10 monitoring | Not triggered — prevention was upstream |

**Gap identified:** The attacker was able to download ProcDump from the internet
directly to the endpoint. A network control blocking outbound access to
live.sysinternals.com (or all non-approved domains) from endpoints would have
stopped the attack at the delivery stage before Defender needed to act.

## Splunk vs Defender — This Attack

| Capability | Splunk | Defender |
|------------|--------|---------|
| LSASS access event (EID 10) | Not generated | N/A |
| Tool execution detected | Not in Sysmon EID 1 results | Signature match |
| Prevention action | Cannot prevent | Blocked and removed |
| Alert generated | No events to alert on | Medium severity alert |
| Command line captured | No process creation logged | Full command line in event |
| Remediation documented | Not applicable | Remove action confirmed |

This is the clearest example in this lab of Defender providing value that Splunk
alone cannot — not just detecting, but preventing, and doing so before the attack
generated any SIEM-visible telemetry.

## MITRE ATT&CK Mapping

| Tactic | Technique | ID | Evidence |
|--------|-----------|-----|---------|
| Credential Access | OS Credential Dumping: LSASS Memory | T1003.001 | ProcDump -ma targeting lsass.exe |
| Command and Control / Resource Development | Ingress Tool Transfer | T1105 | ProcDump downloaded via Invoke-WebRequest |
