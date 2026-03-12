# Credential Dumping — Investigation Walkthrough

## Investigator Perspective

This investigation begins from a Defender alert for a known credential dumping tool.
Unlike the previous case studies where Splunk provided the initial detection signal,
this attack was caught entirely by Defender's antivirus and behavioral engines before
any SIEM telemetry was generated. The investigation demonstrates how to work backward
from a prevention event to reconstruct attacker intent and assess scope.

## Step 1 — Initial Alert

A Medium severity Defender alert fired on CLIENT01:

**"An active 'DumpLsass' hacktool in a command line was prevented from executing"**

- Device: client01
- User: CORP\Administrator
- Category: Credential Access
- Detection status: **Blocked**
- MITRE ATT&CK: T1003.001 — LSASS Memory
- Detection source: Antivirus
- Detection technology: Client, Heuristic

The alert status is **Blocked** rather than Detected — meaning the tool was prevented
from running, not just flagged. This is the best possible outcome for this threat type.

## Step 2 — Examine the Defender Timeline

The CLIENT01 device timeline was reviewed to establish the full sequence of events
around the alert time (8:38 PM, March 11, 2026).

<p align="center">
  <img src="https://github.com/SanaMochi/SOC-Home-Lab/blob/main/04_Incident_Case_Studies/03_Credential_Dumping/Screenshots/timeline.png" width=100% />
</p>

Key events observed in chronological order:

| Time | Event | Significance |
|------|-------|-------------|
| 8:38:52 PM | Defender prevented execution of HackTool:Win32/DumpLsass.A | First prevention — procdump64.exe blocked |
| 8:38:52 PM | Defender prevented execution of HackTool:Win32/DumpLsass.A | Second prevention — PROCDU~1.EXE (8.3 name) also blocked |
| 8:39:51 PM | Detection of HackTool:Win32/DumpLsass.A by Antivirus | Signature confirmed |
| 8:39:51 PM | Detection of HackTool:Win32/DumpLsass.A by Antivirus | Second signature match |
| 8:39:51 PM | An active DumpLsass hacktool was prevented | Alert generated |
| 8:53:51 PM | powershell.exe observed using LSASS Memory technique | Behavioral detection |

Note: Defender detected both the full filename (procdump64.exe) and the 8.3 short
filename (PROCDU~1.EXE) — this is a common attacker evasion attempt that Defender
handles correctly by matching both representations.

## Step 3 — Review Prevention Details

The expanded prevention event confirmed the exact command the attacker attempted to run.

<p align="center">
  <img src="https://github.com/SanaMochi/SOC-Home-Lab/blob/main/04_Incident_Case_Studies/03_Credential_Dumping/Screenshots/proc_tree.png" width=100% />
</p>

| Field | Value |
|-------|-------|
| Threat name | HackTool:Win32/DumpLsass.A |
| Process command line | procdump64.exe -ma lsass.exe C:\Temp\lsass.dmp |
| Remediation action | remove |
| Remediation result | Success |
| Remediation time | Mar 11, 2026 8:38:52 PM |
| MITRE technique | T1003.001: LSASS Memory |

The `-ma` flag in the command line requests a full memory dump (all memory regions),
not just a minidump. This is the most comprehensive dump type and would have extracted
the maximum amount of credential material if it had succeeded.

The target output path `C:\Temp\lsass.dmp` reveals the attacker's staging location —
the same C:\Temp directory used in the previous encoded PowerShell attack, suggesting
a consistent working directory across this simulated attack chain.

## Step 4 — Check Splunk for Sysmon Event ID 10

Standard procedure for LSASS access attempts is to check Sysmon for Event ID 10
(ProcessAccess), which captures when a process opens a handle to another process.

```spl
index=sysmon EventCode=10 SourceImage="*procdump*" TargetImage="*lsass.exe"
| table _time host SourceImage TargetImage GrantedAccess
```

<p align="center">
  <img src="https://github.com/SanaMochi/SOC-Home-Lab/blob/main/04_Incident_Case_Studies/03_Credential_Dumping/Screenshots/splunk.png" width=100% />
</p>

**Result: 0 events**

This is the expected and correct finding. Sysmon Event ID 10 is generated when a process
successfully opens a handle to a target process. Since Defender terminated ProcDump at
the execution layer — before it could call OpenProcess() on lsass.exe — no handle was
ever opened and no Event ID 10 was generated.

This finding confirms the prevention was complete: the attacker gained zero access to
LSASS memory.

**Analyst note:** In environments without Defender prevention, or when an attacker uses
a more evasive tool, Sysmon Event ID 10 would be the primary detection signal. The
standard detection query for unprotected environments is:

```spl
index=sysmon EventCode=10 TargetImage="*lsass.exe"
| where NOT match(SourceImage, "(?i)MsMpEng|antimalware|defender|svchost")
| table _time host SourceImage TargetImage GrantedAccess CallTrace
| sort -_time
```

The exclusion of MsMpEng.exe (Defender) is necessary because Defender itself legitimately
accesses LSASS for protection purposes and would otherwise generate significant noise.

## Step 5 — Confirm Attack Execution Attempt

The terminal output from the attacker's session confirms the attempt was made and blocked.

<p align="center">
  <img src="https://github.com/SanaMochi/SOC-Home-Lab/blob/main/04_Incident_Case_Studies/03_Credential_Dumping/Screenshots/cli.png" width=90% />
</p>

The sequence visible in the terminal:
1. ProcDump downloaded via `Invoke-WebRequest` from Sysinternals
2. Archive extracted to C:\Temp\procdump
3. `procdump64.exe -ma lsass.exe C:\Temp\lsass.dmp` executed
4. Error: "Program 'procdump64.exe' failed to run: Access is denied"

The access denied error is Defender's prevention response. The attacker receives no
useful output and no credential material.

## Step 6 — Timeline Reconstruction

| Time | Event | Source | Detail |
|------|-------|--------|--------|
| ~8:25 PM | ProcDump downloaded and extracted | Terminal | Invoke-WebRequest + Expand-Archive |
| 8:38:52 PM | procdump64.exe execution attempted | Terminal | -ma lsass.exe C:\Temp\lsass.dmp |
| 8:38:52 PM | Defender blocks execution x2 | Defender AV | HackTool:Win32/DumpLsass.A — both filename variants |
| 8:38:52 PM | Binary removed by Defender | Defender | Remediation action: remove, result: success |
| 8:39:51 PM | Alert generated | Defender | Medium severity, Blocked, T1003.001 |
| — | Sysmon Event ID 10 | Sysmon | Not generated — handle never opened |

## Step 7 — Key Investigation Questions Answered

**Did the attacker successfully dump LSASS?**
No. Defender terminated ProcDump before it opened a handle to lsass.exe. No dump file
was created at C:\Temp\lsass.dmp.

**How was it detected?**
Signature-based detection — Defender matched procdump64.exe to the known signature
HackTool:Win32/DumpLsass.A. Both the full filename and 8.3 short filename were matched,
preventing a basic evasion attempt.

**Why is there no Sysmon Event ID 10?**
Sysmon logs process handle access, which requires the process to reach the OpenProcess()
system call. Defender killed ProcDump at execution, before any handle was opened.

**What would have happened without Defender?**
A successful LSASS dump would have produced a .dmp file containing NTLM hashes and
Kerberos tickets for all accounts that authenticated on CLIENT01 — including domain
admin credentials if any admin had logged in. Sysmon Event ID 10 with
GrantedAccess 0x1FFFFF would have been the detection signal.

**Is there risk of residual persistence?**
Low. ProcDump is a standalone tool with no persistence mechanism. Defender confirmed
the binary was removed. The attacker's working directory C:\Temp should be reviewed
for any other staged files from the broader attack chain.

## Step 8 — Recommended Response Actions

1. **Investigate** how ProcDump was downloaded — `Invoke-WebRequest` to Sysinternals
   suggests outbound internet access from CLIENT01, which may violate network policy
2. **Review** the full CLIENT01 timeline for the session — multiple PowerShell scripts
   executed before this attempt suggest an active hands-on attacker session
3. **Pivot** to other endpoints — check if ProcDump or similar tools were downloaded
   on DC01 or other machines in the environment
4. **Harden** by blocking outbound access to sysinternals.com from endpoints, or
   implement an application control policy blocking unsigned or unapproved executables
5. **Enable** LSA Protection (RunAsPPL) on all endpoints — this prevents even
   privileged processes from reading LSASS memory without a signed kernel driver
