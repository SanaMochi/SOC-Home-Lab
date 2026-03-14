# Lateral Movement via PsExec Pattern — Microsoft Defender Investigation

## Overview

This attack generated **no meaningful Defender detection**. The DC01 device timeline
contained a single Defender event during the attack window — an AntivirusReport on
services.exe at 21:16:05 — which on closer inspection is unrelated background AV scanning
noise with no connection to the lateral movement activity. No alert was generated, no
process was blocked, and no behavioral detection fired.

This is a realistic and important outcome. The PsExec pattern works entirely within
legitimate Windows functionality: net use maps a share, sc.exe creates a service, and
the binary path runs cmd.exe. There is no malicious file to signature-match, no shellcode
to detect, and no exploit to block. EDR products have limited leverage against attacks
that are architecturally indistinguishable from legitimate administrative activity.

**The primary — and in this case only — detection layer for this attack is the SIEM.**

## Defender Timeline — DC01

The DC01 device timeline was reviewed for the full attack window (9:14 PM – 9:17 PM,
March 12, 2026).

<p align="center">
  <img src="https://github.com/SanaMochi/SOC-Home-Lab/blob/main/04_Incident_Case_Studies/05_Lateral_Movement/Screenshots/defender.png" width=100% />
</p>

| Time | Event | Action Type | Source |
|------|-------|-------------|--------|
| Mar 12, 2026 9:16:05 PM | Unknown process file observed on host | AntivirusReport | Microsoft Defender for Endpoint |
| Mar 12, 2026 8:02:03 AM | An account was added to the Domain Admins group | SentinelActivity | Microsoft Sentinel |

No service creation event, no network logon alert, no lateral movement detection.

## The 9:16:05 PM Event — Confirmed Unrelated Background Noise

The AntivirusReport event at 21:16:05 shares a one-second timestamp with the 7045 service
creation and was investigated for a possible connection.

| Field | Value | Significance |
|-------|-------|-------------|
| Event | Unknown process file observed on host | Generic AV scan notification |
| Action type | AntivirusReport | Background scan — not a behavioral detection |
| Entity | services.exe | The legitimate Windows Service Control Manager |
| Path | C:\Windows\System32 | Canonical system binary — not attacker-controlled |
| Child process | None captured | No execution event observed |
| Command line | Not captured | No process launch recorded |

The action type `AntivirusReport` distinguishes this from a genuine detection. Defender
generates AntivirusReports during routine scheduled or on-access scanning — they appear
in the timeline constantly as background activity. The entity being scanned is `services.exe`
from `C:\Windows\System32`, the legitimate Windows Service Control Manager that Defender
has baseline-profiled across millions of endpoints.

**Analyst note — correlation by timestamp is not causation.** The 21:16:05 AV scan and
the 21:16:04 service creation share a timestamp but have no causal link. The service
installation triggered the SCM (services.exe) to register the new service, which may have
prompted Defender to perform a background scan of services.exe itself — but this is routine
system activity that occurs constantly, not a detection of SimulatedPsExec or the cmd.exe
binary path. Defender did not observe or flag the service binary path content.

A less experienced analyst might record this as "Defender detected the service creation" —
which would be an incorrect finding. The correct conclusion is that Defender performed
routine background scanning on a system binary at approximately the same time as the
attack event.

## Why Defender Did Not Detect This Attack

The PsExec pattern evades EDR behavioral detection for several structural reasons:

| Reason | Detail |
|--------|--------|
| No malicious binary on disk | The service binary path is cmd.exe — a signed Microsoft binary with no threat signature |
| No shellcode or injection | Execution is a plain cmd.exe command, not a memory-based technique |
| Legitimate parent process | services.exe is a trusted Windows process — its child process activity is expected |
| No network C2 | The attack completed within the domain — no outbound beacon to detect |
| Admin-level access used legitimately | Domain admin using ADMIN$ is architecturally normal behavior |
| No anomalous access rights | No process opened handles to protected memory or sensitive APIs |

This is why the PsExec pattern remains prevalent in real-world intrusions years after its
creation. Tools like Impacket's psexec.py can execute this technique from a Linux host
with no Windows tooling, and the resulting telemetry is nearly impossible for an EDR to
distinguish from legitimate remote administration.

## What Would Trigger a Defender Alert for This Technique

In a real attack with a malicious payload, Defender would be more likely to detect:

| Payload Type | Why Defender Would Detect It |
|-------------|------------------------------|
| Known offensive tool binary (Mimikatz, Cobalt Strike) | Signature match on the file written to ADMIN$ |
| Encoded PowerShell in the service binary path | Behavioral heuristic on obfuscated execution |
| Process hollowing or injection from the service | Memory-based behavioral detection |
| Outbound C2 connection from the spawned process | Network behavioral detection |
| Credential access from SYSTEM service context | T1003 heuristic |

In this simulation the binary path ran `cmd.exe /c echo lateral_movement_test` — a
completely benign command. Defender had no behavioral basis for an alert.


## The 8:02 AM Domain Admins Event — Separate Investigation Thread

The Microsoft Sentinel event at 8:02 AM is outside this case study's attack window but
is visible in the same DC01 timeline and is forensically relevant to the broader attack chain.

In the context of all five case studies in this lab, this event represents Case Study 04 —
privilege escalation via Domain Admins group modification. The sequence across the full
attack chain is:

| Time | Event | Case Study |
|------|-------|-----------|
| 8:02 AM | John Doe added to Domain Admins by Administrator | Case Study 04 |
| 9:14 PM | Administrator Type 3 logon from CLIENT01 to DC01 | **Case Study 05** |
| 9:16 PM | SimulatedPsExec service created on DC01 | **Case Study 05** |

This multi-case-study timeline demonstrates how individual alert findings connect into a
broader attack narrative — a core skill in Tier 2 SOC analysis.

## Splunk vs Defender — This Attack

| Capability | Splunk | Defender |
|------------|--------|---------|
| 4624 Type 3 logon from CLIENT01 | Full event with source IP confirmed | Not in timeline |
| 7045 service creation | Service name and binary path captured | Not in timeline |
| Service binary path content | Full visibility | Not surfaced |
| Attack chain correlation | Correlation query available | Not possible |
| Alert generated | N/A — SIEM is detection only | No alert |
| Prevention | N/A — SIEM cannot prevent | No block |

This is the inverse of Case Study 03 (Credential Dumping), where Defender was the sole
detection layer and Splunk returned zero results because Defender killed the process before
the system call was made. Here, Splunk holds all the signal and Defender contributes
nothing. Both scenarios are realistic — a SOC analyst needs to know which tool to trust
for which attack class.

## Hardening Recommendations

Since Defender cannot reliably detect this technique, defensive focus should be on
reducing the attack surface:

| Control | Effect |
|---------|--------|
| Block SMB (port 445) from workstations to DCs at the network layer | Prevents ADMIN$ connection — stops the attack at Step 1 |
| Implement Privileged Access Workstations (PAWs) | Restricts domain admin sessions to dedicated hardened hosts |
| Restrict which accounts can connect to ADMIN$ | Limit remote admin share access to specific service accounts |
| Alert on 7045 events with non-standard binary paths | Provides SIEM detection where Defender cannot |
| Alert on any new service installation on domain controllers | DC01 service installs should be rare and scheduled |
| Enable Windows Firewall rules on DC01 restricting sc.exe remote access | Limits which hosts can remotely install services |

## MITRE ATT&CK Mapping

| Tactic | Technique | ID | Evidence |
|--------|-----------|-----|---------|
| Lateral Movement | Remote Services: SMB/Windows Admin Shares | T1021.002 | net use \\DC01\ADMIN$ — 4624 Type 3 from 192.168.113.20 |
| Execution / Persistence | Create or Modify System Process: Windows Service | T1543.003 | sc.exe \\DC01 create — 7045 on DC01 |
| Execution | System Services: Service Execution | T1569.002 | sc.exe \\DC01 start — service start attempt |
