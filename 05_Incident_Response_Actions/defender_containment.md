# Incident Response — Defender for Endpoint Containment Actions

## Overview

This document covers the containment actions performed against CLIENT01 using Microsoft
Defender for Endpoint following the simulated attack chain across all five case studies.
CLIENT01 was selected as the containment target because it was the origin host for four
of the five attacks — encoded PowerShell execution, brute force authentication, the
ADMIN$ lateral movement pivot to DC01, and the credential dumping attempt.

In a real incident, containment would begin the moment a host is confirmed as compromised
or actively being used for attack activity. The actions below follow the standard Defender
containment workflow: isolate the device, preserve forensic evidence, then release for
remediation once the environment is secured.

All actions were performed manually via the Defender portal. Each action is logged in the
Action Center with submitter, timestamp, and status — providing a full audit trail of
analyst activity.

## Action 1 — Device Isolation

**Why isolate first:** Isolation cuts the device off from all network communication while
keeping the Defender for Endpoint agent connected. This prevents the attacker from
continuing to use the device, exfiltrating data, or receiving C2 instructions — while
preserving the ability to perform remote response actions from the portal.

### Steps Performed

1. Defender portal → Devices → CLIENT01
2. Top-right "..." menu → **Isolate device**
3. For  Full Isolation do not check "_Allow Outlook, Teams and Skype for Business communication while 
    device is isolated_" (block all network traffic except Defender agent communication)
4. Added comment: *"Simulated IR response — CLIENT01 used as attack origin across 5 case studies"*
5. Clicked Confirm

<p align="center">
  <img src="https://github.com/SanaMochi/SOC-Home-Lab/blob/main/05_Incident_Response_Actions/Screenshots/defender_containment/isolate_window.png" width=70% />
</p>

### Isolation Confirmed

The isolation was pending until CLIENT01 was reconnected to the network. Then CLIENT01 device page immediately updated to reflect the isolated state.

<p align="center">
  <img src="https://github.com/SanaMochi/SOC-Home-Lab/blob/main/05_Incident_Response_Actions/Screenshots/defender_containment/client.png" width=100% />
</p>

Key details from the device page post-isolation:

| Field | Value |
|-------|-------|
| Status | **Isolated** |
| Last Action Type | Device Isolation |
| Action Status | Completed |
| Time Submitted | Mar 13, 2026 9:54:23 PM |
| Submitted By | SanaMohiuddin@mylab135.onmicrosoft.com |
| Action Source | Manual device action |
| Comment | Simulated IR response — CLIENT01 used as attack origin across 5 case studies |

The Action Center logged the isolation immediately:

<p align="center">
  <img src="https://github.com/SanaMochi/SOC-Home-Lab/blob/main/05_Incident_Response_Actions/Screenshots/defender_containment/action_home.png" width=100% />
</p>

### What Isolation Does Technically

Full device isolation blocks all inbound and outbound network traffic from the endpoint
except for a single persistent TLS channel to the Defender for Endpoint backend. This means:

- The attacker loses all remote access to the machine
- No data can be exfiltrated from the isolated host
- The analyst retains full remote response capability through the portal
- The device's memory, processes, and disk state are preserved for forensic collection
- The option to allow Outlook, Teams, and Skype traffic during isolation was left unchecked —
  full isolation was appropriate given the severity of the simulated incident


## Action 2 — Collect Investigation Package

Before releasing the device from isolation, a forensic investigation package was collected.
This preserves volatile evidence that would be lost after remediation or reboot.

### Steps Performed

1. CLIENT01 device page → "..." menu → **Collect investigation package**
2. Added comment: *"IR Investigation"*
3. Clicked Confirm

<p align="center">
  <img src="https://github.com/SanaMochi/SOC-Home-Lab/blob/main/05_Incident_Response_Actions/Screenshots/defender_containment/investigation_window.png" width=70% />
</p>

The collection completed successfully:

<p align="center">
  <img src="https://github.com/SanaMochi/SOC-Home-Lab/blob/main/05_Incident_Response_Actions/Screenshots/defender_containment/investigation_action.png" width=50% />
</p>

### What the Investigation Package Contains

The Defender investigation package is a ZIP archive collected from the endpoint containing:

| Artifact | Contents |
|----------|----------|
| Autoruns | All persistence mechanisms — registry run keys, scheduled tasks, services |
| Installed programs | Full software inventory at time of collection |
| Network connections | Active and recent TCP/UDP connections with process mapping |
| Prefetch files | Evidence of recently executed programs |
| Processes | Running process list with parent-child relationships |
| Security event log | Recent Windows Security events |
| Users and groups | Local account and group membership state |
| Windows Defender logs | AV scan history and detection events |

In a real incident this package would be the starting point for offline forensic analysis —
it captures the host state at the moment of containment before any remediation changes it.


## Action 3 — Release from Isolation

After forensic collection was confirmed complete, CLIENT01 was released from isolation
to allow remediation and monitoring to resume.

### Steps Performed

1. CLIENT01 device page → "..." menu → **Release from isolation**
2. Added comment: *"Release client01.corp.local from isolation"*
3. Clicked Confirm

<p align="center">
  <img src="https://github.com/SanaMochi/SOC-Home-Lab/blob/main/05_Incident_Response_Actions/Screenshots/defender_containment/release_window.png" width=50% />
</p>

The release completed and was logged in the Action Center:

<p align="center">
  <img src="https://github.com/SanaMochi/SOC-Home-Lab/blob/main/05_Incident_Response_Actions/Screenshots/defender_containment/action_home2.png" width=100% />
</p>

## Full Action Center Audit Trail

The complete Action Center history shows all three containment actions performed in sequence,
providing a full documented audit trail of analyst activity:

<p align="center">
  <img src="https://github.com/SanaMochi/SOC-Home-Lab/blob/main/05_Incident_Response_Actions/Screenshots/defender_containment/action_home3.png" width=100% />
</p>

| Time | Action | Asset | Status |
|------|--------|-------|--------|
| Mar 13, 2026 10:25 PM | Collect investigation package | client01.corp.local | Completed |
| Mar 13, 2026 10:17 PM | Stop isolation | client01.corp.local | Completed |
| Mar 13, 2026 10:00 PM | Isolate device | client01.corp.local | Completed |

The Action Center provides a permanent record of who performed each action, when, from
which interface (Portal vs API vs automated playbook), and the outcome. This audit trail
is essential for incident post-mortems and regulatory reporting.

## Full Containment Workflow — Real Incident Reference

In a production incident, containment would follow this decision flow:

### Immediate (0–15 minutes)
1. Confirm the host is actively compromised — do not isolate on suspicion alone
2. **Isolate device** — cuts attacker access, preserves Defender channel
3. Notify incident commander and escalate per runbook
4. Capture the device page screenshot showing isolation status for the incident ticket

### Short-term (15–60 minutes)
5. **Collect investigation package** — preserve volatile state before any changes
6. Review Action Center to confirm all actions completed successfully
7. Pull Defender timeline for the device — review last 24-48 hours of activity
8. Identify all accounts that logged onto the device — flag for credential reset
9. Determine if the attacker pivoted to other hosts from this one

### Remediation (1–4 hours)
10. **Disable compromised user accounts** in Active Directory (see account-disable.md)
11. Reset credentials for all accounts active on the compromised host
12. Rebuild or reimage the host if persistence mechanisms are found
13. **Release from isolation** only after remediation is confirmed complete
14. Monitor closely for 24–48 hours post-release


## CLIENT01 Device Context

The Defender device page revealed additional context relevant to the investigation:

| Field | Value | Significance |
|-------|-------|-------------|
| Active Alerts | 2 Medium | Pre-existing alerts from simulated attacks |
| Active Incidents | 2 | Correlated incident groupings |
| Logged On Users (30 days) | administrator, asmith, (1 other) | asmith appeared in lateral movement telemetry |
| Most Logons | administrator (Local admin) | Primary attacker account |
| Exposure Level | Medium | 62 security recommendations, 41 vulnerabilities |
| Device Role | Domain Admin Device, Infra IT Admin Device | High-value target — DC access from this host |

The presence of `asmith` in the logged-on users list corroborates the finding from
Case Study 05, where asmith Type 3 logons appeared on DC01 during the lateral movement
window. This account requires investigation as a potential secondary compromise.

## MITRE ATT&CK — Defender Response Mapping

| Defender Action | Counters | MITRE Technique |
|----------------|----------|-----------------|
| Device Isolation | Cuts C2 channel, stops lateral movement | T1021, T1071 |
| Investigation Package | Captures persistence artifacts | T1547, T1053, T1543 |
| Account Disable | Removes attacker's credential access | T1078 |
