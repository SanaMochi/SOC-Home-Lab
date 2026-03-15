# Privilege Escalation — Microsoft Sentinel & Defender Investigation

## Overview

This attack produced a named Microsoft Sentinel alert — the first case study in this
lab where Sentinel generated an alert independently of Splunk. The alert appeared on
the DC01 Defender device timeline as a SentinelActivity event, demonstrating Sentinel's
built-in analytics rule for Domain Admins group modifications.

This case study is notable because it shows three independent detection sources firing
on the same event: Splunk (raw Windows Security log), Sentinel (analytics rule), and
ADUC (visual confirmation). Each source provides different context.

## Sentinel Alert

**Alert:** An account was added to the Domain Admins group  
**Action Type:** SentinelActivity  
**Service Source:** Microsoft Sentinel  
**Event Time:** Mar 12, 2026 8:02:03 AM  

<p align="center">
  <img src="https://github.com/SanaMochi/SOC-Home-Lab/blob/main/04_Incident_Case_Studies/04_Priviledge_Escalation/Screenshots/dc01.png" width=100% />
</p>

The alert appeared on the DC01 device timeline at exactly the same timestamp as the
Windows Security Event ID 4728 — confirming Sentinel is ingesting DC01 security logs
and running analytics rules against them in near real time.

## Sentinel Alert Detail

The expanded Sentinel event provides a human-readable description of the exact change.

<p align="center">
  <img src="https://github.com/SanaMochi/SOC-Home-Lab/blob/main/04_Incident_Case_Studies/04_Priviledge_Escalation/Screenshots/event.png" width=50% />
</p>

| Field | Value |
|-------|-------|
| Event | An account was added to the Domain Admins group |
| Event Time | Mar 12, 2026 8:02:03 AM |
| Action Type | SentinelActivity |
| Service Source | Microsoft Sentinel |
| Description | On 'DC01.corp.local' the user 'John Doe' was added by 'Administrator' to group: 'Domain Admins' |
| Activity ID | aaad22c3-be50-465f-b258-8570d629c3db |

The Description field is exceptionally useful for alert triage — it provides a complete
plain-language summary of the event without requiring the analyst to parse raw event
fields. An analyst seeing this alert immediately knows:
- What happened: group membership change
- Who did it: Administrator
- Who was affected: John Doe
- Which group: Domain Admins
- Where: DC01.corp.local

This is the ideal alert format — actionable context delivered at first glance.

## ADUC Visual Confirmation

Active Directory Users and Computers on DC01 provided visual confirmation of both
the attack state and the restored baseline.

### Before Attack

<p align="center">
  <img src="https://github.com/SanaMochi/SOC-Home-Lab/blob/main/04_Incident_Case_Studies/04_Priviledge_Escalation/Screenshots/group_baseline.png" width=50% />
</p>

Two members — admin01 and Administrator. This is the expected legitimate state.

### During Attack

<p align="center">
  <img src="https://github.com/SanaMochi/SOC-Home-Lab/blob/main/04_Incident_Case_Studies/04_Priviledge_Escalation/Screenshots/jdoe_added.png" width=50% />
</p>

John Doe (corp.local/Corps-Users) visible as the third member. The blue highlight
indicates the newly added account. The OU path Corps-Users confirms this is a
standard user account — not an administrative account.

### After Cleanup

<p align="center">
  <img src="https://github.com/SanaMochi/SOC-Home-Lab/blob/main/04_Incident_Case_Studies/04_Priviledge_Escalation/Screenshots/jdoe_removed.png" width=50% />
</p>

Restored to baseline. The attacker's cleanup removed the visual indicator but the
Windows Security log retained both the 4728 and 4729 events — cleanup does not
erase the audit trail.

## Why Sentinel Detected This But Not Defender

Microsoft Defender for Endpoint focuses on endpoint behavioral signals — process
execution, file creation, network connections, memory access. AD group membership
changes are a directory services event, not an endpoint event. Sentinel's analytics
rules operate against the SecurityEvent table (Windows Security logs forwarded from
DC01 via AMA) and include built-in rules specifically for privileged group modifications.

This is a clear example of tool specialization:
- **Defender** catches what happens on endpoints (processes, files, memory)
- **Sentinel** catches what happens in the directory (group changes, policy changes, account creation)

A SOC without Sentinel (or equivalent SIEM analytics) would miss this detection
entirely if relying on Defender alone.

## Detection Comparison Across All Sources

| Source | Detection | Detail Level | Response Capability |
|--------|-----------|-------------|-------------------|
| Splunk | Event ID 4728/4729 | High — raw field access | Detection only |
| Microsoft Sentinel | Named analytics alert | Medium — plain language summary | Playbook automation possible |
| Defender for Endpoint | Via Sentinel integration on DC01 timeline | Low — timeline entry only | Device response actions |
| ADUC | Visual group membership | Visual only — no logging | Manual only |

## Note on Removal Event

The Event ID 4729 (removal of John Doe from Domain Admins) was captured in Splunk
but did not generate a separate Sentinel alert. This is expected behavior — Sentinel's
built-in analytics rule triggers on additions to privileged groups (4728) as the
higher-risk event. Removals may generate alerts in environments with custom analytics
rules configured to detect the add/remove cleanup pattern.

The absence of a Sentinel removal alert does not mean the cleanup went undetected —
the 4729 event is fully visible in Splunk and the complete add/remove timeline is
documented in the investigation.


## MITRE ATT&CK Mapping

| Tactic | Technique | ID | Evidence |
|--------|-----------|-----|---------|
| Privilege Escalation | Account Manipulation | T1098 | jdoe added to Domain Admins via Add-ADGroupMember |
| Defense Evasion | Account Manipulation | T1098 | jdoe removed from Domain Admins 7 minutes later |
| Discovery | Permission Groups Discovery: Domain Groups | T1069.002 | Attacker identified Domain Admins as escalation target |
