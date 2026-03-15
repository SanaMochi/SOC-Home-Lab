# Case Study 04 — Privilege Escalation (Domain Admins Group Membership)

## Attack Summary

Privilege escalation via Active Directory group membership manipulation is one of the
highest-impact techniques available to an attacker with domain access. By adding a
standard user account to the Domain Admins group, an attacker instantly grants that
account unrestricted access to every system in the domain — all domain controllers,
all servers, all workstations, and all domain data.

In this simulation, the standard user account jdoe (John Doe), located in the
Corps-Users OU, was added to the Domain Admins group by the Administrator account
on DC01. The change was detected by both Splunk via Windows Security Event ID 4728
and by Microsoft Sentinel, which generated a named alert with full context. The
account was immediately removed after confirmation (Event ID 4729), simulating
attacker cleanup behavior.

## Why Attackers Use This Technique

- Instantly grants domain-wide administrative access to a controlled account
- More covert than using the built-in Administrator account directly
- The compromised account appears to be a standard user — attracts less scrutiny
- Enables persistent access even if the original compromise vector is remediated
- Domain Admin rights enable Golden Ticket creation for long-term persistence
- Can be performed silently in seconds with a single PowerShell command

## Attack Chain Position

Group membership escalation occurs after credential access or initial foothold on DC:

Initial Access → Credential Access → **Privilege Escalation** → Persistence → Impact

MITRE ATT&CK: T1098 — Account Manipulation  
MITRE ATT&CK: T1069.002 — Permission Groups Discovery: Domain Groups

## Simulation Details

| Field | Value |
|-------|-------|
| Attacker Host | DC01 (192.168.113.10) |
| Attacker Account | CORP\Administrator |
| Target Account | jdoe (John Doe, corp.local/Corps-Users) |
| Target Group | Domain Admins (SID -512) |
| Add Command | Add-ADGroupMember -Identity "Domain Admins" -Members "jdoe" |
| Remove Command | Remove-ADGroupMember -Identity "Domain Admins" -Members "jdoe" -Confirm:$false |
| Time of Add | 2026-03-12 08:02:03 |
| Time of Remove | 2026-03-12 08:09:28 |

## Baseline State

Before the attack, Domain Admins contained only two legitimate members:
- admin01 (corp.local/Corps-Admins)
- Administrator (corp.local/Users)

jdoe is a standard user in Corps-Users with no administrative privileges.
Any addition of jdoe to a privileged group is immediately anomalous.

## Telemetry Sources

| Source | Events Generated |
|--------|-----------------|
| Windows Security Log (DC01) | Event ID 4728 (add) and Event ID 4729 (remove) |
| Splunk (wineventlog index) | Both events captured with full field extraction |
| Microsoft Sentinel | Named alert: "An account was added to the Domain Admins group" |
| Microsoft Defender for Endpoint | DC01 timeline entry via Sentinel integration |
