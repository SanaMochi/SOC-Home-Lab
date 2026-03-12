# Privilege Escalation — Investigation Walkthrough

## Investigator Perspective

This investigation begins from a Splunk alert on Event ID 4728 — a member was added to
a security-enabled global group. The target group is Domain Admins, which makes this an
immediate high-priority finding. The goal is to confirm the change, identify who made it,
assess whether it was authorized, and determine if the elevated account was used before
removal.

## Step 1 — Establish Baseline

Before the attack was executed, the monitoring window showed zero group membership
change events in the last 24 hours, confirming a clean baseline.

<p align="center">
  <img src="https://github.com/SanaMochi/SOC-Home-Lab/blob/main/04_Incident_Case_Studies/04_Priviledge_Escalation/Screenshots/baseline.png" 
     width=100% />
</p>

The all-time view shows 17 historical events — all from lab setup activities in
February 2026 when users and groups were created. None of these represent unauthorized
changes.

<p align="center">
  <img src="https://github.com/SanaMochi/SOC-Home-Lab/blob/main/04_Incident_Case_Studies/04_Priviledge_Escalation/Screenshots/all_time.png" 
     width=100% />
</p>

The Domain Admins group contained exactly two legitimate members before the attack:

<p align="center">
  <img src="https://github.com/SanaMochi/SOC-Home-Lab/blob/main/04_Incident_Case_Studies/04_Priviledge_Escalation/Screenshots/group_baseline.png" 
     width=50% />
</p>

## Step 2 — Alert Fires on Event ID 4728

The detection query surfaced a new Event ID 4728 in the monitoring window — a member
was added to Domain Admins.

Key fields from the detection:

| Field | Value | Significance |
|-------|-------|-------------|
| EventCode | 4728 | Member added to security-enabled global group |
| Subject_Account_Name | Administrator | Account that performed the change |
| Group_Name | Domain Admins | The group modified — highest privilege group |
| Member_Name | John Doe | The account added |
| Host | DC01 | Domain controller — authoritative source |
| Time | 2026-03-12 08:02:03 | Timestamp of the change |

First triage questions:
- Is this a scheduled maintenance window? No
- Is jdoe a service account that requires Domain Admin? No — standard user in Corps-Users
- Was there a change ticket or authorization for this? No
- Is Administrator the expected account to make this change? Possibly, but requires verification

Verdict: Unauthorized privilege escalation — escalate immediately.

## Step 3 — Confirm via ADUC

Active Directory Users and Computers confirmed jdoe (John Doe) appeared in the Domain
Admins members list immediately after the PowerShell command ran.

<p align="center">
  <img src="https://github.com/SanaMochi/SOC-Home-Lab/blob/main/04_Incident_Case_Studies/04_Priviledge_Escalation/Screenshots/jdoe_added.png" 
     width=50% />
</p>

John Doe's OU path (`corp.local/Corps-Users`) is visible — confirming this is a standard
user account with no legitimate reason to be in Domain Admins.

## Step 4 — Expand Raw Event

The raw Event ID 4728 from Splunk provides full forensic detail.

<p align="center">
  <img src="https://github.com/SanaMochi/SOC-Home-Lab/blob/main/04_Incident_Case_Studies/04_Priviledge_Escalation/Screenshots/4728_full.png" 
     width=80% />
</p>

Key raw event fields:

| Section | Field | Value |
|---------|-------|-------|
| Subject | Account Name | Administrator |
| Subject | Security ID | S-1-5-21-...-500 (built-in Administrator SID) |
| Subject | Logon ID | 0x7D6608 |
| Member | Account Name | CN=John Doe,OU=Corps-Users,DC=corp,DC=local |
| Member | Security ID | S-1-5-21-...-1103 (jdoe's SID) |
| Group | Group Name | Domain Admins |
| Group | Security ID | S-1-5-21-...-512 (Domain Admins SID) |

The Member field showing the full Distinguished Name
`CN=John Doe,OU=Corps-Users,DC=corp,DC=local` is forensically significant — it
confirms exactly which account was added and from which OU, ruling out any ambiguity
about which "John Doe" account was targeted.

The Subject Logon ID (0x7D6608) can be correlated with Event ID 4624 logon events
to determine when the Administrator session began and what else it did.

## Step 5 — Attacker Cleanup Observed (Event ID 4729)

Shortly after the addition, the attacker removed jdoe from Domain Admins — a common
cleanup behavior to reduce the window of detection. This generated Event ID 4729.

<p align="center">
  <img src="https://github.com/SanaMochi/SOC-Home-Lab/blob/main/04_Incident_Case_Studies/04_Priviledge_Escalation/Screenshots/q1_4729.png" 
     width=100% />
</p>

| EventCode | Time | Action |
|-----------|------|--------|
| 4728 | 08:02:03 | John Doe added to Domain Admins |
| 4729 | 08:09:28 | John Doe removed from Domain Admins |

The 7-minute window between add and remove is the exposure window — any actions
taken by jdoe using Domain Admin privileges during this period would need to be
investigated. Key pivot: search for 4624 logon events for jdoe between 08:02 and
08:09 to determine if the account was used.

The removal of jdoe was confirmed in ADUC:

<p align="center">
  <img src="https://github.com/SanaMochi/SOC-Home-Lab/blob/main/04_Incident_Case_Studies/04_Priviledge_Escalation/Screenshots/jdoe_removed.png" 
     width=50% />
</p>

## Step 6 — Execution Evidence

The attacker's PowerShell session on DC01 shows both commands executed cleanly
with no errors.

<p align="center">
  <img src="https://github.com/SanaMochi/SOC-Home-Lab/blob/main/04_Incident_Case_Studies/04_Priviledge_Escalation/Screenshots/cli.png" 
     width=100% />
</p>

The absence of errors confirms both commands completed successfully. The
`-Confirm:$false` flag on the remove command suppressed the confirmation prompt —
a deliberate choice to make the removal faster and less visible.

## Step 7 — Timeline Reconstruction

| Time | Event | Source | Detail |
|------|-------|--------|--------|
| Before 08:02 | Baseline clean | Splunk | 0 group changes in 24hr window |
| 08:02:03 | John Doe added to Domain Admins | Windows Security EID 4728 | Subject: Administrator, DC01 |
| 08:02:03 | Sentinel alert fires | Microsoft Sentinel | "An account was added to the Domain Admins group" |
| 08:02–08:09 | Exposure window | — | 7 minutes of Domain Admin access for jdoe |
| 08:09:28 | John Doe removed from Domain Admins | Windows Security EID 4729 | Attacker cleanup |

## Step 8 — Key Investigation Questions Answered

**Was this an authorized change?**
No. jdoe is a standard Corps-Users account with no documented need for Domain Admin
access. No change ticket or maintenance window was active.

**Who made the change?**
The built-in Administrator account (SID -500) on DC01. This implies the attacker
either had Administrator credentials or was already operating in that session.

**Was the elevated account used during the exposure window?**
Unknown from this evidence alone. Next step: search for jdoe logon events (4624)
between 08:02 and 08:09 on any host in the domain.

**Is there residual risk?**
Low — jdoe was removed from Domain Admins. However if jdoe's credentials were used
during the window to create persistence (new accounts, scheduled tasks, GPO changes),
those changes would persist after the group removal.

**Why did the attacker remove jdoe?**
Classic attacker behavior — minimize the footprint to reduce detection probability.
A Domain Admin account that appears briefly and disappears is harder to catch than
one that stays permanently elevated. However the 4729 event is itself a detection
signal — add/remove pairs on privileged groups in short succession are highly
suspicious.

## Step 9 — Recommended Response Actions

1. **Immediate:** Verify jdoe's password has not been changed and reset it as precaution
2. **Investigate:** Search all DC01 logs for jdoe logon events between 08:02 and 08:09
3. **Investigate:** Review Administrator session (Logon ID 0x7D6608) for all commands
   run during that session — what else did this session do?
4. **Check:** Review DC01 for new user accounts, scheduled tasks, GPO modifications,
   or service installations made during the exposure window
5. **Alert tuning:** Add a dedicated high-severity alert for any addition to Domain
   Admins, Enterprise Admins, or Schema Admins — these should never change without
   a change ticket
6. **Harden:** Implement Privileged Access Workstations (PAW) for Domain Admin tasks
   and enable Just-In-Time (JIT) admin access to reduce standing privilege
