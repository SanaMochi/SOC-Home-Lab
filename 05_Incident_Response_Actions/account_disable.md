# Incident Response — Account Disable and Credential Containment

## Overview

Account disabling is one of the highest-priority containment actions during an Active
Directory compromise. Once an attacker has demonstrated use of a specific account —
through logon events, group membership changes, or remote execution — that account must
be treated as compromised and disabled immediately to prevent re-entry, even after the
device has been isolated.

Device isolation (see defender-containment.md) stops the attacker's current session.
Account disabling ensures they cannot re-establish access using the same credentials
from a different host, a persisted session, or a stolen Kerberos ticket.


## Accounts Requiring Action in This Incident

Based on findings across all five case studies, the following accounts were identified
as requiring containment:

| Account | Reason | Priority |
|---------|--------|----------|
| CORP\Administrator | Used directly for brute force, encoded PowerShell, lateral movement, and privilege escalation across all 5 attacks | **Critical — disable and reset immediately** |
| jdoe (John Doe) | Targeted in brute force (4625 events), added to Domain Admins during Attack 4 | **High — disable pending investigation** |
| asmith (Alice Smith) | Type 3 logons appeared on DC01 during the lateral movement window — lateral movement to DC01 unconfirmed | **Medium — investigate before disabling** |

In this simulation, jdoe was selected as the demonstration target for account disabling
because it was the most clearly compromised non-admin account. In a real incident,
CORP\Administrator would be the first account actioned — but disabling the built-in
Administrator in a lab environment would break the simulation infrastructure.


## Action 1 — Disable Account via PowerShell (DC01)

Account management commands are run directly on DC01 as they require the Active Directory
PowerShell module, which is available on the domain controller.

### Commands Executed

```powershell
# Disable the account
Disable-ADAccount -Identity "jdoe"

# Verify the change
Get-ADUser -Identity "jdoe" | Select Name, Enabled
```

<p align="center">
  <img src="https://github.com/SanaMochi/SOC-Home-Lab/blob/main/05_Incident_Response_Actions/Screenshots/disable_account/disabled_powershell.png" 
    width=70% />
</p>

The command completed with no output — in PowerShell, silence means success. The
`Get-ADUser` verification confirms the change took effect immediately:

| Field | Value |
|-------|-------|
| Name | John Doe |
| Enabled | **False** |

The disable takes effect domain-wide immediately. Any active sessions using jdoe's
credentials will lose access at their next authentication attempt (Kerberos ticket
renewal), and new logon attempts will be rejected with error code 0xC0000072
(account disabled) generating Event ID 4625 on any host where login is attempted.


## Action 2 — Verify in Active Directory Users and Computers

ADUC provides a visual confirmation of the disabled state. A disabled account displays
a downward arrow overlay on the user icon — immediately distinguishable from active accounts.

<p align="center">
  <img src="https://github.com/SanaMochi/SOC-Home-Lab/blob/main/05_Incident_Response_Actions/Screenshots/disable_account/disabled_aduc.png" 
    width=90% />
</p>

John Doe's account icon shows the downward arrow overlay — confirming the disable is
reflected in the directory. Alice Smith's account is unaffected.

This visual check is useful during incident response when multiple accounts are being
actioned simultaneously — it provides a fast at-a-glance status across the OU without
running PowerShell queries.


## What Happens When an Account Is Disabled

| Scenario | Behaviour |
|----------|-----------|
| Active Kerberos session (already logged in) | Session continues until ticket expires (default 10 hours) — force logoff separately |
| New logon attempt | Rejected immediately — Event ID 4625 with status 0xC0000072 |
| Existing mapped drives or network sessions | Disconnected at next re-authentication |
| Service accounts using this identity | Services fail to start — check for service dependencies before disabling |
| Cached credentials on workstations | Cannot be used for new network authentication |

**Important:** Disabling an account does not invalidate existing Kerberos tickets. If the
attacker has an active TGT (Ticket Granting Ticket) for jdoe, they can continue using
it until it expires. For full containment after a ticket-based attack, a password reset
followed by running `klist purge` on affected hosts is required in addition to disabling.

## Accounts to Disable in a Real Version of This Incident

### CORP\Administrator — Critical
The built-in Administrator account (SID -500) was used directly across all five attacks.
In a real incident this account would be disabled immediately after confirming an
alternative admin account is available. Steps:

```powershell
# Only if an alternative DA account exists and is confirmed working
Disable-ADAccount -Identity "Administrator"
# Immediately verify alternative admin access before proceeding
```

Note: The built-in Administrator account cannot be locked out by failed logons, making
it a high-value target for attackers. Consider renaming it and creating a decoy
Administrator account as a hardening measure post-incident.

### asmith — Investigate First
Alice Smith's Type 3 logons appeared on DC01 during the lateral movement attack window
at 21:16:12. Before disabling, determine:
- Was asmith logged into CLIENT01 at the time?
- Do any 4624 events for asmith show a source IP of 192.168.113.20 (CLIENT01)?
- Is there a 7045 service creation associated with asmith?

If the logons are explained by legitimate activity, no action is needed. If unexplained,
disable and investigate.

## Action 3 — Re-enable Account (Lab Cleanup)

After the simulation was documented, jdoe was re-enabled to restore the lab to its
baseline state.

```powershell
Enable-ADAccount -Identity "jdoe"
Get-ADUser -Identity "jdoe" | Select Name, Enabled
```

<p align="center">
  <img src="https://github.com/SanaMochi/SOC-Home-Lab/blob/main/05_Incident_Response_Actions/Screenshots/disable_account/enable_jdoe.png" 
    width=70% />
</p>

| Field | Value |
|-------|-------|
| Name | John Doe |
| Enabled | **True** |

**Note:** In a real incident, re-enabling a compromised account would only occur after
full remediation — password reset, investigation of all activity during the compromise
window, removal of any persistence mechanisms, and sign-off from the incident commander.
Re-enabling without these steps would restore attacker access.


## Recommended Full Account Containment Checklist

For each compromised account identified in an incident:

- [ ] Disable the account in Active Directory
- [ ] Force logoff any active sessions on all hosts
- [ ] Reset the account password (invalidates existing Kerberos tickets)
- [ ] Review logon history for the past 30 days — identify all hosts accessed
- [ ] Check for new accounts created by this account during the compromise window
- [ ] Check for group membership changes made by or to this account
- [ ] Check for scheduled tasks, services, or GPOs created using this account
- [ ] Determine if the account credentials were used for lateral movement to other hosts
- [ ] Document all findings in the incident ticket before re-enabling

## MITRE ATT&CK Context

| Technique Used by Attacker | ID | Containment Action |
|---------------------------|-----|-------------------|
| Valid Accounts — Domain Accounts | T1078.002 | Disable account, reset password |
| Account Manipulation | T1098 | Review and revert group membership changes |
| Brute Force — Password Spraying | T1110.003 | Disable targeted account, enforce lockout policy |
