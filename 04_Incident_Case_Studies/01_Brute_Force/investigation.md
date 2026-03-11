# Brute Force — Investigation Walkthrough

## Investigator Perspective

This document walks through the investigation as it would be performed by a Tier 2 SOC 
analyst responding to a brute force alert. The goal is to determine scope, confirm 
compromise, and recommend containment.

## Step 1 — Alert Triage

The initial alert fired based on the threshold detection rule in Splunk:
- 10 or more failed logon events (Event ID 4625) within a 5-minute window
- Triggered for account: jdoe
- Source host: CLIENT01
- Host generating events: CLIENT01 (DC01 authentication traffic)

First question: is this a real attack or a false positive?

Indicators pointing toward real attack:
- 30 failed attempts in under 60 seconds — far exceeding normal user error patterns
- Failures followed by successful logons — pattern consistent with successful credential 
  compromise
- Administrator logged in when poershell script is run — suggests automated tooling 
  targeting accounts

False positive considerations ruled out:
- Volume (32 failures) is too high for a user forgetting their password
- Time pattern — failures clustered in a short burst rather than spread over time

Verdict: Escalate as likely true positive.

## Step 2 — Scope the Attack

Query expanded to identify all affected accounts:

The account jdoe showed the brute force pattern within the same time window that Administrator ran the script. 
This indicates either automated tooling targeting the account or a script cycling 
through a target list.

Source address appeared as ::1 (IPv6 loopback) for the majority of events, indicating 
the authentication attempts originated locally on CLIENT01 rather than from an external 
network source. This is consistent with an attacker who already has access to CLIENT01 
and is attempting to escalate or move laterally using credential guessing.

<p align="center">
  <img src="https://github.com/SanaMochi/SOC-Home-Lab/blob/main/04_Incident_Case_Studies/01_Brute_Force/Screenshots/sus.png" width=90% />
  <img src="https://github.com/SanaMochi/SOC-Home-Lab/blob/main/04_Incident_Case_Studies/01_Brute_Force/Screenshots/4625_full_log.png" width=100% />
</p>

## Step 3 — Confirm Successful Compromise

The correlation query confirmed that the account had successful logins following the 
failure burst:

| Account | Failed Attempts | Successful Logins | Assessment |
|---------|----------------|-------------------|------------|
| jdoe | 32 | 22 | Likely compromised |
| Administrator | 30 | 4 | Attackers Session |

The presence of successful logins after a failure burst is a strong indicator of credential 
compromise. The attacker appears to have obtained the valid password for the account after 30 attempts.

<p align="center">
  <img src="https://github.com/SanaMochi/SOC-Home-Lab/blob/main/04_Incident_Case_Studies/01_Brute_Force/Screenshots/success.png" width=90% />
</p>

## Step 4 — Pivot to Endpoint

Pivoted to Microsoft Defender for Endpoint timeline for CLIENT01 to establish what was 
running on the machine during the attack window.

Defender timeline revealed:
- PowerShell execution via Windows Terminal at the time of the failures
- Process chain: wt.exe → WindowsTerminal.exe → powershell.exe
- Command captured: Start-Process -FilePath "cmd.exe" -Credential $cred
- User context: corp\administrator

This confirms the brute force attempts were executed via a PowerShell script running 
interactively on CLIENT01 under the Administrator account. The $cred variable in the 
captured command indicates credential objects were being constructed programmatically — 
consistent with an automated credential guessing loop.

## Step 5 — Timeline Reconstruction

| Time | Event | Host | Detail |
|------|-------|------|--------|
| 22:55:00 | Brute force begins | CLIENT01 | 4625 failures against jdoe start |
| 22:55:00–22:56:00 | 32 failures generated | CLIENT01 | Automated loop via PowerShell |
| 22:55:00 | Administrator also targeted | CLIENT01 | 30 failures against Administrator |
| 22:56:00+ | Successful logons begin | CLIENT01 | 4624 events for jdoe (22) and Administrator (4) |
| ~22:56:10 | Defender captures PowerShell | CLIENT01 | Process tree recorded in device timeline |

## Step 6 — Key Investigation Questions Answered

**Was this brute force or password spray?**
Brute force — multiple attempts against the same accounts rather than one attempt 
across many accounts.

**Was there successful compromise?**
Yes — both jdoe and Administrator showed successful logins following the failure burst.

**What was the attack vector?**
Local PowerShell execution on CLIENT01. The attacker (or simulation script) already had 
access to CLIENT01 and was running credential guessing locally.

**What is the highest severity finding?**
The Administrator account showing 30 failures followed by 4 successful logins. 
Administrator compromise in an Active Directory environment represents potential 
domain-wide impact.

**Were there any Defender alerts?**
Defender captured the PowerShell execution and process tree but did not generate a 
dedicated brute force alert, as the attempts were local rather than network-based. 
The process tree showing credential objects in PowerShell is still a meaningful 
behavioral signal.

## Step 7 — Recommended Response Actions

1. **Immediate:** Reset passwords for jdoe and Administrator
2. **Immediate:** Review all logon activity for both accounts in the past 24 hours for 
   signs of lateral movement following the successful logins
3. **Containment:** If unauthorized access is confirmed, isolate CLIENT01 via Defender 
   device isolation
4. **Investigation:** Determine how the attacker gained initial access to CLIENT01 to 
   execute the PowerShell script
5. **Hardening:** Implement account lockout policy — lock accounts after 5 failed 
   attempts within 10 minutes
6. **Detection tuning:** Lower brute force threshold for privileged accounts such as 
   Administrator — consider threshold of 3 failures rather than 10
