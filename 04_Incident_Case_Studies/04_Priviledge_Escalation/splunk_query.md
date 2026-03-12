# Privilege Escalation — Splunk Detection Queries

## Data Source

- Index: wineventlog
- Event IDs: 4728 (member added to global security group), 4729 (member removed)
- Host: DC01 (domain controller — authoritative source for AD group changes)

Event IDs 4728 and 4729 are generated on the domain controller whenever a member
is added to or removed from a security-enabled global group. Since Domain Admins is
a global security group, every membership change generates these events on DC01
regardless of which tool was used to make the change.

## Query 1 — Baseline and Detection Query

```spl
index=wineventlog (EventCode=4728 OR EventCode=4729)
| table _time host EventCode Subject_Account_Name Group_Name Member_Name
| sort -_time
```

### What Each Line Does

| Line | Purpose |
|------|---------|
| `EventCode=4728 OR EventCode=4729` | Capture both add and remove events |
| `table ... Subject_Account_Name Group_Name Member_Name` | Surface who did what to which group |
| `sort -_time` | Most recent first |

### Baseline Result (24 hours before attack)

<p align="center">
  <img src="https://github.com/SanaMochi/SOC-Home-Lab/blob/main/04_Incident_Case_Studies/04_Priviledge_Escalation/Screenshots/baseline.png" width=100% />
</p>

Zero events in the active monitoring window — any new event is immediately anomalous.

### Detection Result (after attack)

<p align="center">
  <img src="https://github.com/SanaMochi/SOC-Home-Lab/blob/main/04_Incident_Case_Studies/04_Priviledge_Escalation/Screenshots/q1_4728.png" 
      width=100% />
</p>

One event returned — jdoe added to Domain Admins by Administrator at 08:02:03.

### Full Add + Remove Pair

<p align="center">
  <img src="https://github.com/SanaMochi/SOC-Home-Lab/blob/main/04_Incident_Case_Studies/04_Priviledge_Escalation/Screenshots/q1_4729.png" 
      width=100% />
</p>

Both events visible together — the add/remove pair within 7 minutes is itself a
high-confidence indicator of malicious activity. Legitimate group changes rarely
follow this pattern.

## Query 2 — Privileged Group Monitoring (Tuned)

```spl
index=wineventlog (EventCode=4728 OR EventCode=4729)
| search Group_Name="*Admin*" OR Group_Name="*Enterprise*" OR Group_Name="*Schema*"
| table _time host EventCode Subject_Account_Name Group_Name Member_Name
| sort -_time
```

### What This Adds

Scopes detection to only the highest-privilege groups. In a production environment
with many groups, this prevents noise from legitimate changes to less critical groups
while ensuring Domain Admins, Enterprise Admins, and Schema Admins are always surfaced.

## Query 3 — Rapid Add/Remove Detection

```spl
index=wineventlog (EventCode=4728 OR EventCode=4729) Group_Name="Domain Admins"
| stats
    count(eval(EventCode="4728")) as adds,
    count(eval(EventCode="4729")) as removes,
    min(_time) as first_seen,
    max(_time) as last_seen
    by Member_Name Subject_Account_Name
| where adds > 0 AND removes > 0
| eval exposure_minutes=round((last_seen-first_seen)/60,1)
| table Member_Name Subject_Account_Name adds removes exposure_minutes
```

This query specifically detects the add/remove pattern and calculates the exposure
window in minutes. An account that appears in Domain Admins and is then removed is
a high-confidence malicious indicator — this pattern almost never occurs legitimately.

## Raw Event Analysis

The full Event ID 4728 provides three sections of forensic value:

<p align="center">
  <img src="https://github.com/SanaMochi/SOC-Home-Lab/blob/main/04_Incident_Case_Studies/04_Priviledge_Escalation/Screenshots/4728_full.png" 
      width=80% />
</p>

### Subject Section — Who Did It
```
Account Name:  Administrator
Security ID:   S-1-5-21-1120781209-3873177609-3714756752-500
Logon ID:      0x7D6608
```
The Logon ID is a pivot point — correlate with Event ID 4624 to find when this
Administrator session began and what else it did during the same session.

### Member Section — Who Was Added
```
Account Name:  CN=John Doe,OU=Corps-Users,DC=corp,DC=local
Security ID:   S-1-5-21-1120781209-3873177609-3714756752-1103
```
The Distinguished Name confirms the exact account and its OU location. The SID
(-1103) is a user-created account — not a built-in account.

### Group Section — What Was Changed
```
Group Name:    Domain Admins
Security ID:   S-1-5-21-1120781209-3873177609-3714756752-512
```
SID ending in -512 is always Domain Admins. This is the universal identifier
regardless of domain name — useful for cross-domain correlation.

## Field Extraction Note

The `Member_Name` field used in these queries is extracted by the Splunk Windows TA
from the Member section of the raw event. In some Splunk configurations this field
may not be automatically extracted — if it appears blank, use the raw event view or
add a rex extraction:

```spl
| rex "Member:\s+.*?Account Name:\s+(?P<MemberName>CN=[^\r\n]+)"
```

## False Positive Considerations

| Scenario | How to Distinguish |
|----------|--------------------|
| Legitimate admin promotion | Change ticket exists, expected account, during maintenance window |
| Service account requiring DA | Should use dedicated service account not a user account, documented |
| IT staff testing | Should still generate a ticket — DA changes always require authorization |

In a well-managed environment, **any** addition to Domain Admins without a
corresponding change ticket is a finding regardless of who made the change.

## Tuning Recommendations

- Create a dedicated saved search alerting on any 4728 event where Group_Name
  contains "Admin" — run every 5 minutes with zero threshold
- Integrate with a CMDB or ticketing system to auto-correlate group changes
  against open change tickets
- Alert on the add/remove pattern specifically — exposure windows under 30 minutes
  are highly suspicious
- Maintain a reference list of accounts that legitimately belong in Domain Admins
  and alert on any addition of an account not on that list
