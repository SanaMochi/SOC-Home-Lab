# Brute Force — Splunk Detection Queries

## Data Source

- Index: wineventlog
- Event IDs: 4625 (failed logon), 4624 (successful logon)
- Host: CLIENT01, DC01

## Query 1 — Threshold-Based Brute Force Detection
```spl
index=wineventlog EventCode=4625
| bucket span=5m _time
| stats count by _time Target_Account_Name Subject_Account_Name Source_Network_Address host
| where count >= 10
| sort -count
```
<p align="center">
  <img src="https://github.com/SanaMochi/SOC-Home-Lab/blob/main/04_Incident_Case_Studies/01_Brute_Force/Screenshots/4624.png" width=100% />
</p>

### What Each Line Does

| Line | Purpose |
|------|---------|
| `index=wineventlog EventCode=4625` | Scope search to failed logon events only |
| `bucket span=5m _time` | Group events into 5-minute time windows |
| `stats count by ...` | Count failures per account, source, and host within each window |
| `where count >= 10` | Surface only time windows exceeding the threshold |
| `sort -count` | Show highest counts first |

### Results from Simulation

| Time | Subject Account | Target Account | Source Address | Host | Count |
|------|------------------|--------|----------------|------|-------|
| 2026-03-10 22:55:00 | Administrator | jdoe | ::1 | CLIENT01 | 30 |

Administrator as the Subject Account indicates that Administrator is a compromised 
account attempting to gain access to jdoe.
Note: Source address ::1 indicates IPv6 loopback — authentication originated locally 
on CLIENT01. In a network-based attack this would reflect the attacker's IP address.

### Threshold Rationale

Threshold set at 10 failures within 5 minutes based on lab baseline analysis showing 
near-zero legitimate failure volume. In enterprise environments thresholds should be 
calibrated to normal authentication patterns — typically 10–20 failures for standard 
accounts, 3–5 for privileged accounts.

## Query 2 — Compromise Confirmation (Failures Followed by Success)
```spl
index=wineventlog (EventCode=4624 OR EventCode=4625)
| stats
    count(eval(EventCode=4625)) as failed_attempts,
    count(eval(EventCode=4624)) as successful_logins
    by Account_Name
| where failed_attempts > 5 AND successful_logins > 0
```

### What Each Line Does

| Line | Purpose |
|------|---------|
| `EventCode=4624 OR EventCode=4625` | Pull both success and failure events |
| `count(eval(EventCode=4625))` | Count only failures per account |
| `count(eval(EventCode=4624))` | Count only successes per account |
| `where failed_attempts > 5 AND successful_logins > 0` | Surface accounts with both patterns |

### Results from Simulation

| Account | Failed Attempts | Successful Logins | Assessment |
|---------|----------------|-------------------|------------|
| jdoe | 32 | 22 | Credential compromise likely |
| Administrator | 30 | 4 | Attacker's Session |

### Detection Value

This query upgrades the brute force detection from anomaly detection to compromise 
confirmation. Finding both failed and successful logons for the same account within 
the search window strongly indicates the attacker successfully guessed the password.

## Query 3 — Raw Event Investigation
```spl
index=wineventlog EventCode=4625 host="CLIENT01"
| table _time Account_Name Target_Account_Name Source_Network_Address Logon_Type host
| sort -_time
```

Use this query during investigation to review individual failure events and confirm 
field values such as logon type, exact account names, and source addresses.

## False Positive Considerations

| Scenario | How to Distinguish |
|----------|--------------------|
| User forgetting password | Low volume (2–5 failures), consistent source host matching normal logon host, no subsequent suspicious activity |
| Service account credential mismatch | Consistent source host, service account name, failures occur at regular intervals matching service restart patterns |
| Vulnerability scanner | Known scanner IP, consistent timing, targets multiple accounts simultaneously |

## Tuning Recommendations

- Exclude known service accounts from threshold alerting: `| where NOT match(Account_Name, "svc_")`
- Create separate lower-threshold rule for privileged accounts (Administrator, Domain Admins members)
- Correlate with logon type — Type 10 (RDP) failures from external IPs warrant immediate escalation
