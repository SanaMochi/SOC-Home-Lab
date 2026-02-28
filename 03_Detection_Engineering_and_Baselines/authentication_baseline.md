# Authentication Baseline – Windows Security Events

## Data Source

Windows Security Log:

- Event ID 4624 – Successful logon
- Event ID 4625 – Failed logon

Collected from:

- DC01 (Domain Controller)
- CLIENT01 (Domain-joined workstation)

Logs ingested into Splunk via Universal Forwarder.


## Objective

Establish normal authentication behavior across the lab environment to:

- Detect brute-force activity
- Identify abnormal logon types
- Understand domain authentication flow
- Improve triage accuracy during investigations

Authentication telemetry is critical because most attacker techniques require valid credentials or authentication attempts.


## Methodology

Baseline created by:

1. Querying successful and failed authentication events
2. Grouping results by:
   - Host
   - Event Code
   - Account
   - Logon Type
3. Identifying patterns between:
   - Domain controller activity
   - Endpoint user activity
4. Separating:
   - Human logons
   - Machine/service logons


## Splunk Query Used
```SPL
index=wineventlog (EventCode=4624 OR EventCode=4625)
| stats count by host EventCode Account_Name Logon_Type
| sort -count
```

<p align="center">
  <img src="https://github.com/SanaMochi/SOC-Home-Lab/blob/main/03_Baseline/Screenshots/authentication_baseline.png" width=100% />
</p>

This query highlights the most frequent authentication patterns.

## Logon Type Reference

| Logon Type | Meaning | Example |
|-----------|---------|---------|
| 2 | Interactive | User logging into workstation console |
| 3 | Network | Accessing shared resources (SMB, SYSVOL, LDAP) |
| 5 | Service | Windows services starting |
| 7 | Unlock | Workstation unlock |
| 10 | RemoteInteractive | RDP login |
| 11 | CachedInteractive | Offline domain login |

Logon Type 3 was the most frequently observed.

<p align="center">
  <img src="https://github.com/SanaMochi/SOC-Home-Lab/blob/main/03_Baseline/Screenshots/event4624.png" width=70% />
</p>

## Baseline Observations

### Domain Controller Generates High Volume Network Logons

The domain controller (dc01) shows a large number of:

Event ID: 4624  
Logon Type: 3  

This behavior is expected because:

- Domain authentication relies heavily on network logons
- Clients repeatedly access:
  - SYSVOL
  - NETLOGON
  - LDAP services
- Machine accounts authenticate automatically

Examples observed:
- CLIENT01$
- DC01$
- SYSTEM

These represent normal domain operations rather than user-driven activity.


### Machine Accounts Generate Frequent Authentication Events

Machine accounts (ending in `$`) appear frequently.

Example:

CLIENT01$

These occur because domain-joined systems continuously:
- Refresh Kerberos tickets
- Apply Group Policy
- Validate domain trust

This behavior is expected in Active Directory environments.

Detection implication: \
Machine account spikes are only suspicious when:
- Appearing from unusual hosts
- Occurring at abnormal times
- Combined with failed authentication events

### Interactive Logons Are Low Volume

Interactive logons (Type 2) primarily occur on:

CLIENT01

These events correspond to:

- Manual user login
- Administrative testing activity

Because the lab environment has limited users, interactive authentication volume remains low.

Detection implication: \
New or unexpected interactive logons are high-value signals.


### Failed Logons Are Minimal

Event ID 4625 occurrences are low and primarily associated with:

- Testing activity
- Credential validation attempts

Low failure volume establishes a strong baseline for brute-force detection.

Detection implication: \
Any spike in Event ID 4625 would be immediately anomalous.


### Account Name "-" Appears in Some Network Logons

Some events show: \
Account Name: -

This occurs when:
- Authentication is tied to system-level processes
- The session is not mapped to a traditional user context

Common causes include:
- Kerberos pre-authentication flow
- Internal Windows authentication operations

This behavior is normal when observed alongside system or machine activity.

## Analytical Patterns Derived From Baseline

### Network Authentication Dominates Domain Controller Logs

Most authentication activity on DC01 is:

Logon Type 3 (Network)

This reflects expected domain communication patterns rather than user behavior.

During investigations, analyst focus should prioritize:

- Interactive logons (Type 2)
- Remote logons (Type 10)
- Failed logons (4625)


### Interactive Logons Represent High-Signal Events

Because user activity volume is low, interactive logons provide strong detection value.

New interactive sessions should be validated during investigations.

### Machine Authentication Creates Background Noise

Machine accounts generate consistent authentication traffic.

Analysts should avoid treating these as suspicious without additional indicators.


## Detection Value Derived From Baseline

The authentication baseline supports detection for:

- Brute-force attacks
- Credential spraying
- Lateral movement via SMB or RDP
- Privileged account misuse

## Detection Rules Derived From Baseline

Based on observed authentication patterns, the following detection logic was created:

### Brute Force Detection Strategy

Because failed logons (Event ID 4625) occur at very low volume in this environment, spikes in failure counts represent high-signal anomalies.

Detection thresholds:

- Multiple failed logons from a single account
- Multiple failed logons from a single source host
- Failed logons followed by successful authentication

Implementation:

See:
03-Detection-Engineering/brute-force-detection.md
