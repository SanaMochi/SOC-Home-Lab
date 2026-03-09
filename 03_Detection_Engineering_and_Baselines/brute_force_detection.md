# Brute Force Detection – Windows Authentication Events

## Objective

Detect password brute-force and credential spraying activity using Windows authentication telemetry.

Attackers commonly attempt multiple authentication failures in order to:

- Guess weak passwords
- Validate stolen credentials
- Identify valid accounts before lateral movement

Brute-force activity is often an early-stage attack indicator.

## Data Source

Windows Security Log

Relevant Events:

- Event ID 4625 – Failed logon

<p align="center">
  <img src="https://github.com/SanaMochi/SOC-Home-Lab/blob/main/03_Detection_Engineering_and_Baselines/Screenshots/4625.png" width=50% />
</p>
  
- Event ID 4624 – Successful logon (used for correlation)

<p align="center">
  <img src="https://github.com/SanaMochi/SOC-Home-Lab/blob/main/03_Detection_Engineering_and_Baselines/Screenshots/4624.png" width=50% />
</p>

Collected from:

- Domain Controller (primary authentication source)

## Detection Logic

Brute-force behavior typically appears as:

- Multiple failed logons within a short time window
- Failures targeting:
  - A single account
  - Multiple accounts from one source host
- Failures followed by a successful login

Detection thresholds should be environment-dependent.

Lab threshold:

- 10+ failed logons within 5 minutes

## Splunk Detection Query

```SPL
index=wineventlog EventCode=4625
| bucket span=5m _time
| stats count by _time Account_Name Source_Network_Address host
| where count >= 10
| sort -count
```

This query identifies repeated authentication failures across short time intervals.

## Correlation Enhancement (Success After Failures)

```SPL
index=wineventlog (EventCode=4624 OR EventCode=4625)
| stats 
count(eval(EventCode="4625")) as failed_attempts
count(eval(EventCode="4624")) as successful_logins
by Account_Name Source_Network_Address
| where failed_attempts > 5 AND successful_logins > 0
```

This detects potential password guessing followed by successful compromise.

## Key Investigation Fields

| Field                  | Purpose                            |
| ---------------------- | ---------------------------------- |
| Account_Name           | Targeted account                   |
| Source_Network_Address | Source system or attacker host     |
| Logon_Type             | Authentication method              |
| host                   | Domain controller generating event |

These fields help determine attack origin and scope.

## False Positive Considerations

Common benign causes include:
- User typing incorrect password repeatedly
- Service account password mismatch
- Scheduled tasks using outdated credentials
- Misconfigured applications

False positives typically show:
- Consistent internal source host
- Single account repeatedly failing

## Tuning Strategy

Improve detection accuracy by:
- Excluding known service accounts
- Filtering internal vulnerability scanners
- Adjusting thresholds based on environment size
- Correlating with successful logons

Example tuning filter:

```SPL
| where Account_Name!="svc_backup"
```

Thresholds should scale with authentication volume.

## Detection Value

Brute-force detection supports identification of:
- Credential attacks
- Initial access attempts
- Password spraying campaigns

Because authentication activity is unavoidable in most attacks, this detection provides strong early visibility. 

## MITRE ATT&CK Mapping

Technique: \
T1110 – Brute Force

## Detection Maturity

| Field | Value |
|-------|--------|
| Level | Lab Validation |
| Status | Tested in Controlled Environment |
| Telemetry Source | Windows Security Logs (Event ID 4625, 4624) |
| Detection Type | Threshold-Based Behavioral Detection |
| False Positive Risk | Moderate (password typos, service accounts) |
| Tuning Required | Yes – account exclusions & lockout policy alignment |
