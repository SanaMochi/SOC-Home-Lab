# Service Creation Detection – Suspicious Service Installation

## Objective

Detect potential malicious execution through Windows service creation.

Attackers commonly create services to:

- Execute commands remotely
- Maintain persistence
- Run payloads under SYSTEM privileges

Service creation is heavily used during lateral movement.

## Data Source

Windows System Log

Relevant Event:

- Event ID 7045 – A service was installed in the system

<p align="center">
  <img src="https://github.com/SanaMochi/SOC-Home-Lab/blob/main/03_Detection_Engineering_and_Baselines/Screenshots/event7045.png" width=70% />
</p>

This event is generated whenever a new Windows service is created.

## Detection Logic

Service creation events are analyzed for suspicious execution paths and scripting engines.

### Splunk Query

```SPL
index=wineventlog EventCode=7045
| table _time host Service_Name ImagePath Account_Name
| sort -_time
```

## Sentinel Detection Query (KQL)
```KQL
SecurityEvent
| where EventID == 7045
| project TimeGenerated, Computer, ServiceName, ServiceFileName = CommandLine, ServiceAccount = SubjectUserName
| sort by TimeGenerated desc
```

**Lateral movement correlation — service creation paired with network logon:**
```KQL
let services = SecurityEvent
| where EventID == 7045
| project TimeGenerated, Computer, ServiceName;
let networkLogons = SecurityEvent
| where EventID == 4624 and LogonType == 3
| project LogonTime = TimeGenerated, Computer, AccountName;
services
| join kind=inner networkLogons on Computer
| where abs(datetime_diff('minute', TimeGenerated, LogonTime)) <= 5
| project TimeGenerated, Computer, ServiceName, AccountName
```

This correlation directly mirrors the PsExec detection pattern from the lab plan — a Type 3 logon followed closely by service creation on the same host is a strong lateral movement indicator.

## Key Investigation Fields

| Field        | Investigation Value            |
| ------------ | ------------------------------ |
| Service_Name | Installed service identifier   |
| ImagePath    | Executable or command executed |
| Account_Name | Privilege context              |
| host         | Target system                  |


This query highlights newly installed services and their execution context.

Because service creation blends with legitimate administrative behavior, baseline analysis is important.

## Analytical Observations

### Services Provide Privileged Execution

Services often run under:

NT AUTHORITY\SYSTEM

This allows attackers to:

- Execute commands with maximum privileges
- Avoid user-level restrictions

Because of this, malicious service creation is commonly used after initial access.

### Service Creation Appears in Lateral Movement

Tools such as:
- PsExec
- Impacket

install temporary services to execute remote commands.

This makes Event 7045 highly valuable during incident investigation.

## False Positive Considerations

Legitimate service creation may occur during:

- Software installation
- Endpoint management activity
- System updates

Baseline comparison helps distinguish normal behavior.

## Detection Tuning Opportunities

Detection accuracy improves by:

- Filtering known software installation paths
- Monitoring unusual service names
- Correlating with logon activity (Event 4624 Type 3)

## MITRE ATT&CK Mapping

T1569.002 – Service Execution

Execution via Windows services.

## Detection Maturity

| Field | Value |
|-------|--------|
| Level | Lab Validation |
| Status | Tested via Simulated Service Creation |
| Telemetry Source | Windows System Logs (Event ID 7045) |
| Detection Type | Persistence & Lateral Movement Monitoring |
| False Positive Risk | Moderate (software installs create services) |
| Tuning Required | Yes – baseline approved service creators |
