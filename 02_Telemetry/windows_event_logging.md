# Windows Security Event Logging

## Overview

Native Windows Security logs were enabled to capture identity and privilege-related activity across the domain environment.

These logs form the foundation for authentication monitoring and privilege escalation detection.

## Key Event Categories

### Authentication Events

| Event ID | Description |
|----------|-------------|
| 4624 | Successful logon |
| 4625 | Failed logon |

<p align="center">
  <img src="https://github.com/SanaMochi/SOC-Home-Lab/blob/main/02_Telemetry/Screenshots/windows_event_logging/4624.png" width=100% />
</p>

<p align="center">
  <img src="https://github.com/SanaMochi/SOC-Home-Lab/blob/main/02_Telemetry/Screenshots/windows_event_logging/4625.png" width=100% />
</p>

Detection Value:

- Brute force detection  
- Abnormal logon patterns  
- Lateral movement tracking

### Account & Group Changes

| Event ID | Description |
|----------|-------------|
| 4720 | User account created |
| 4728 | User added to group |
| 4729 | User removed from group |

<p align="center">
  <img src="https://github.com/SanaMochi/SOC-Home-Lab/blob/main/02_Telemetry/Screenshots/windows_event_logging/4728.png" width=100% />
</p>

Detection Value:

- Privilege escalation  
- Persistence mechanisms

### Service Creation

| Event ID | Description |
|----------|-------------|
| 7045 | New service installed |

Detection Value:

- Remote execution detection  
- Lateral movement via PsExec / Impacket

## Architecture Role

Windows Security logs provide **identity telemetry** that complements:

- Sysmon (process telemetry)
- Defender (behavioral telemetry)

This enables multi-layer detection.

## Validation

Splunk Query:
```SPL
index=wineventlogs
```


Verified:
- Authentication events present
- Group modification events searchable
