# Sysmon Deployment & Endpoint Telemetry

## Overview

Sysmon was deployed on all Windows endpoints to provide enhanced endpoint telemetry beyond native Windows logging.

Endpoints:
- DC01 (Domain Controller)
  
  <p align="center">
  <img src="https://github.com/SanaMochi/SOC-Home-Lab/blob/main/02_Telemetry/Screenshots/sysmon_deployment/sysmon_dc01.png" width=90%/>
</p>
- CLIENT01 (Workstation)

  <p align="center">
  <img src="https://github.com/SanaMochi/SOC-Home-Lab/blob/main/02_Telemetry/Screenshots/sysmon_deployment/sysmon_client01.png" width=85%/>
</p>

Sysmon enables detailed visibility into process execution, network activity, and inter-process behavior required for detection engineering.

## Configuration

The **SwiftOnSecurity Sysmon configuration** was used to provide high-signal telemetry while reducing noise.

Configuration focus areas:

- Process creation logging
- Network connections
- Process access monitoring

## Key Telemetry Collected

### Process Creation — Event ID 1

Captures:

- Parent-child process relationships
- Command-line arguments
- Execution paths

<p align="center">
  <img src="https://github.com/SanaMochi/SOC-Home-Lab/blob/main/02_Telemetry/Screenshots/sysmon_deployment/event_id1.png" width=100%/>
</p>

Detection Use Cases:

- Suspicious PowerShell execution  
- Living-off-the-land binaries  
- Malware execution chains

### Network Connections — Event ID 3

Captures:

- Outbound connections
- Destination IPs
- Process initiating connection

<p align="center">
  <img src="https://github.com/SanaMochi/SOC-Home-Lab/blob/main/02_Telemetry/Screenshots/sysmon_deployment/event_id3.png" width=100%/>
</p>

Detection Use Cases:

- Command and control activity  
- Data exfiltration  
- Lateral movement

### Process Access — Event ID 10

Captures:

- Processes attempting to access other processes

Detection Use Cases:

- Credential dumping (LSASS access)  
- Token theft activity

## Architecture Role

Sysmon provides **process-level telemetry** that complements:

- Windows Security Logs (identity telemetry)
- Defender for Endpoint (behavioral detection)

This layered telemetry model improves detection coverage across the attack lifecycle.

## Validation

### Endpoint Validation

Confirmed Sysmon operational locally:

Event Viewer → Applications and Services Logs → Microsoft → Windows → Sysmon → Operational

Verified:

- Event ID 1  
- Event ID 3  

### SIEM Validation

Splunk Query:
```SPL
index=sysmon
```


Confirmed:

- Events from both DC01 and CLIENT01
- Process telemetry searchable

## Troubleshooting

### Issue 1 — Sysmon Logs Not Appearing in Splunk

**Root Cause**  
Sysmon channel not configured in forwarder inputs.

**Resolution**

inputs.conf:
```SPL
[WinEventLog://Microsoft-Windows-Sysmon/Operational]
index=sysmon
```


Restarted Splunk Forwarder.

### Issue 2 — Forwarder Permission Error

**Root Cause**  
Forwarder running under Local Service.

**Resolution**

Changed service account: \
Local System

Restarted forwarder.

## Lessons Learned

- Sysmon installation alone does not guarantee ingestion.
- Each Windows event channel must be explicitly configured.
- Always validate telemetry locally before SIEM troubleshooting.
