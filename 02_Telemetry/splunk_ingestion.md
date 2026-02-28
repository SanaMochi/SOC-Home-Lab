# Splunk Ingestion & Telemetry Pipeline

## Overview

Centralized log collection was implemented using **Splunk Enterprise** to support detection engineering and incident analysis within the SOC lab environment.

Telemetry from Windows endpoints is forwarded using the **Splunk Universal Forwarder** to a centralized SIEM instance.

## Log Forwarding Architecture

### Components

**SIEM**
- Splunk Enterprise (Primary log analysis platform)

**Endpoints**
- DC01 (Domain Controller)
- CLIENT01 (Windows Client)

**Forwarding Method**
- Splunk Universal Forwarder installed on all endpoints

<p align="center">
  <img src="https://github.com/SanaMochi/SOC-Home-Lab/blob/main/02_Telemetry/Screenshots/splunk/forwarder_running.png" width=50% />
</p>

## Telemetry Data Sources

### Windows Event Logs

The following native Windows logs were ingested:

- Application
- Security
- System

<p align="center">
  <img src="https://github.com/SanaMochi/SOC-Home-Lab/blob/main/02_Telemetry/Screenshots/splunk/win_log_splunk.png" width=70% />
</p>

These logs support:

- Authentication monitoring
- System behavior analysis
- Privilege change tracking

### Sysmon Operational Logs

Sysmon was deployed to provide enhanced endpoint telemetry including:

- Process creation
- Network connections
- Parent-child process relationships


<p align="center">
  <img src="https://github.com/SanaMochi/SOC-Home-Lab/blob/main/02_Telemetry/Screenshots/splunk/sysmon_log_splunk.png" width=70% />
</p>

This telemetry is used for detection engineering via SPL queries.

## Telemetry Pipeline Architecture

<p align="center">
  <img src="https://github.com/SanaMochi/SOC-Home-Lab/blob/main/02_Telemetry/Diagrams/Telemtry%20Pipeline.png" width=40% />
</p>

## Index Configuration

Two indexes were created to logically separate telemetry:

| Index | Purpose |
|------|----------|
| wineventlogs | Native Windows logs |
| sysmon | Sysmon endpoint telemetry |

Separating indexes improves:

- Query performance  
- Detection organization  
- Troubleshooting clarity  


## Validation Sequence

Validation was performed incrementally to ensure reliable ingestion.


### 1. Endpoint Validation

Confirmed events exist locally:

- Event Viewer  
  - Windows Logs → Security  
  - Applications and Services → MIcrosoft → Windows→ Sysmon → Operational

### 2. Forwarder Validation

Verified:

- Splunk Forwarder service running
- inputs.conf properly configured

### 3. Network Validation

Confirmed:

- Port **9997** open on SIEM
- Forwarder successfully connected

### 4. Index Validation

Verified indexes exist:

- wineventlogs  
- sysmon  

### 5. SIEM Search Validation

Test queries:
```SPL
index=wineventlogs
```
```SPL
index=sysmon
```


Confirmed events returned successfully.

## Troubleshooting

### Issue 1 — Splunk Not Receiving Forwarded Logs

**Problem**  
Splunk was not receiving logs from the Universal Forwarder.

**Root Cause**  
Receiving port **9997** was not enabled on the Splunk server.

**Resolution**
- Enabled receiving:
  - Splunk Web → Settings → Forwarding and Receiving  
  - Configure Receiving → New Receiving Port → 9997
- Restarted Splunk service

**Validation** \
Forwarder reconnected and events began ingesting.

### Issue 2 — Logs Missing Due to Index Configuration

**Problem**  
Windows logs were not appearing correctly in search results.

**Root Cause**  
Required indexes had not yet been created in Splunk.

**Resolution**
Created indexes:

- wineventlogs  
- sysmon  

After creation:
- Windows logs ingested successfully
- Sysmon ingestion investigated separately

**Validation**
```SPL
index=wineventlogs
```

Returned authentication events as expected.

## Lessons Learned

- Splunk ingestion requires both:
  - Active receiving ports
  - Correct index configuration
- Forwarder connectivity alone does not guarantee ingestion
- Validate telemetry incrementally:
  1. Windows logs  
  2. Sysmon logs  
  3. Detection queries

This approach reduces troubleshooting complexity in multi-source environments.
