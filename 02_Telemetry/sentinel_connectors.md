# Microsoft Sentinel Data Connectors

## Overview

Microsoft Sentinel was deployed as the cloud SIEM platform to centralize telemetry from on-premise lab systems.

Data ingestion was configured through Azure Arc and Azure Monitor Agent (AMA) to collect security telemetry from domain infrastructure and endpoint systems.

Sentinel enables cloud-based threat hunting, detection engineering, and cross-source correlation using KQL.

## Data Sources Connected

### Microsoft Defender for Endpoint

Microsoft Defender for Endpoint was integrated with my Sentinel workspace to provide EDR behavioral telemetry and alert correlation.

<p align="center">
  <img src="https://github.com/SanaMochi/SOC-Home-Lab/blob/main/02_Telemetry/Screenshots/sentinnel-connectors/xdrpng.png" width=90% />
</p>

This data complements raw log ingestion by adding behavioral detection signals.

### Windows Security Events (via Azure Monitor Agent)

Domain and endpoint systems were onboarded through Azure Arc and configured with Data Collection Rules (DCR) to ingest Windows Security Event Logs.

Collected events include:
- 4624 — Successful logon
- 4625 — Failed logon
- 4728 — User added to privileged group
- 4729 — User removed from group
- 7045 — Service creation

These logs provide visibility into:
- Authentication activity
- Privilege escalation
- Persistence techniques

### Sysmon Telemetry (via Azure Monitor Agent)

Sysmon logs were ingested from both lab machines using custom XPath queries in the Data Collection Rule.

Sysmon events collected include:
- Event ID 1 — Process creation
- Event ID 3 — Network connection
- Event ID 5 — Process termination
- Event ID 7 — Image loaded
- Event ID 8 — CreateRemoteThread
- Event ID 10 — Process access
- Event ID 11 — File creation
- Event ID 13 — Registry modification
- Event ID 22 — DNS query

This telemetry provides deep visibility into:
- Process execution chains
- Command-line activity
- Network communications
- Credential access attempts


## Architecture

Telemetry Pipeline:

<p align="center">
  <img src="https://github.com/SanaMochi/SOC-Home-Lab/blob/main/02_Telemetry/Diagrams/Telemetry%20Pipeline%20Sentinel.png" width=30% />
</p>

This architecture mirrors modern hybrid enterprise environments where on-prem systems stream telemetry to cloud SIEM platforms.

## Detection Value

Microsoft Sentinel enables:
- Centralized threat hunting across hosts
- Correlation between endpoint telemetry and authentication activity
- Investigation using Kusto Query Language (KQL)

Examples of telemetry used in detection engineering include:
- Brute-force authentication attempts
- Encoded PowerShell execution
- Suspicious process creation
- Credential access attempts

## Validation

Successful ingestion was verified by:
- Confirming Azure Arc connectivity for DC01 and CLIENT01

<p align="center">
  <img src="https://github.com/SanaMochi/SOC-Home-Lab/blob/main/02_Telemetry/Screenshots/sentinnel-connectors/arc.png" width=100% />
</p>
  
- Verifying Azure Monitor Agent installation

<p align="center">
  <img src="https://github.com/SanaMochi/SOC-Home-Lab/blob/main/02_Telemetry/Screenshots/sentinnel-connectors/ama.png" width=90% />
</p>
  
- Validating Data Collection Rule assignments

<p align="center">
  <img src="https://github.com/SanaMochi/SOC-Home-Lab/blob/main/02_Telemetry/Screenshots/sentinnel-connectors/dcr.png" width=70% />
</p>

- Confirming Windows Security and Sysmon logs visible in KQL queries

<p align="center">
  <img src="https://github.com/SanaMochi/SOC-Home-Lab/blob/main/02_Telemetry/Screenshots/sentinnel-connectors/logs.png" width=70% />
</p>

Both machines generate searchable telemetry in Sentinel.
