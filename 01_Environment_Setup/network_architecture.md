# SOC Lab Network Architecture

## Overview

This lab simulates a small enterprise environment consisting of:

- On-prem Active Directory domain
- Windows endpoint telemetry
- SIEM ingestion pipelines
- Cloud-based detection and response

The goal is to generate realistic Windows security telemetry and perform detection and investigation workflows.


## Architecture Diagram

<p align="center">
  <img src="https://github.com/SanaMochi/SOC-Home-Lab/blob/main/01_Environment_Setup/Diagrams/network_architecture.png" width 50% />
</p>

## Infrastructure Components

### Hypervisor
- VMware Workstation
- NAT networking

### Virtual Machines

| Hostname | OS | Role | IP |
|----------|----|------|----|
| DC01 | Windows Server 2022 | Domain Controller / DNS | 192.168.10.10 |
| CLIENT01 | Windows 11 Enterprise | Domain Endpoint | 192.168.10.20 |

## Domain Architecture

- Forest: corp.local
- Single domain design
- Domain services:
  - Active Directory Domain Services
  - DNS

CLIENT01 is joined to the domain for centralized authentication and policy enforcement.

## Logging Architecture

### Endpoint Telemetry Sources

DC01 and CLIENT01 generate:

- Windows Events Logs:
  - Security
  - System
  - Application
- Sysmon Logs

These logs are forwarded to:

- Splunk (on-prem SIEM)
- Microsoft Sentinel (cloud SIEM/SOAR)

## Cloud Security Stack

Microsoft security tools used:

- Defender for Endpoint (EDR telemetry)
- Microsoft Sentinel (SIEM/SOAR)

Defender sends alerts and device telemetry into Sentinel for investigation.

## Network Flow

1. Domain authentication traffic: \
   CLIENT01 → DC01

2. Log ingestion: \
   Endpoint → SIEM platforms

3. Security telemetry: \
   Endpoint → Defender → Sentinel
