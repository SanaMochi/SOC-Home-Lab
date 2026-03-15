# SOC Home Lab — End-to-End Detection & Incident Response Environment

A self-built security operations lab simulating an enterprise Windows domain with a full
attack-detect-respond pipeline. Five attack techniques were simulated, detected across
multiple telemetry sources, and fully documented as analyst case studies with SPL queries,
KQL detections, raw event analysis, and incident response actions.

Built to demonstrate Tier 2 SOC analyst skills: detection engineering, multi-source
investigation, MITRE ATT&CK mapping, and structured incident documentation.

## Technologies

![Active Directory](https://img.shields.io/badge/Active%20Directory-0078D4?style=flat&logo=microsoft&logoColor=white)
![Splunk](https://img.shields.io/badge/Splunk-000000?style=flat&logo=splunk&logoColor=white)
![Microsoft Defender](https://img.shields.io/badge/Microsoft%20Defender-00A4EF?style=flat&logo=microsoft&logoColor=white)
![Microsoft Sentinel](https://img.shields.io/badge/Microsoft%20Sentinel-0078D4?style=flat&logo=microsoft&logoColor=white)
![Sysmon](https://img.shields.io/badge/Sysmon-666666?style=flat&logo=windows&logoColor=white)
![VMware](https://img.shields.io/badge/VMware-607078?style=flat&logo=vmware&logoColor=white)

- **Windows Server 2022** — Domain Controller (DC01), Active Directory, DNS
- **Windows 11 Enterprise** — Domain-joined endpoint (CLIENT01)
- **Splunk Enterprise** — Primary SIEM with Universal Forwarder on both VMs
- **Sysmon** — Endpoint telemetry via SwiftOnSecurity config (process, network, file, memory)
- **Microsoft Defender for Endpoint** — EDR on both VMs, onboarded to Microsoft 365 Defender
- **Microsoft Sentinel** — Cloud SIEM connected via Azure Arc + AMA, analytics rules, playbooks
- **Azure Logic Apps** — Automated response playbook triggered by Sentinel analytics rules
- **VMware Workstation** — Type 2 hypervisor, NAT networking (192.168.113.0/24)


## Lab Architecture

<p align="center">
  <img src="https://github.com/SanaMochi/SOC-Home-Lab/blob/main/01_Environment_Setup/Diagrams/network_architecture.png" width=50% />
</p>

| Host | Role | IP |
|------|------|----|
| DC01 | Domain Controller, DNS, AD DS | 192.168.113.10 |
| CLIENT01 | Domain-joined workstation | 192.168.113.20 |
| Gateway | VMware NAT | 192.168.113.2 |

**Domain:** corp.local  
**Splunk Indexes:** wineventlog (Windows Security/System), sysmon (Sysmon telemetry)


## Lab Goals

- Simulate an enterprise Windows domain with realistic user and group structure
- Generate authentic attack telemetry across five MITRE ATT&CK techniques
- Build detection queries in both SPL (Splunk) and KQL (Sentinel)
- Investigate each attack from raw events through to analyst conclusions
- Document findings in structured case studies matching real SOC workflows
- Demonstrate incident response actions: device isolation, account containment, SOAR automation


## Attack Simulations & Detections

Five attacks were simulated across the kill chain, each generating real telemetry and
documented with full investigation walkthroughs.

| # | Technique | MITRE | Detection Source | Defender Alert |
|---|-----------|-------|-----------------|----------------|
| 1 | [Brute Force Authentication](04_Incident_Case_Studies/01_Brute_Force/) | T1110.001 | Splunk (EID 4625/4624) | Process tree captured |
| 2 | [Encoded PowerShell Execution](04_Incident_Case_Studies/02_Encoded_PowerShell/) | T1059.001, T1027 | Splunk (Sysmon EID 1) + Defender | ✅ Medium alert fired |
| 3 | [Credential Dumping — LSASS](04_Incident_Case_Studies/03_Credential_Dumping/) | T1003.001 | Defender (prevention) | ✅ Blocked — HackTool:Win32/DumpLsass.A |
| 4 | [Privilege Escalation — Domain Admins](04_Incident_Case_Studies/04_Privilege_Escalation/) | T1098 | Splunk (EID 4728/4729) + Sentinel | ✅ Sentinel named alert |
| 5 | [Lateral Movement — PsExec Pattern](04_Incident_Case_Studies/05_Lateral_Movement/) | T1021.002, T1543.003 | Splunk (EID 4624 Type3 + EID 7045) | Not detected — SIEM-only finding |

Each case study includes: attack overview, step-by-step investigation walkthrough,
annotated Splunk queries, and Defender/Sentinel investigation.


## Key Skills Demonstrated

- **Active Directory** — Domain deployment, OU structure, group policy, user/group management
- **Multi-source telemetry pipeline** — Sysmon + Windows event forwarding + Splunk + Defender + Sentinel
- **Detection engineering** — SPL and KQL query writing with field-level analysis and tuning notes
- **Dual-SIEM investigation** — Correlating findings across Splunk (on-prem) and Sentinel (cloud)
- **MITRE ATT&CK mapping** — Technique identification, tactic context, detection gap analysis
- **Incident investigation** — Raw event analysis, timeline reconstruction, pivot methodology
- **EDR analysis** — Defender process trees, behavioral alerts, prevention vs detection distinction
- **Incident response** — Device isolation, forensic package collection, account disabling
- **SOAR automation** — Sentinel analytics rule → automation rule → Logic App playbook → email alert


## Repository Navigation

```
SOC-Home-Lab/
│
├── 01_Environment_Setup/           ← Lab infrastructure documentation
│   ├── domain_build.md             — AD DS installation, domain configuration
│   ├── network_config.md           — VMware networking, IP scheme, firewall
│   ├── vm_details.md               — VM specs, OS versions, domain join
│   └── Diagrams/
│       └── network_architecture.png
│
├── 02_Telemetry_Pipeline/          ← Detection stack configuration
│   ├── sysmon_deployment.md        — Sysmon install, SwiftOnSecurity config
│   ├── splunk_ingestion.md         — Splunk Enterprise setup, index config, UF deployment
│   ├── defender_onboarding.md      — MDE onboarding for both VMs
│   └── sentinel_connectors.md      — Azure Arc, AMA, Sentinel workspace config
│
├── 03_Detection_Engineering/       ← Detection rules with SPL + KQL
│   ├── brute_force_detection.md    — EID 4625/4624 threshold and correlation queries
│   ├── encoded_powershell_detection.md  — Sysmon EID 1 CommandLine flag detection
│   ├── lsass_access_detection.md   — Sysmon EID 10 GrantedAccess analysis
│   ├── privilege_escalation_detection.md — EID 4728/4729 group membership monitoring
│   └── service_creation_detection.md  — EID 7045 + EID 4624 Type 3 correlation
│
├── 04_Incident_Case_Studies/       ← Full investigation documentation per attack
│   ├── 01_Brute_Force/
│   │   ├── attack_overview.md
│   │   ├── investigation.md        — Step_=-by-step Tier 2 investigation walkthrough
│   │   ├── splunk_query.md         — Annotated SPL with results and tuning notes
│   │   ├── defender_investigation.md
│   │   └── screenshots/
│   │
│   ├── 02_Encoded_PowerShell/
│   │   ├── attack_overview.md
│   │   ├── investigation.md
│   │   ├── splunk_query.md
│   │   ├── defender_investigation.md  — Defender auto-decoded Base64, MITRE auto-tagged
│   │   └── screenshots/
│   │
│   ├── 03_Credential_Dumping/
│   │   ├── attack_overview.md
│   │   ├── investigation.md
│   │   ├── splunk_query.md         — Includes zero-result analysis (prevention confirmed)
│   │   ├── defender_investigation.md  — Prevention event, dual filename detection
│   │   └── screenshots/
│   │
│   ├── 04_Privilege_Escalation/
│   │   ├── attack_overview.md
│   │   ├── investigation.md
│   │   ├── splunk_query.md         — Add/remove pair detection, exposure window calc
│   │   ├── defender_investigation.md  — Sentinel named alert with plain-language description
│   │   └── screenshots/
│   │
│   └── 05_Lateral_Movement/
│       ├── attack_overview.md
│       ├── investigation.md
│       ├── splunk_query.md         — EID 4624 Type 3 + EID 7045 correlation query
│       ├── defender_investigation.md  — No EDR detection — SIEM-only finding documented
│       └── screenshots/
│
└── 05_Incident_Response_Actions/   ← Containment and response documentation
    ├── defender_containment.md     — Device isolation, investigation package, audit trail
    ├── account_disable.md          — AD account disabling via PowerShell + ADUC
    └── sentinel_playbooks.md       — Logic App playbook: Sentinel alert → email notification
```


## Detection Coverage Summary

| Event Source | Event IDs Monitored | Techniques Covered |
|-------------|--------------------|--------------------|
| Windows Security Log | 4624, 4625, 4728, 4729, 4725 | Brute force, lateral movement, privilege escalation, account changes |
| Windows System Log | 7045 | Service creation (PsExec pattern) |
| Sysmon | EID 1, 10 | Process execution, LSASS memory access |
| Microsoft Defender for Endpoint | Behavioral alerts, prevention events | Encoded PowerShell, credential dumping |
| Microsoft Sentinel | Analytics rules, named alerts | Domain Admins group modification, account disable |



## Notable Findings Across Attacks

**Attack 3 — Credential Dumping:** Defender blocked ProcDump before Sysmon generated
Event ID 10. The correct analyst finding was zero Splunk results confirming prevention —
not a query failure. Demonstrates detection vs prevention distinction.

**Attack 4 — Privilege Escalation:** Microsoft Sentinel fired a named alert ("An account
was added to the Domain Admins group") independently of Splunk, sourced from the Windows
Security log via AMA. Shows SIEM specialization — Sentinel detects directory changes,
Defender detects endpoint behavior.

**Attack 5 — Lateral Movement:** No Defender alert fired. The PsExec pattern uses only
signed Windows binaries (net use, sc.exe, cmd.exe) with no malicious file on disk —
architecturally indistinguishable from legitimate remote administration. SIEM (Splunk)
is the only viable detection layer for this technique class.


## Environment Setup

> Full setup documentation is in [01-Environment_Setup/](01_Environment_Setup/) and
> [02_Telemetry/](02_Telemetry/)

**Quick reference — VM specs:**

| VM | OS | RAM | vCPU | Role |
|----|-----|-----|------|------|
| DC01 | Windows Server 2022 | 4GB | 2 | Domain Controller |
| CLIENT01 | Windows 11 Enterprise | 4GB | 2 | Workstation |
