# Case Study 05 — Lateral Movement via PsExec Pattern (Service Creation)

## Attack Summary

Lateral movement via remote service creation is one of the most common post-exploitation
techniques observed in real-world intrusions. After obtaining domain administrator credentials,
an attacker can pivot from a compromised workstation to a domain controller or other high-value
target by establishing a network connection and remotely installing a service that executes
arbitrary commands. This is the exact technique implemented by PsExec, Impacket's psexec.py,
and Metasploit's psexec module — all of which are staples of both red team operations and
active threat actor playbooks.

In this simulation, the attack was executed from CLIENT01 using built-in Windows tools that
generate identical telemetry to real PsExec usage. A Type 3 network logon was established to
DC01 via the ADMIN$ administrative share, followed by remote service creation using sc.exe.
The service binary path was set to a cmd.exe command — the same structural pattern used by
real PsExec to achieve remote code execution. Both steps generated the expected Windows
Security and System log events on DC01, confirming authentic, analyst-grade telemetry.

## Why Attackers Use This Technique

- Leverages legitimate Windows functionality — no malware required
- ADMIN$ share access and sc.exe are both built-in, signed Windows components
- The PsExec pattern is executable with Impacket from Linux with no Windows tools at all
- Domain admin credentials are sufficient — no additional exploitation required
- Service creation runs commands as SYSTEM — the highest privilege level on Windows
- Works across the entire domain once a single domain admin account is compromised

## Attack Chain Position

Lateral movement follows successful credential access and enables escalation to the most
sensitive assets in the environment:

Initial Access → Execution → Credential Access → **Lateral Movement** → Domain Dominance

MITRE ATT&CK:
- T1021.002 — Remote Services: SMB/Windows Admin Shares
- T1543.003 — Create or Modify System Process: Windows Service
- T1569.002 — System Services: Service Execution

## Simulation Details

| Field | Value |
|-------|-------|
| Source Host | CLIENT01 (192.168.113.20) |
| Target Host | DC01 (DC01.corp.local) |
| Attacker Account | CORP\Administrator (SID -500) |
| Step 1 — Network Logon | `net use \\DC01\ADMIN$ /user:corp\administrator` |
| Step 2 — Service Creation | `sc.exe \\DC01 create SimulatedPsExec binpath= "cmd.exe /c echo lateral_movement_test > C:\Temp\lateral_test.txt" start= demand` |
| Step 3 — Service Start | `sc.exe \\DC01 start SimulatedPsExec` |
| Service Start Result | Failed (error 1053) — cmd.exe exits immediately without registering with SCM |
| 4624 Event Time | 2026-03-12 21:14:39.405 |
| 7045 Event Time | 2026-03-12 21:16:04.652 |
| Time Between Events | ~85 seconds |

## Detection Outcome

This simulation produced **full detection via SIEM, with no EDR detection**.

The attack chain was completely visible in Splunk: the Type 3 network logon (EventCode 4624)
appeared on DC01 at 21:14:39, sourced from 192.168.113.20 (CLIENT01), followed by service
creation (EventCode 7045) at 21:16:04 with SimulatedPsExec and a cmd.exe binary path.

Microsoft Defender for Endpoint generated no meaningful alert. The only event on DC01's
timeline was an AntivirusReport on services.exe at 21:16:05 — routine background AV scanning
with no connection to the attack. Defender saw no malicious binary, no suspicious child
process, and no behavioral pattern to alert on because the attack used only signed,
legitimate Windows components throughout.

| Control Layer | Outcome |
|--------------|---------|
| Windows Security Log (4624) | Type 3 logon from 192.168.113.20 logged on DC01 |
| Windows System Log (7045) | SimulatedPsExec service creation logged on DC01 |
| Splunk correlation query | Both events visible in chronological attack chain |
| Microsoft Defender for Endpoint | No detection — background AV noise only |

## Service Start Failure — Expected Behavior

The `sc.exe \\DC01 start SimulatedPsExec` command returned error 1053:
*"The service did not respond to the start or control request in a timely fashion."*

This is expected and does not affect the validity of the simulation. The Service Control
Manager expects a service binary to register itself within a timeout window. A plain
`cmd.exe /c echo` command exits immediately without performing that registration, triggering
the timeout. In a real PsExec attack, the service binary is purpose-built to execute its
payload and complete the SCM handshake before exiting. The critical telemetry — the 4624
Type 3 logon and the 7045 service installation — was fully generated and captured regardless.

## Telemetry Sources

| Source | Events Generated |
|--------|-----------------|
| Windows Security Log (DC01) | EventCode 4624 — Type 3 network logon, Administrator from 192.168.113.20 |
| Windows System Log (DC01) | EventCode 7045 — SimulatedPsExec, cmd.exe binary path, LocalSystem |
| Splunk wineventlog index | Both events indexed and queryable with full field extraction |
| Microsoft Defender for Endpoint | No attack-relevant detection |
