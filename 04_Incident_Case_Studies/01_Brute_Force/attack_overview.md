# Case Study 01 — Brute Force Authentication Attack

## Attack Summary

A brute force attack involves repeated authentication attempts against one or more accounts 
using incorrect credentials. The goal is to guess a valid password through volume, either by 
targeting a single account with many passwords (brute force) or targeting many accounts with 
one password (password spray).

In this simulation, repeated failed logon attempts were generated against the jdoe domain 
account from CLIENT01, followed by successful authentication — replicating the pattern of an 
attacker who successfully guesses a password after repeated attempts.

## Why Attackers Use This Technique

- Exploits weak or commonly used passwords
- Requires no prior access to the environment
- Can be automated at scale
- Successful credential compromise enables lateral movement, privilege escalation, and 
  persistent access

## Attack Chain Position

Brute force sits at the earliest stage of an attack chain:

Initial Access → Credential Access → (Valid Credentials Obtained) → Lateral Movement

MITRE ATT&CK: T1110 — Brute Force
Sub-technique: T1110.001 — Password Guessing

## Environment

| Field | Value |
|-------|-------|
| Source Host | CLIENT01 (192.168.113.20) |
| Target Account | jdoe |
| Attacker Account | corp\Administrator |
| Authentication Target | DC01 |
| Attack Duration | ~60 seconds |
| Total Failed Attempts | 32 |
| Successful Logins After Failures | 22 |

## Telemetry Sources

| Source | Events |
|--------|--------|
| Windows Security Log | Event ID 4625 (failed), 4624 (success) |
| Splunk (wineventlog index) | Authentication pattern detection |
| Microsoft Defender for Endpoint | PowerShell execution timeline, process tree |

## Key Observation

During this simulation, two accounts generated anomalous authentication patterns — jdoe 
(the intended target) and Administrator (executed attack). It took 30 attempts for the password to be found.
