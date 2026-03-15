# Encoded PowerShell — Splunk Detection Queries

## Data Source

- Index: sysmon
- Event ID: 1 (Process Creation)
- Host: CLIENT01

Sysmon Event ID 1 is the primary telemetry source for this detection because it captures
the full CommandLine of every process at launch — including the Base64 encoded string
passed to PowerShell. Windows Security logs do not capture command line arguments,
making Sysmon essential for this detection class.

## Query 1 — Broad PowerShell Process Creation

```spl
index=sysmon EventCode=1 Image="*powershell.exe"
| table _time host CommandLine ParentImage User
| sort -_time
```

### What Each Line Does

| Line | Purpose |
|------|---------|
| `index=sysmon EventCode=1` | Scope to Sysmon process creation events |
| `Image="*powershell.exe"` | Filter to PowerShell processes only |
| `table _time host CommandLine ParentImage User` | Surface the fields most useful for triage |
| `sort -_time` | Most recent first |

### When to Use

Use this as your starting query when triaging a PowerShell-related alert. It gives a
broad view of all PowerShell executions and lets you spot anomalies in the CommandLine
column before narrowing the search.

<p align="center">
  <img src="https://github.com/SanaMochi/SOC-Home-Lab/blob/main/04_Incident_Case_Studies/02_Encoded_Powershell/Screenshots/sysmon.png" 
    width=100% />
</p>


Note: This query returns 315 events because it covers all PowerShell activity in the
time window including Splunk's own forwarder processes. The encoded commands appear at
the top sorted by most recent time.

## Query 2 — Targeted Encoded PowerShell Detection

```spl
index=sysmon EventCode=1 Image="*powershell.exe"
(CommandLine="*-enc*" OR CommandLine="*encodedcommand*" OR CommandLine="*-nop*" OR CommandLine="*-hidden*")
| table _time host CommandLine ParentImage
| sort -_time
```

### What Each Line Does

| Line | Purpose |
|------|---------|
| `index=sysmon EventCode=1 Image="*powershell.exe"` | Scope to PowerShell process creation |
| `CommandLine="*-enc*" OR ...` | Match any of the known obfuscation flag patterns |
| `table _time host CommandLine ParentImage` | Surface execution context |
| `sort -_time` | Most recent first |

### Why Multiple Patterns

Attackers abbreviate flags to evade detection. Both forms must be covered:

| Full Flag | Abbreviated | Detected By |
|-----------|-------------|-------------|
| -EncodedCommand | -enc | `*-enc*` OR `*encodedcommand*` |
| -WindowStyle Hidden | -w hidden | `*-hidden*` |
| -NoProfile | -nop | `*-nop*` |
| -NonInteractive | -NonI | not covered — add `*-nonI*` if needed |

<p align="center">
  <img src="https://github.com/SanaMochi/SOC-Home-Lab/blob/main/04_Incident_Case_Studies/02_Encoded_Powershell/Screenshots/detection.png" 
    width=100% />
</p>

This query returned exactly 11 events — the two malicious executions plus some
surrounding PowerShell activity matching the flag patterns. In a production environment
this would be tuned further with exclusions for known administrative scripts.

## Query 3 — Raw Event Investigation

```spl
index=sysmon EventCode=1 Image="*powershell.exe" CommandLine="*-EncodedCommand*"
| table _time host User CommandLine ParentImage ParentCommandLine IntegrityLevel
```

Use this to pull the specific full-flag variant event with all context fields for
documentation and escalation.

<p align="center">
  <img src="https://github.com/SanaMochi/SOC-Home-Lab/blob/main/04_Incident_Case_Studies/02_Encoded_Powershell/Screenshots/full_log.png" 
    width=90% />
</p>

### Key Fields to Document in Every Investigation

| Field | Why It Matters |
|-------|---------------|
| CommandLine | Contains the Base64 string to decode |
| ParentImage | Reveals what launched PowerShell — unexpected parents are red flags |
| ParentCommandLine | Full context of the parent process |
| User | Who was logged in — expected admin or compromised account |
| IntegrityLevel | High = elevated privileges, increases severity |
| CurrentDirectory | C:\Temp is suspicious — legitimate scripts usually run from system paths |
| Hashes | Can be used to pivot to VirusTotal or threat intel platforms |

## How to Decode During Investigation

When you find a Base64 string in a CommandLine field, decode it directly in PowerShell:

```powershell
$encoded = "PASTE_BASE64_STRING_HERE"
[System.Text.Encoding]::Unicode.GetString([System.Convert]::FromBase64String($encoded))
```

Note: PowerShell encodes commands in Unicode (UTF-16LE), not standard UTF-8 Base64.
Using the wrong encoding during decode will produce garbled output. Always use
`[System.Text.Encoding]::Unicode` for PowerShell -EncodedCommand payloads.

## False Positive Considerations

| Scenario | How to Distinguish |
|----------|--------------------|
| Legitimate admin scripts | Known script path, expected parent process (Task Scheduler, specific admin tool), documented change ticket |
| Software deployment tools | Source is SYSTEM or a known service account, parent is a known deployment binary |
| Splunk/monitoring tools | Parent image matches known monitoring software path |

Recommended exclusion pattern for known tools:
```spl
| where NOT match(ParentImage, "(?i)splunk|sccm|tanium|cylance")
```

## Tuning Recommendations

- Add PowerShell Script Block Logging (Event ID 4104) — logs decoded content of every
  script block regardless of obfuscation, eliminates the need to manually decode
- Alert on PowerShell spawned by unexpected parents: Office applications, browsers,
  WMI, or scheduled tasks with no associated change record
- Lower threshold for High integrity level executions — elevated PowerShell with
  encoding flags should be near-zero in a hardened environment
