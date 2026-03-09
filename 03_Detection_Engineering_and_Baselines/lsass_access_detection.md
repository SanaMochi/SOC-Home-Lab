# LSASS Access Detection – Credential Dumping Behavior

## Objective

Detect potential credential dumping attempts targeting LSASS memory.

Attackers commonly access LSASS to extract:

- Plaintext credentials
- NTLM hashes
- Kerberos tickets

Credential dumping often leads directly to lateral movement and domain compromise.

## Data Source

Sysmon Event ID 10 – Process Access

<p align="center">
  <img src="https://github.com/SanaMochi/SOC-Home-Lab/blob/main/03_Detection_Engineering_and_Baselines/Screenshots/event10.png" width=90% />
</p>

Sysmon Event ID 10 logs when a process attempts to access another process.

Critical target:\
lsass.exe

## Detection Logic

Credential dumping tools such as:

- Mimikatz
- ProcDump
- Custom loaders

attempt to open LSASS with high access rights.

Suspicious access masks include:

- 0x1010
- 0x1410
- 0x1fffff

## Splunk Detection Query

```SPL
index=sysmon EventCode=10 TargetImage="*lsass.exe"
```

This identifies processes attempting to access LSASS memory.

## Enhanced Detection (Exclude Known Benign Sources)

```SPL
index=sysmon EventCode=10 TargetImage="*lsass.exe"
| search NOT SourceImage="*MsMpEng.exe"
```

Microsoft Defender commonly accesses LSASS legitimately.

## Sentinel Detection Query (KQL)
```KQL
DeviceEvents
| where ActionType == "OpenProcessApiCall"
| where FileName =~ "lsass.exe"
| where not(InitiatingProcessFileName has_any ("MsMpEng.exe", "SenseIR.exe"))
| project TimeGenerated, DeviceName, InitiatingProcessFileName, InitiatingProcessCommandLine, AccountName
| sort by TimeGenerated desc
```

`InitiatingProcessFileName` is the equivalent of `SourceImage` in Sysmon Event ID 10.

## Key Investigation Fields

| Field         | Purpose                      |
| ------------- | ---------------------------- |
| SourceImage   | Process attempting access    |
| TargetImage   | Target process (lsass.exe)   |
| GrantedAccess | Access permissions requested |
| host          | Affected endpoint            |

Source process context is critical for determining malicious behavior.

## False Positive Considerations

Legitimate LSASS access may occur from:
- Antivirus tools
- Endpoint detection platforms
- Backup or security utilities

False positives usually show:
- Consistent process paths
- Signed binaries
- Known security tooling

## Tuning Strategy

Improve accuracy by:
- Excluding known security tools
- Flagging execution from:
  - Temp directories
  - User directories
- Correlating with process creation events

Example suspicious indicators:
- procdump.exe
- rundll32.exe
- powershell.exe

## Detection Value

LSASS access is a high-impact security event because:
- It typically occurs after initial compromise
- It often precedes lateral movement
- It directly targets credential material

This detection provides strong visibility into post-exploitation activity.

## MITRE ATT&CK Mapping

Technique:\
T1003.001 – OS Credential Dumping: LSASS Memory
