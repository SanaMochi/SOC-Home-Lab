
# Encoded PowerShell Detection – Sysmon Process Creation

## Objective

Detect obfuscated PowerShell execution using encoded command-line arguments.

Attackers frequently use encoded PowerShell to:

- Hide malicious scripts
- Bypass signature-based detection
- Execute fileless payloads

Encoded PowerShell is a high-signal behavioral indicator.

## Data Source

Sysmon Event ID 1 – Process Creation

Sysmon provides command-line visibility not available in default Windows logging.

Primary fields used:

- Image
- CommandLine
- ParentImage

## Detection Logic

Encoded PowerShell execution typically includes:

- -enc
- -encodedcommand
- Base64 strings

Common attacker flags:

- -nop
- -w hidden
- -executionpolicy bypass

These flags are frequently combined to evade detection.

## Splunk Detection Query

```SPL
index=sysmon EventCode=1
(Image="*powershell.exe")
(CommandLine="*-enc*" OR CommandLine="*encodedcommand*")
```

This identifies encoded PowerShell execution.

## Extended Detection (Common Obfuscation Flags)

```SPL
index=sysmon EventCode=1 Image="*powershell.exe"
(CommandLine="*-enc*" 
OR CommandLine="*-nop*" 
OR CommandLine="*-w hidden*" 
OR CommandLine="*executionpolicy bypass*")
```

This improves coverage of common attack patterns.

| Field       | Purpose                                 |
| ----------- | --------------------------------------- |
| CommandLine | Identify encoded or obfuscated commands |
| ParentImage | Determine execution source              |
| host        | Identify affected endpoint              |

Parent process context is critical for triage.

Example:
- explorer.exe → powershell.exe → often benign
- winword.exe → powershell.exe → suspicious

## False Positive Considerations

Encoded PowerShell may appear in:
- Administrative automation scripts
- Configuration tools
- Legitimate enterprise management platforms

False positives typically include:
- Known script paths
- Consistent administrative hosts
- Tuning Strategy

Improve detection quality by:
- Filtering known automation scripts
- Flagging unusual parent processes
- Monitoring execution from temp directories

Example tuning filter:
```SPL
| where NOT like(CommandLine,"%C:\\Program Files%")
```

## Detection Value

Encoded PowerShell detection provides strong coverage for:
- Fileless malware
- Living-off-the-land attacks
- Initial payload execution

Because obfuscation is rarely required for legitimate scripting, encoded commands are high-signal indicators.

## MITRE ATT&CK Mapping

Technique: \
T1059.001 – Command and Scripting Interpreter: PowerShell
