# Encoded PowerShell — Investigation Walkthrough

## Investigator Perspective

This document walks through the investigation as it would be performed by a Tier 2 SOC
analyst. The starting point is a Sysmon process creation event surfaced in Splunk showing
a PowerShell process with an encoded command line. The goal is to determine what executed,
confirm whether it was malicious, and identify the scope.

## Step 1 — Initial Detection

The detection query flagged two PowerShell process creation events (Sysmon Event ID 1)
on CLIENT01 within the last hour. Both events showed PowerShell launched with obfuscation
flags in the CommandLine field.

First triage questions:
- Is this a known administrative script or scheduled task? — No, executed interactively
  from Windows Terminal by CORP\Administrator
- Is the parent process expected? — wt.exe → WindowsTerminal.exe → powershell.exe is
  a human-initiated execution chain, not an automated task
- Is the encoded content visible? — Yes, the Base64 string is present in the CommandLine
  field in Sysmon

Verdict: Investigate further.

## Step 2 — Scope the Execution

Both events originated from CLIENT01, executed by CORP\Administrator, with working
directory C:\Temp. Two variants were observed:

| Time | CommandLine Flags | Host |
|------|------------------|------|
| 03:23:18 | -NoProfile -NonInteractive -WindowStyle Hidden -ExecutionPolicy Bypass -EncodedCommand | CLIENT01 |
| 03:24:38 | -nop -w hidden -enc | CLIENT01 |

The abbreviated variant (`-nop -w hidden -enc`) is the more commonly seen pattern in
real-world attacks as it is shorter and less likely to be caught by basic string matching
rules that look for the full flag names.

<p align="center">
  <img src="https://github.com/SanaMochi/SOC-Home-Lab/blob/main/04_Incident_Case_Studies/02_Encoded_Powershell/Screenshots/detection.png" 
    width=100% />
</p>

## Step 3 — Decode the Payload

The Base64 string from the CommandLine field was extracted and decoded to reveal the
plaintext command:

```
Write-Output 'Simulated malicious payload executed' | Out-File C:\Temp\payload_executed.txt
```

<p align="center">
  <img src="https://github.com/SanaMochi/SOC-Home-Lab/blob/main/04_Incident_Case_Studies/02_Encoded_Powershell/Screenshots/decoded.png" 
    width=100% />
</p>

Decoding confirmed the payload wrote a file to disk. In a real attack this step would
reveal the actual malicious command — a download cradle, a reverse shell, a persistence
mechanism, or a credential harvesting script. The ability to decode Base64 payloads is
a core analyst skill for this exact reason.

Decode command used during investigation:
```powershell
$encoded = "PASTE_BASE64_HERE"
[System.Text.Encoding]::Unicode.GetString([System.Convert]::FromBase64String($encoded))
```

## Step 4 — Confirm Execution

Execution was confirmed two ways:

1. Sysmon Event ID 1 shows the process was created and completed
2. The output file C:\Temp\payload_executed.txt was written to disk, visible in the
   directory listing

<p align="center">
  <img src="https://github.com/SanaMochi/SOC-Home-Lab/blob/main/04_Incident_Case_Studies/02_Encoded_Powershell/Screenshots/cli.png" 
    width=100% />
</p>

In a real incident, confirming execution is critical — detecting a command is different
from confirming it ran successfully. Sysmon process creation events alone confirm the
process launched; file system artifacts and follow-on activity confirm the payload
completed.

## Step 5 — Review Full Sysmon Event

The raw Sysmon Event ID 1 captured the following key fields:

| Field | Value |
|-------|-------|
| Image | C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe |
| CommandLine | powershell.exe -NoProfile -NonInteractive -WindowStyle Hidden -ExecutionPolicy Bypass -EncodedCommand [Base64] |
| ParentImage | C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe |
| ParentCommandLine | C:\WINDOWS\System32\WindowsPowerShell\v1.0\powershell.exe |
| User | CORP\Administrator |
| IntegrityLevel | High |
| CurrentDirectory | C:\Temp\ |
| Hashes | MD5, SHA256, IMPHASH all captured |

<p align="center">
  <img src="https://github.com/SanaMochi/SOC-Home-Lab/blob/main/04_Incident_Case_Studies/02_Encoded_Powershell/Screenshots/full_log.png" 
    width=100% />
</p>

The IntegrityLevel of High confirms the process ran with elevated privileges. The
ParentImage being powershell.exe (spawning another powershell.exe) is itself a
behavioral indicator — legitimate admin scripts rarely spawn child PowerShell processes
this way.

## Step 6 — Timeline Reconstruction

| Time | Event | Source | Detail |
|------|-------|--------|--------|
| 03:23:18 | Encoded PowerShell executed (variant 1) | Sysmon EID 1 | Full flag obfuscation |
| 03:24:38 | Encoded PowerShell executed (variant 2) | Sysmon EID 1 | Abbreviated flag obfuscation |
| 03:28:30 | Defender alert fires | MDE | Suspicious PowerShell download or encoded command execution |
| 03:31:58 | Second Defender alert fires | MDE | Same alert, second execution |

Note: Defender alert timestamps reflect when the behavioral analysis completed, not
when the process executed. Raw Sysmon events in Splunk capture execution time directly.

## Step 7 — Key Investigation Questions Answered

**What did the encoded command actually do?**
Wrote a file to C:\Temp\payload_executed.txt. In a real attack the payload would
typically be a download cradle, reverse shell, or credential harvesting command.

**Was this a legitimate administrative action?**
No indicators of legitimate use — working directory C:\Temp, hidden window, execution
policy bypass, and interactive launch from Windows Terminal are not consistent with
scheduled maintenance tasks.

**What is the parent process chain?**
wt.exe → WindowsTerminal.exe → powershell.exe → powershell.exe (child). The human-
initiated chain from Windows Terminal confirms interactive execution by a logged-in user.

**Did Defender detect it?**
Yes — Defender generated a Medium severity alert: "Suspicious PowerShell download or
encoded command execution" with MITRE tags (T1059.001, T1027, T1057, T1106) applied automatically.
Defender also automatically decoded the command line in the alert details.

**What makes the abbreviated variant more dangerous?**
Simple detection rules that search for the string "-EncodedCommand" would miss the
`-enc` variant entirely. Both variants must be covered in detection logic.

## Step 8 — Recommended Response Actions

1. **Investigate** what account ran the script and whether the Administrator session
   was authorized at that time
2. **Review** all file writes by powershell.exe on CLIENT01 in the surrounding time
   window — look for dropped executables, scripts, or configuration changes
3. **Check** for network connections spawned by the PowerShell process — encoded
   commands are frequently download cradles connecting to C2 infrastructure
4. **Search** for the same Base64 string across all endpoints in the environment to
   determine if this was executed on other machines
5. **Harden** by enabling PowerShell Script Block Logging (Event ID 4104) which logs
   the decoded content of all executed scripts regardless of obfuscation
