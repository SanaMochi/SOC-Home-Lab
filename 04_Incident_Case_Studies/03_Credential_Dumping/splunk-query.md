# Credential Dumping — Splunk Detection Queries

## Data Source

- Index: sysmon
- Event ID: 10 (ProcessAccess)
- Primary field: TargetImage, SourceImage, GrantedAccess, CallTrace

Sysmon Event ID 10 is the standard telemetry source for LSASS access detection. It fires
when any process opens a handle to another process, capturing the source, target, and
the access rights requested (GrantedAccess). For LSASS dumping, the GrantedAccess value
is the most important field — higher values indicate more memory access rights.

## Query 1 — LSASS Access Detection (Standard)

```spl
index=sysmon EventCode=10 TargetImage="*lsass.exe"
| where NOT match(SourceImage, "(?i)MsMpEng|antimalware|defender|svchost|wininit")
| table _time host SourceImage TargetImage GrantedAccess CallTrace
| sort -_time
```

### What Each Line Does

| Line | Purpose |
|------|---------|
| `EventCode=10 TargetImage="*lsass.exe"` | Filter to process access events targeting LSASS |
| `NOT match(SourceImage, ...)` | Exclude known legitimate processes that access LSASS |
| `table ... GrantedAccess CallTrace` | Surface the access rights and call stack |
| `sort -_time` | Most recent first |

### GrantedAccess Values — What They Mean

| Value | Meaning | Suspicion Level |
|-------|---------|----------------|
| 0x1FFFFF | Full access — all rights | Critical |
| 0x1F3FFF | Full access variant | Critical |
| 0x143A | Read + query — sufficient for dumping | High |
| 0x1000 | Query limited information only | Low — often legitimate |
| 0x0410 | Read process memory | High |

In an unprotected environment a successful ProcDump against LSASS would show
GrantedAccess 0x1FFFFF — full memory access rights.

---

## Query 2 — Targeted ProcDump / Known Tool Detection

```spl
index=sysmon EventCode=10 TargetImage="*lsass.exe" SourceImage="*procdump*"
| table _time host SourceImage TargetImage GrantedAccess
```

### Result from This Simulation

![Splunk returning zero results — Defender prevented handle from being opened](../screenshots/splunk.png)

**0 events returned.** This is the correct finding for a prevented attack. Defender
terminated ProcDump before it reached the OpenProcess() system call, so Sysmon never
generated an Event ID 10. The absence of this event confirms prevention was complete.

This is an important analyst skill — knowing when zero results is a meaningful finding
rather than a query error.

## Query 3 — Broad Credential Dumping Tool Detection

```spl
index=sysmon EventCode=1
(Image="*procdump*" OR Image="*mimikatz*" OR Image="*sekurlsa*" OR CommandLine="*lsass*")
| table _time host Image CommandLine User
| sort -_time
```

This query catches credential dumping tool execution via Sysmon process creation (Event
ID 1) rather than the LSASS access itself. Useful as a complementary detection when
Event ID 10 is not available or when the tool is blocked before accessing LSASS.

## Query 4 — High GrantedAccess LSASS Requests

```spl
index=sysmon EventCode=10 TargetImage="*lsass.exe"
| eval suspicious=if(GrantedAccess="0x1FFFFF" OR GrantedAccess="0x1F3FFF" OR GrantedAccess="0x143A", "YES", "NO")
| where suspicious="YES"
| table _time host SourceImage GrantedAccess CallTrace
| sort -_time
```

This query specifically surfaces the highest-risk access requests. Use it when you have
a high volume of LSASS access events and need to triage by severity.

## Why Sysmon Returned No Results

In this simulation Sysmon Event ID 10 was not generated because Defender terminated
ProcDump at the execution layer before it could call OpenProcess() on lsass.exe.

The sequence of events:
1. procdump64.exe launched
2. Defender AV engine matched HackTool:Win32/DumpLsass.A signature
3. Process terminated immediately
4. No system calls to OpenProcess() were made
5. No Sysmon Event ID 10 generated

In environments without Defender endpoint protection, or when using more evasive
techniques (custom loaders, direct syscalls, process hollowing), Event ID 10 would
be generated and these queries would be your primary detection mechanism.

## Detection Engineering Notes

### Why Exclude MsMpEng.exe

Defender (MsMpEng.exe) legitimately accesses LSASS memory continuously for protection
purposes. Without this exclusion, every Defender scan generates noise in the detection.
Always exclude known security tools from LSASS access alerts — but maintain a separate
alert if security tool binaries themselves are replaced or tampered with.

### CallTrace Analysis

The CallTrace field in Event ID 10 shows the call stack leading to the OpenProcess()
call. Legitimate LSASS access comes from known Windows DLLs (ntdll.dll, sechost.dll).
Suspicious CallTrace values include:
- Unknown or unsigned DLLs in the stack
- Calls originating from unusual memory regions
- UNKNOWN regions indicating reflective loading or shellcode

### False Positive Considerations

| Source | Why It Accesses LSASS | How to Exclude |
|--------|----------------------|----------------|
| MsMpEng.exe | Defender real-time protection | Exclude by image path |
| svchost.exe | Windows security services | Exclude with GrantedAccess 0x1000 only |
| lsm.exe | Local session manager | Known legitimate |
| wininit.exe | Windows initialization | Known legitimate |
| AV/EDR products | Protection scanning | Exclude known vendor paths |

## Tuning Recommendations

- Alert immediately on GrantedAccess 0x1FFFFF from any non-system process
- Enable LSA Protection (RunAsPPL) — forces LSASS to run as a Protected Process Light,
  requiring a signed kernel driver to access it even with admin rights
- Block known credential dumping tool hashes via Defender custom indicators
- Monitor C:\Temp and user profile directories for .dmp file creation
