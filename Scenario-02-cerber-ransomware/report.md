# Scenario 02 — Cerber Ransomware Investigation

**Dataset:** Splunk BOTSv1  
**Scope:** Exercises 4.11–4.14  
**Evidence:** Three Splunk screenshots and a cited external malware analysis  
**Environment:** Public training lab

## 1. Summary

I investigated the execution associated with `121214.tmp`, counted distinct `.txt` paths in Bob Smith's profile, and examined a firewall event for a suspicious download.

The process event shows `wscript.exe` running `20429.vbs` as the parent of a `cmd.exe` process whose command line starts `121214.tmp`. The recorded parent process ID is **3968**. A separate profile-scoped search returns **406** distinct text-file paths. The firewall event identifies **mhtr.jpg**, downloaded from `92.222.104.182`, and records a malware detection with an action of `monitored` and no quarantine.

External research links this filename and delivery address to Cerber and describes **steganography** as the concealment technique. The screenshots support the lab findings but do not establish the full infection chain or demonstrate payload extraction.

## 2. Key findings

| Item | Value | Basis |
|---|---|---|
| Workstation | `we8105desk` | Sysmon event and file-count search |
| Account | `WAYNECORPINC\bob.smith` | Process event |
| Windows profile | `C:\Users\bob.smith.WAYNECORPINC` | Process and file paths |
| Parent process ID | `3968` | `ParentProcessId` in the process event |
| Parent image | `C:\Windows\SysWOW64\wscript.exe` | `ParentImage` |
| Script | `20429.vbs` | Parent command line |
| Child process | `cmd.exe`, PID `1476` | `Image` and `ProcessId` |
| Launch target | `121214.tmp` | Child command line |
| Distinct text-file paths | `406` | `dc(TargetFilename)` |
| Download filename | `mhtr.jpg` | Firewall event |
| Download source | `92.222.104.182` | Firewall `dstip` |
| Internal source IP | `192.168.250.100` | Firewall `srcip` |
| Detection | `Malware_Generic.P0` | Firewall `virus` |
| Firewall action | `monitored` | Extracted original action |
| Quarantine status | `File-was-not-quarantined.` | Firewall `quarskip` |

The firewall IP and Sysmon host belong to the scenario context; the three screenshots alone do not show a separate host-to-IP mapping event. Historical external indicators are recorded for analysis, not as a claim that the addresses are malicious today.

## 3. Timeline and time handling

| Timestamp | Observation | Time basis |
|---|---|---|
| 2016-08-24 09:48:14 | Firewall detects the `mhtr.jpg` transfer | Splunk display time; timezone not shown |
| 2016-08-24 09:48:21 | `cmd.exe` command line starts `121214.tmp` | Splunk display time |
| 2016-08-24 16:48:21.537 UTC | Process creation time inside the same Sysmon event | Raw `UtcTime` field |

The displayed events are seven seconds apart, assuming the same display timezone. The process screenshot shows a seven-hour difference between the UI and raw UTC. Do not label the displayed firewall time as UTC without checking the search user's timezone. The file-count screenshot is an aggregate and does not provide a file-activity timeline.

## 4. Investigation steps

### 4.11 — Identify the parent process

I searched for the temporary executable name alongside VBScript references in Sysmon:

```spl
index=botsv1 source="WinEventLog:Microsoft-Windows-Sysmon/Operational"
    "*121214.tmp*" "*.vbs*"
```

The screenshot returns one event. Its raw XML contains `EventID=1`, indicating process creation. The relevant fields are:

- `Image`: `C:\Windows\SysWOW64\cmd.exe`
- `ProcessId`: `1476`
- `ParentProcessId`: `3968`
- `ParentImage`: `C:\Windows\SysWOW64\wscript.exe`
- `ParentCommandLine`: runs `20429.vbs` from Bob's roaming profile.
- `CommandLine`: invokes `cmd.exe /C START` with `121214.tmp` in the same roaming profile.

**Answer: `3968`.** This is the parent ID on the matching `cmd.exe` creation event. It should not be confused with the child PID `1476` or the provider's execution PID in the XML header. This screenshot does not show a separate process-creation record for the temporary executable itself.

![Sysmon process event showing ParentProcessId 3968](screenshots/01-parent-process.png)

### 4.12 — Count text files in Bob's profile

I restricted the search to the workstation, Sysmon Event ID 2, and text-file paths beneath Bob's profile:

```spl
index=botsv1 host="we8105desk"
sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational"
EventCode=2
TargetFilename="C:\\Users\\bob.smith.WAYNECORPINC\\*.txt"
| stats dc(TargetFilename) AS encrypted_txt_files
```

**Answer: `406`.** The screenshot shows 406 events and a distinct-path count of 406. Using `dc` avoids counting repeated events for the same path as separate files; the profile filter excludes paths outside Bob's profile.

**Interpretation:** Sysmon Event ID 2 records a change to file creation time, not an encryption operation. The result is the exercise's count of affected text files in the Cerber scenario. The alias `encrypted_txt_files` is a label chosen in the search, not proof of encryption. In a production investigation, correlate the file events with the responsible process, file-content changes, ransomware extensions, or ransom notes before declaring every file encrypted. This count also does not represent all file types or total business impact.

![Profile-scoped search returning 406 distinct text-file paths](screenshots/02-text-file-count.png)

### 4.13 — Identify the downloaded file

I examined the Fortigate infected-file event for the internal source IP and extracted the URL and original action from the raw log:

```spl
index=botsv1 sourcetype=fgt_utm
srcip="192.168.250.100" msg="File is infected."
| rex field=_raw "url=\"(?<download_url>[^\"]+)\""
| rex field=_raw "\baction=(?<original_action>\S+)"
| table _time srcip dstip filename download_url virus original_action quarskip
```

**Answer: `mhtr.jpg`.** The single result contains the historical URL `hxxp://92[.]222[.]104[.]182/mhtr.jpg` (defanged here), detection `Malware_Generic.P0`, action `monitored`, and `File-was-not-quarantined.`

This confirms a detected suspicious transfer. It does **not** show that the firewall blocked the download or that the endpoint was cleaned. The generic detection name alone is not a Cerber family identification; the filename and external research provide additional context.

![Fortigate result showing mhtr.jpg and a monitored action](screenshots/03-malware-download.png)

### 4.14 — Assess the obfuscation technique

**Answer: steganography.** [Netskope's analysis of Cerber](https://www.netskope.com/blog/anatomy-ransomware-attack-cerber-uses-steganography-hide-plain-sight) describes malware concealed inside `mhtr.jpg` and identifies the same delivery IP seen in the firewall result.

This is an externally supported assessment, not a conclusion based only on the `.jpg` extension. A misleading extension by itself would not prove steganography. No sample was downloaded, executed, decoded, or reverse engineered for this report, so exact sample identity has not been established by a hash comparison.

## 5. Assessment and limitations

The supplied evidence is consistent with the Cerber training scenario: script-driven execution, a detected payload transfer, and file activity in the targeted profile. I would escalate this combination as suspected ransomware activity in a live environment.

The report does not establish the original delivery mechanism, complete process tree, successful encryption of each individual file, lateral movement, or recovery. Earlier exercises are not reconstructed from assumptions. The original screenshots are retained without modifying their results; their Splunk username warning is visible. Queries above were transcribed from these captures and were not rerun during report preparation.

## 6. MITRE ATT&CK mapping

| Technique | ID | Evidence and confidence |
|---|---|---|
| Command and Scripting Interpreter: Visual Basic | T1059.005 | Supported by `wscript.exe` and the `.vbs` parent command line |
| Command and Scripting Interpreter: Windows Command Shell | T1059.003 | Supported by the `cmd.exe /C START` command line |
| Ingress Tool Transfer | T1105 | Consistent with the suspicious `mhtr.jpg` transfer |
| Obfuscated Files or Information: Steganography | T1027.003 | Supported by external Cerber research; not independently demonstrated on the captured sample |
| Data Encrypted for Impact | T1486 | Scenario-level interpretation; Event ID 2 alone is insufficient confirmation |

[MITRE ATT&CK technique reference](https://attack.mitre.org/techniques/enterprise/).

## 7. Recommended response

These are proposed actions for a comparable live incident; they were not performed in the lab:

1. Isolate the suspected endpoint through approved incident-response procedures and assess access to shared storage.
2. Preserve relevant logs and volatile evidence when feasible, prioritizing containment if encryption is active.
3. Correlate endpoint identity, script ancestry, network connections, and file changes across the incident window.
4. Search for the same filenames, script paths, and delivery indicators elsewhere, validating historical indicators before applying current blocks.
5. Review the firewall policy that allowed a monitored detection without quarantine. Investigate whether other controls prevented execution.
6. Determine the affected file scope, eradicate the cause, and restore from verified clean backups. Validate recovery before reconnecting the system.

Detection opportunities include unusual `wscript.exe` to `cmd.exe` chains launching executables from user-writable directories and bursts of suspicious file activity. These patterns require baselining and corroboration rather than alerting solely on an extension or process name.

## 8. Sources

- [Splunk BOTSv1 dataset](https://github.com/splunk/botsv1).
- User-supplied BOTSv1 exercises 4.11–4.14 and the three lab screenshots embedded above.
- [Netskope — Cerber ransomware and steganography](https://www.netskope.com/blog/anatomy-ransomware-attack-cerber-uses-steganography-hide-plain-sight), consulted for the filename association and obfuscation assessment.
- [Microsoft Sysmon documentation](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon), reference for event semantics.

All observations refer to public training data. No live malware or real client evidence is stored in this repository.
