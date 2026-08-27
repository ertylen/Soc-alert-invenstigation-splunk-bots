# Scenario 02 - Cerber Ransomware

Notes from my Splunk BOTSv1 lab, covering questions 4.11-4.14. I used Sysmon and Fortigate logs to check the process launch, count text-file paths in Bob Smith's profile, and identify the downloaded file.

| Question | Result |
|---|---|
| 4.11 - Parent process ID | `3968` |
| 4.12 - Text files | `406` distinct paths in the lab search |
| 4.13 - Downloaded file | `mhtr.jpg` |
| 4.14 - Likely obfuscation | Steganography, based on external research |

## 4.11 - Finding the parent process

I searched for `121214.tmp` together with `.vbs` in Sysmon:

```spl
index=botsv1 source="WinEventLog:Microsoft-Windows-Sysmon/Operational"
    "*121214.tmp*" "*.vbs*"
```

This returned one process-creation event (`EventID=1`). The command line used `cmd.exe /C START` to launch `121214.tmp` from Bob's roaming profile.

| Field | Value |
|---|---|
| Host | `we8105desk` |
| User | `WAYNECORPINC\bob.smith` |
| Image | `C:\Windows\SysWOW64\cmd.exe` |
| ProcessId | `1476` |
| ParentProcessId | `3968` |
| ParentImage | `C:\Windows\SysWOW64\wscript.exe` |
| Script in ParentCommandLine | `20429.vbs` |

The answer is **3968**. It is the parent ID on the `cmd.exe` event; **1476** is the child PID. The screenshot does not show a separate process-creation record for `121214.tmp` itself.

![Process event showing ParentProcessId 3968](screenshots/01-parent-process.png)

## 4.12 - Counting the text files

I limited the search to `we8105desk` and `.txt` paths under Bob's Windows profile, then counted distinct filenames:

```spl
index=botsv1 host="we8105desk"
sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational"
EventCode=2
TargetFilename="C:\\Users\\bob.smith.WAYNECORPINC\\*.txt"
| stats dc(TargetFilename) AS encrypted_txt_files
```

The result is **406**. The profile filter excludes files elsewhere on the machine, and `dc(TargetFilename)` avoids counting repeated events for one path as separate files.

There is a limit to this result: Sysmon Event ID 2 records changes to file creation time, not encryption. **406** is the answer for this ransomware exercise, but the query alone does not prove that every file was encrypted. The column name `encrypted_txt_files` is just an alias. Confirming encryption would require more evidence, such as file-content changes or related process activity.

![Search returning 406 distinct text-file paths](screenshots/02-text-file-count.png)

## 4.13 - Finding the download

I checked infected-file events for `192.168.250.100`. The `rex` commands extract the URL and original action from the raw firewall log:

```spl
index=botsv1 sourcetype=fgt_utm
srcip="192.168.250.100" msg="File is infected."
| rex field=_raw "url=\"(?<download_url>[^\"]+)\""
| rex field=_raw "\baction=(?<original_action>\S+)"
| table _time srcip dstip filename download_url virus original_action quarskip
```

The event identifies **mhtr.jpg** at `hxxp://92[.]222[.]104[.]182/mhtr.jpg` (URL defanged). The detection is `Malware_Generic.P0`.

The action matters here: it says **monitored**, and `quarskip` says **File-was-not-quarantined.** This shows a detection, not a confirmed block or cleanup. The generic signature also does not identify Cerber on its own.

![Fortigate event for mhtr.jpg](screenshots/03-malware-download.png)

## 4.14 - Why steganography?

[Netskope's Cerber analysis](https://www.netskope.com/blog/anatomy-ransomware-attack-cerber-uses-steganography-hide-plain-sight) describes malware hidden inside `mhtr.jpg` and lists the same delivery IP. That supports **steganography** as the answer: malicious content concealed inside an image.

A `.jpg` extension alone would not establish this. This part relies on published research; no malware sample was decoded or matched by hash for this report.

## Timing and scope

The firewall result displays **2016-08-24 09:48:14**, and the process event displays **09:48:21**. They are seven seconds apart if both searches used the same timezone. The raw Sysmon `UtcTime` is **16:48:21.537 UTC**, so the displayed times should not be labelled UTC.

These three screenshots cover only part of the scenario. They do not separately establish the host-to-IP mapping, full infection chain, or total encryption impact. The searches are recorded from the lab screenshots and were not rerun while preparing these notes.

## ATT&CK references

| Technique | Connection to the findings |
|---|---|
| T1059.005 - Visual Basic | `wscript.exe` running a `.vbs` script |
| T1059.003 - Windows Command Shell | `cmd.exe /C START` |
| T1105 - Ingress Tool Transfer | Suspicious file transfer |
| T1027.003 - Steganography | Supported by the external analysis |
| T1486 - Data Encrypted for Impact | Ransomware scenario context; not proven by Event ID 2 alone |

[MITRE ATT&CK](https://attack.mitre.org/techniques/enterprise/)

## Next steps in a live incident

I would isolate the suspected endpoint, preserve the relevant evidence, and check other hosts and shared folders for related activity. I would also review why the firewall detection was monitored rather than blocked, then confirm the affected files and available clean backups. These are proposed actions, not work performed in this lab.

## Sources

- [Splunk BOTSv1](https://github.com/splunk/botsv1) - public training dataset.
- Lab questions 4.11-4.14 and the three screenshots above.
- [Netskope: Cerber and steganography](https://www.netskope.com/blog/anatomy-ransomware-attack-cerber-uses-steganography-hide-plain-sight).
- [Microsoft Sysmon documentation](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon).

This is a training exercise, not a client incident. No malware samples are included.
