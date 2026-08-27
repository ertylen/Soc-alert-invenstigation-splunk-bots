# Scenario 02 — Cerber Ransomware

A Splunk BOTSv1 investigation into script execution, a suspicious download, and file activity in Bob Smith's Windows profile.

[Read the investigation report](report.md)

## Scope

This report covers exercises **4.11–4.14** from the training material used in the lab. It brings the results together as a short SOC investigation rather than presenting them as isolated answers. Earlier stages of the infection are outside the evidence included here.

| Exercise | Finding | Evidence |
|---|---|---|
| 4.11 — Parent process | `3968` | Sysmon process creation event |
| 4.12 — Text files | `406` distinct paths | Profile-scoped Sysmon search; interpreted in the ransomware exercise context |
| 4.13 — Downloaded file | `mhtr.jpg` | Fortigate infected-file event |
| 4.14 — Obfuscation | Steganography | External Netskope analysis; not independently verified through sample analysis |

## Evidence

- [Parent process and command line](screenshots/01-parent-process.png)
- [Distinct text-file count](screenshots/02-text-file-count.png)
- [Malware download and firewall action](screenshots/03-malware-download.png)

The screenshots are original lab captures. Searches transcribed in the report have not been rerun as part of preparing this documentation.

**Dataset:** [Splunk BOTSv1](https://github.com/splunk/botsv1). This is public training data, not a production incident.
