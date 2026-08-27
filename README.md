# SOC Alert Investigation — Splunk BOTS

A portfolio of investigations using Splunk's public Boss of the SOC training datasets. I use SPL searches to review activity, connect events, identify indicators, and explain what the evidence supports.

These are training investigations, not incidents handled for an employer or client. The reports document my lab work and include screenshots of my search results. External research is cited separately from observations in the logs.

## Investigations

| Scenario | Dataset | Focus | Report |
|---|---|---|---|
| 01 — Brute force login | BOTSv1 | HTTP password guessing, password extraction, and request timing | [Read report](Scenario-01-brute-force-login/report.md) |
| 02 — Cerber ransomware | BOTSv1 | Script execution, process ancestry, affected files, and a suspicious download | [Read report](Scenario-02-cerber-ransomware/report.md) |

## Skills demonstrated

- Filtering Windows, Sysmon, HTTP, and firewall events in Splunk.
- Extracting fields with `rex` and summarizing results with `stats`.
- Distinguishing event counts from distinct file or password counts.
- Reading process command lines and parent process relationships.
- Separating observed facts, interpretations, and evidence gaps.
- Mapping relevant behavior to MITRE ATT&CK and proposing response actions.

## Lab and reproduction

Use an authorized Splunk lab with BOTSv1 loaded. These searches use `index=botsv1`; adjust the index and field names to match your installation. Start with **All time** because the dataset contains historical events, then narrow the time range once you identify the relevant activity.

For a local setup, follow the dataset's installation instructions and check current Splunk licensing requirements. Screenshots may display a different timezone from the UTC timestamps inside raw Windows events.

## Repository guide

- [Scenario 01](Scenario-01-brute-force-login/report.md): existing brute force investigation and its evidence screenshots.
- [Scenario 02 overview](Scenario-02-cerber-ransomware/README.md): scope and key results.
- [Scenario 02 report](Scenario-02-cerber-ransomware/report.md): investigation steps, SPL, evidence, limitations, and recommendations.
- [Scenario 02 screenshots](Scenario-02-cerber-ransomware/screenshots/): original evidence images, renamed for readability.

## Sources and scope

- [Splunk BOTSv1](https://github.com/splunk/botsv1) — source training dataset.
- [Splunk BOTSv2](https://github.com/splunk/botsv2) — reference for future work; no BOTSv2 investigation is presented here yet.
- [MITRE ATT&CK](https://attack.mitre.org/) — technique reference.

Scenario 02 currently covers exercises 4.11–4.14 from the supplied training material. Exercise numbering can differ between platforms. Dataset ownership remains with the original providers; this repository contains investigation notes and screenshots, not the dataset or malware samples.
