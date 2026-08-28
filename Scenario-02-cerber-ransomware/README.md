# Scenario 02 — Cerber Ransomware

Splunk BOTSv1 lab notes for questions **4.11–4.14**.

## Quick recall

Remember the scenario like this:

**`wscript.exe → cmd.exe → 121214.tmp → 406 .txt paths → mhtr.jpg → steganography`**

Main results:
- Parent process ID: `3968`
- Distinct `.txt` paths: `406`
- Suspicious downloaded file: `mhtr.jpg`
- Likely concealment method: steganography

The full report shows the SPL searches, screenshots, and the limits of each finding.

**[Read the full report](report.md)**

## Screenshots

- [Parent process and command line](screenshots/01-parent-process.png)
- [Text-file count](screenshots/02-text-file-count.png)
- [Malware download event](screenshots/03-malware-download.png)

This is practice using the public [Splunk BOTSv1](https://github.com/splunk/botsv1) dataset, not a production incident.
