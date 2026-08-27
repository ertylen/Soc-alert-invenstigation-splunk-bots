# Scenario 02 - Cerber Ransomware

My notes and screenshots for Splunk BOTSv1 questions **4.11-4.14**.

I checked the parent process behind the `121214.tmp` launch, counted text-file paths in Bob Smith's profile, and identified `mhtr.jpg` in a firewall event. The report includes the SPL searches and explains what the results do and do not show. The steganography finding comes from the linked Netskope analysis.

**[Read the report](report.md)**

## Screenshots

- [Parent process and command line](screenshots/01-parent-process.png)
- [Text-file count](screenshots/02-text-file-count.png)
- [Download and firewall action](screenshots/03-malware-download.png)

Based on the public [Splunk BOTSv1 dataset](https://github.com/splunk/botsv1). This is lab practice, not a production incident.
