# SOC Alert Investigations — Splunk BOTS

Hands-on SOC investigation practice using Splunk's public **Boss of the SOC (BOTS)** dataset.

The goal of this repository is simple: take suspicious activity, investigate it with SPL, document the evidence, and decide what the logs actually prove.

## Projects

| Scenario | What I investigated | Main skills | Report |
|---|---|---|---|
| **01 — Brute Force Login** | Automated password guessing against a web login | HTTP analysis, `rex`, `stats`, timeline correlation | [View investigation](Scenario-01-brute-force-login/report.md) |
| **02 — Cerber Ransomware** | Initial Cerber activity and related host evidence | Windows events, process analysis, malware investigation | [View investigation](Scenario-02-cerber-ransomware/report.md) |

## Quick project recall

### 01 — Brute Force Login

**Remember it as:** `POST requests → extract passwords → 412 unique → batman → script + browser → 92.17 sec`

I investigated repeated POST requests to `imreallynotbatman.com`, extracted password values from HTTP `form_data`, and identified automated password guessing from `23.22.63.114`. The activity used `Python-urllib/2.7`. I found 412 distinct password values and then correlated `batman` between the scripted traffic and a browser request. The evidence confirms password guessing, but not a successful account compromise.

[Full brute-force investigation →](Scenario-01-brute-force-login/report.md)

### 02 — Cerber Ransomware

**Remember it as:** `Windows events → script/process execution → suspicious download → Cerber evidence`

This investigation follows the initial Cerber ransomware activity using Splunk BOTSv1, focusing on process execution, command-line evidence, affected files, and suspicious network activity.

[Full Cerber investigation →](Scenario-02-cerber-ransomware/report.md)

## SPL I practiced

```spl
| rex field=form_data "passwd=(?<password>[^&]+)"
| stats dc(password)
| sort 0 + _time
| table _time password
```

These investigations also use filtering, field extraction, event correlation, process relationships, and timeline reconstruction.

## Skills demonstrated

- Splunk / SPL investigation
- HTTP and authentication analysis
- Windows event and process analysis
- IOC identification
- Timeline reconstruction
- Separating confirmed evidence from assumptions
- MITRE ATT&CK mapping
- Basic incident-response recommendations

## Lab notes

The repository uses Splunk's public BOTSv1 training data. Searches generally use `index="botsv1"`. Because the dataset contains historical events, I start with **All time** and narrow the time range after locating the relevant activity.

This is training work, not an investigation performed for an employer or client. Screenshots are included as evidence of the searches and results.

## References

- [Splunk BOTSv1](https://github.com/splunk/botsv1)
- [Splunk BOTSv2](https://github.com/splunk/botsv2)
- [MITRE ATT&CK](https://attack.mitre.org/)
