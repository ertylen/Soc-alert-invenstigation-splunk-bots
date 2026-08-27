## SOC Alert Investigation — Splunk BOTS (v1 & v2) 

Practical SOC analyst portfolio project built on Splunk's public `Boss of the SOC (BOTS)` datasets. Each scenario below walks through log review, timeline reconstruction, indicator extraction, and MITRE ATT&CK mapping — the way an entry-level SOC analyst would document a real investigation.

## About this project

- `Goal:` demonstrate ability to investigate alerts, read logs, and produce clear written findings.

  `Data source`  [Splunk BOTSv1](https://github.com/splunk/botsv1) / [BOTSv2](https://github.com/splunk/botsv2) — free, public, made for training.

  `Tools` Splunk Enterprise (free trial / dev license), VirtualBox or VMware for the lab VM.

  `Disclaimer`: all data used is Splunk's official public training dataset. No real or client data involved.

## Lab setup

## Option A — Hosted/demo Splunk instance (BOTS already loaded) 

1. Log in to your demo/hosted Splunk instance.

2. Confirm the index name that holds the BOTS data — check `Settings` → `Indexes`, or run index=* sourcetype=*`  and inspect which index returns Windows Security / network events. It may be `botsv1`, `botsv2`, `main`, or a custom name.

3. Swap that index name into all searches below and start investigating — no local install needed.

Option B — Self-hosted Splunk (manual setup):

1. Install Splunk Enterprise (free trial license, no cost, up to 500MB/day ingest).

2. Set up a VM for the Splunk instance (VirtualBox/VMware).

3. Take a clean snapshot before importing the dataset, so you can always roll back:

  ```` bash

   # VirtualBox

   VBoxManage snapshot `SOC-Lab` take  clean_state

   # VMware — use the Snapshot button in the VM menu, or:

   vmrun snapshot `SOC-Lab.vmx` clean_state
  ````
  

4. Download and index the BOTS dataset (instructions in Splunk's repo README for each version).

5. Confirm data is searchable:  `index=botsv1 or ` `index=botsv2` 

## Repository structure


````
soc-alert-investigation-splunk-bots/

├── README.md

├── scenario-01-brute-force-login/

│   ├── report.md

│   └── screenshots/
```` 
