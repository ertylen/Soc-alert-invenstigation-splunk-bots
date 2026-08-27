Scenario 1: Suspicious Login / Brute Force Investigation

Dataset: Splunk BOTSv1 (index="botsv1")
Alert type: Suspected brute force against imreallynotbatman.com

# 1. Summary

While reviewing HTTP traffic to imreallynotbatman.com, I identified a large volume of POST requests to the site's login form. The activity included 412 distinct password values and the User-Agent Python-urllib/2.7, a pattern consistent with automated password guessing.

I reconstructed the sequence from the first submitted password to the use of batman by the script and its subsequent use by a browser client. The two observed submissions of batman were 92.17 seconds apart. This suggests that a potentially recovered credential was then used in a browser, but the searches shown below do not independently prove successful authentication.

# 2. Timeline

| Time (UTC) | Event | Target |
|---|---|---|
| 2016-08-10 14:45:21.226 | First password submitted by the script: `12345678` | imreallynotbatman.com |
| 2016-08-10 14:46:33.689 | Script submits the candidate password `batman` | imreallynotbatman.com |
| 2016-08-10 14:48:05.858 | Browser client submits the same password | imreallynotbatman.com |



# 3. Indicators and observations

- **Source IP:** `23.22.63.114`
- **Destination IP:** `192.250.70`
- **Target site:** `imreallynotbatman.com`
- **Script User-Agent:** `Python-urllib/2.7`
- **Browser User-Agent:** `Mozilla/5.0 (Windows NT 6.1; WOW64; Trident/7.0; rv:11.0) like Gecko`
- **Distinct password values submitted:** 412
- **First password submitted:** `12345678`
- **Candidate recovered password:** `batman`

User-Agent strings are client-controlled and can be spoofed. They support the analysis but do not establish the attacker's identity, intent, or tool on their own.

The password values above are from Splunk's public training dataset, not live credentials.

# 4. Splunk searches used

Count distinct password values:

``
 index="botsv1" sourcetype="stream:http" src_ip="23.22.63.114" dest_ip="192.168.250.70" http_method="POST" form_data="*username*passwd*"
 | rex field=form_data "passwd=(?<password>[^&]+)"
 | stats dc(password) AS unique_passwords
``

**RESULT:** 412 distinct password values.

This is a count of unique extracted values, not a count of failed logins or total login attempts.

Identify the first password submitted

``
 index="botsv1" sourcetype="stream:http" src_ip="23.22.63.114" dest_ip="192.168.250.70" http_method="POST" form_data="*passwd*"
 | rex field=form_data "passwd=(?<password>[^&]+)"
 | sort 0 + _time
 | table _time, password
 | head 1
``

**RESULT:** The first observed password was 12345678, submitted at 14:45:21.226.

Identify a password used by both script and browser clients

``
 index="botsv1" sourcetype="stream:http" dest_ip="192.168.250.70" http_method="POST" from_data"*username*passwd*"
 | rex field=form_data "passwd=(?<password>[^&]+)"
 | stats count dc(http_user_agent) AS agent_count values(http_user_agent) AS agents by password
 | where agent_count>1 
``

**RESULT:** batman was the only password in the result set associated with both Python-urllib/2.7 and the browser User-Agent.

This makes batman a candidate recovered password. However, the query groups requests across source IPs and accounts. Correlate the source IP, username, timestamps, and authentication evidence before attributing the browser activity to the same attacker or declaring the account compromised.

Calculate the interval between observed password submissions


``
index="botsv1" sourcetype="stream:http" dest_ip="192.168.250.70" http_method="POST" form_data="*passwd=batman*"
| stats min(_time) AS first_observed max(_time) AS last_observed range(_time) AS seconds
| eval seconds=round(seconds,2)
| convert ctime(first_observed) ctime(last_observed)
| table first_observed, last_observed, seconds
`` 

**RESULT:** 92.17 seconds between the first and last matching events: 14:46:33.689 and 14:48:05.858.

This measures the range of matching events, not the time between a proven password discovery and a proven successful login. Inspect the underlying events to confirm their clients and account. The wildcard filter can also match longer password values beginning with batman; verify the extracted password is an exact match.

# 5. Verdict

True positive for password-guessing activity. The large number of distinct password values, the short time window, and the Python client User-Agent support an automated brute force assessment.

Account compromise remains unconfirmed by the searches presented here. The subsequent browser submission of batman is consistent with an attempt to use a recovered credential. Confirm success through application authentication logs, response content, session evidence, or subsequent authenticated activity. HTTP 200 or a change in User-Agent alone is insufficient.


# 6. MITRE ATT&CK mapping

| Tactic | Technique | ID | Assessment |
|---|---|---|---|
| Credential Access | Brute Force: Password Guessing | T1110.001 | Supported by the observed password-guessing activity |
| Initial Access | Valid Accounts | T1078 | Apply only if successful account access is confirmed |


# 7. Recommendations

Apply login rate limits and progressive delays. Consider temporary account lockouts, balancing protection against the risk of attackers deliberately locking out legitimate users.

Require MFA for administrative accounts and restrict access to administration endpoints where practical.

Alert on bursts of authentication failures and correlate them with subsequent successful logins and account activity.

Use User-Agent strings such as Python-urllib as supporting detection signals rather than the sole basis for blocking. Attackers can change them, and legitimate automation can use them.

If compromise is confirmed, reset the affected credentials, revoke active sessions, and review the account's subsequent actions.

Investigation based on Splunk's public Boss of the SOC (BOTS) training dataset. The queries and reported results document an analysis of the imreallynotbatman.com brute force scenario.


## 8. Evidence screenshots

![Distinct password count](<4.Unique Password.png>)

![First password attempt](<1.First Password.png>)

![Password used by script and browser clients](3.Correct%20%20Password.png)

![Time between password submissions](<2.Time Interval.png>)
