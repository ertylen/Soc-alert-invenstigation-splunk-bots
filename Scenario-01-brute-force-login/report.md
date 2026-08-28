# Scenario 01 — Brute Force Login Investigation

**Dataset:** Splunk BOTSv1  
**Target:** `imreallynotbatman.com`  
**Alert type:** Suspicious login activity / password guessing

## Quick recall

This scenario is about identifying an automated password-guessing attack against the login page of `imreallynotbatman.com`.

What I found:
- Source IP `23.22.63.114` sent many HTTP POST requests to the login form.
- The requests used `Python-urllib/2.7`, which is consistent with scripted activity.
- I extracted **412 distinct password values** from the POST data.
- The first observed password was `12345678`.
- The password `batman` appeared first from the script and later from a browser client.
- The two `batman` submissions were **92.17 seconds apart**.

Important limitation: the evidence confirms password guessing, but the searches below do **not** prove that authentication succeeded.

---

## 1. Investigation goal

The goal was to determine whether the HTTP activity represented brute-force login attempts, identify useful indicators, and check whether a guessed password was later reused from a browser.

## 2. Timeline

| Time (UTC) | Event |
|---|---|
| 2016-08-10 14:45:21.226 | First observed scripted password submission: `12345678` |
| 2016-08-10 14:46:33.689 | Script submits `batman` |
| 2016-08-10 14:48:05.858 | Browser client submits `batman` |

## 3. Indicators

- **Source IP:** `23.22.63.114`
- **Destination IP:** `192.168.250.70`
- **Target:** `imreallynotbatman.com`
- **Script User-Agent:** `Python-urllib/2.7`
- **Browser User-Agent:** `Mozilla/5.0 (Windows NT 6.1; WOW64; Trident/7.0; rv:11.0) like Gecko`
- **Distinct password values:** 412
- **First password:** `12345678`
- **Password reused by script and browser:** `batman`

User-Agent values are client-controlled, so they are supporting evidence rather than proof of attacker identity or tooling.

## 4. Splunk investigation

### 4.1 Count distinct password values

```spl
index="botsv1" sourcetype="stream:http" src_ip="23.22.63.114" dest_ip="192.168.250.70" http_method="POST" form_data="*username*passwd*"
| rex field=form_data "passwd=(?<password>[^&]+)"
| stats dc(password) AS unique_passwords
```

**Result:** `412` distinct password values.

This is the number of unique extracted passwords, not the total number of login attempts and not a count of failed authentications.

![Distinct password count](<4.Unique Password.png>)

### 4.2 Find the first submitted password

```spl
index="botsv1" sourcetype="stream:http" src_ip="23.22.63.114" dest_ip="192.168.250.70" http_method="POST" form_data="*passwd*"
| rex field=form_data "passwd=(?<password>[^&]+)"
| sort 0 + _time
| table _time password
| head 1
```

**Result:** the first observed password was `12345678` at `14:45:21.226` UTC.

![First password attempt](<1.First Password.png>)

### 4.3 Find a password used by both script and browser clients

```spl
index="botsv1" sourcetype="stream:http" dest_ip="192.168.250.70" http_method="POST" form_data="*username*passwd*"
| rex field=form_data "passwd=(?<password>[^&]+)"
| stats count dc(http_user_agent) AS agent_count values(http_user_agent) AS agents by password
| where agent_count > 1
```

**Result:** `batman` was associated with both `Python-urllib/2.7` and the browser User-Agent.

This makes `batman` a strong candidate for a guessed password that was then manually tested. The query alone does not prove that the same person controlled both clients or that the login succeeded.

![Password used by script and browser clients](3.Correct%20%20Password.png)

### 4.4 Measure the time between the two `batman` submissions

```spl
index="botsv1" sourcetype="stream:http" dest_ip="192.168.250.70" http_method="POST" form_data="*passwd=batman*"
| stats min(_time) AS first_observed max(_time) AS last_observed range(_time) AS seconds
| eval seconds=round(seconds,2)
| convert ctime(first_observed) ctime(last_observed)
| table first_observed last_observed seconds
```

**Result:** `92.17` seconds between the first and last matching events.

This measures the time range between matching POST requests. It should not be described as confirmed time-to-compromise because successful authentication has not been proven.

![Time between password submissions](<2.Time Interval.png>)

## 5. Verdict

**True positive: automated password-guessing activity.**

The combination of a high number of distinct passwords, repeated POST requests, a short time window, and the Python client supports the brute-force assessment.

A full account compromise is **not confirmed** by this evidence alone. To prove successful access I would look for application authentication logs, session creation, redirect behavior, response content, or authenticated activity after the password submission.

## 6. MITRE ATT&CK

| Tactic | Technique | ID | Assessment |
|---|---|---|---|
| Credential Access | Brute Force: Password Guessing | T1110.001 | Confirmed by observed password-guessing behavior |
| Initial Access | Valid Accounts | T1078 | Only applicable if successful login is confirmed |

## 7. Recommended response

- Add rate limiting or progressive delays to repeated login attempts.
- Use MFA, especially for privileged accounts.
- Alert on bursts of failed authentication attempts followed by a successful login.
- Correlate source IP, username, session creation, and subsequent account activity.
- Treat suspicious User-Agent values as supporting signals, not as a blocking rule by themselves.
- If compromise is confirmed, reset the affected credentials and revoke active sessions.

---

Training investigation based on Splunk's public Boss of the SOC dataset.