# Case-03: Web SQL Injection Detection & Log Analysis

## What Happened
This case simulates a SQL Injection (SQLi) attack against a deliberately vulnerable PHP login form, moving detection into a new layer entirely: application/web traffic, rather than network (case-01) or host authentication (case-02). An automated attack was run using sqlmap, generating a mix of successful and failed injection attempts, and the resulting Apache access log was ingested into Splunk to separate real attack traffic from background noise and identify the tool behind it.

- **Status:** Completed
- **Severity:** High (Initial Access via Application Vulnerability)

## Lab Environment
This case introduces a new victim role, a vulnerable web application, alongside the existing attacker/SIEM setup. Full network architecture and deployment steps are documented separately:

**[View Lab Setup](./LAB-SETUP03.md)**

**Quick Overview:**
- **Attacker:** Kali Linux (`192.168.10.10`), sqlmap v1.10.6
- **Target:** Ubuntu Server 22.04 (`192.168.20.10`), Apache + PHP + MariaDB, intentionally unsanitized login form
- **Analysis Platform:** Splunk Enterprise 9.x, index `main`, source type `access_combined`

## 1. The Trigger
The trigger here is not a single alert but a pattern in the access log: a sharp, short-lived spike in request volume against `/login.php`, well outside what normal login traffic looks like.

- **Target:** POST parameter `username` in `/login.php`
- **Attack tool identified:** `sqlmap/1.10.6#stable` (via User-Agent)
- **Volume:** 358 HTTP requests containing SQLi payloads
- **Techniques used:** Boolean-based blind, Time-based blind, UNION query injection

> **Why this matters:** A login form receiving hundreds of requests in a one-minute window, many carrying SQL syntax in the username field, is not a user mistyping a password. It is a tool systematically probing the input for a way in.

## 2. Evidence Collection

### A. Attack Simulation (Kali)
```bash
sqlmap -u "http://192.168.20.10/login.php" \
       --data="username=admin&password=test" \
       --level=3 --risk=2 \
       --batch \
       --technique=BEUSTQ
```
Flags: `--level=3 --risk=2` increases payload variety and depth; `--batch` runs non-interactively; `--technique=BEUSTQ` tests all SQLi technique classes (Boolean, Error, Union, Stacked, Time, Query).

### B. Attack Timeline

<img width="850" height="300" alt="SQLi attack timeline dashboard" src="evidence/case03-timeline.png" />

Traffic spikes sharply at 14:53, isolated cleanly from baseline request volume once `user_agent` is checked against known sqlmap signatures.

```spl
index=main host="ubuntu-victim-web"
| eval is_sqli=if(user_agent LIKE "%sqlmap%", 1, 0)
| timechart span=1m sum(is_sqli) as "SQLi Attacks", count as "Total Requests"
```

### C. Top Attacking IPs and Tools

<img width="850" height="250" alt="Top attacker IPs and user agents" src="evidence/case03-top-ips.png" />

`192.168.10.10` is confirmed as the source, `sqlmap/1.10.6#stable` as the tool. Default `access_combined` field extraction failed to parse the User-Agent field correctly in this environment, so it was pulled manually with `rex`.

```spl
index=main host="ubuntu-victim-web"
| rex field=_raw "\"[^\"]*\" \"(?<user_agent>[^\"]+)\""
| fillnull value="Unknown" clientip, user_agent
| stats count by clientip, user_agent
| sort -count
| head 10
```

### D. SQLi Attempt Detail Table

<img width="850" height="300" alt="Detailed table of SQLi request attempts" src="evidence/case03-critical-table.png" />

A mix of HTTP `200` (payload validated without breaking the application) and `500` (application error, likely from aggressive fuzzing) responses. Both are relevant, not just the 200s.

```spl
index=main host="ubuntu-victim-web"
| rex field=_raw "\"[^\"]*\" \"(?<user_agent>[^\"]+)\""
| search user_agent="*sqlmap*"
| table _time, clientip, method, uri_path, status, user_agent
| sort -_time
| head 20
```

## 3. Reproduction Steps

### Phase 1: Provision the vulnerable target
Deploy the vulnerable PHP login form on Ubuntu (Apache + PHP + MariaDB). Full setup: `LAB-SETUP03.md`.

### Phase 2: Run the attack (Kali)
```bash
sqlmap -u "http://192.168.20.10/login.php" \
       --data="username=admin&password=test" \
       --level=3 --risk=2 \
       --batch \
       --technique=BEUSTQ
```

### Phase 3: Extract and transfer the log
```bash
scp adi@192.168.20.10:/var/log/apache2/access.log ~/case03-access.log
grep -i "union\|select\|or 1=1" ~/case03-access.log | head -5
```

### Phase 4: Ingest into Splunk
Upload via Settings > Add Data > Upload, source type `access_combined`, host value `ubuntu-victim-web`.

### Phase 5: Run the three queries above and build the dashboard

#### Expected Outcome
A clear traffic spike in the timeline panel, `192.168.10.10` and `sqlmap` identified as source and tool, and a detail table showing the mix of `200`/`500` responses that confirms the attack's mechanics.

## 4. Context and Baseline
- **Target:** `/login.php` on `192.168.20.10`, a deliberately unsanitized login form.
- **Normal Behavior:** Legitimate login traffic is low-volume, spread out, and carries normal credential-shaped input. Hundreds of requests in a one-minute window, many with SQL syntax in the username field, has no legitimate explanation.

## 5. Deep Dive Analysis
- **Tool fingerprinting:** sqlmap leaves a distinct signature, both in its User-Agent string and in the frequency/sequential nature of its requests. Once the field extraction issue was resolved, the tool was trivial to identify.
- **Parser limitations:** the default `access_combined` parser did not extract `user_agent` correctly in this environment. Writing a working `rex` pattern was a required step, not an edge case, and is a realistic skill gap the default SIEM tooling doesn't close on its own.
- **Status codes matter beyond 200:** the `500` responses in the detail table are as informative as the `200`s. A cluster of server errors on a login endpoint is itself a signal, often indicating the payload broke the application's query logic rather than passing cleanly.

## 6. MITRE ATT&CK Mapping

| Tactic | Technique ID | Name | Application in This Case |
|---|---|---|---|
| Initial Access | T1190 | Exploit Public-Facing Application | sqlmap targeted the unsanitized `username` parameter on the public login form. |
| Credential Access | T1552 | Unsecured Credentials | A successful SQLi against this login form could expose the underlying `users` table directly. |

> **Tactical Insight:** This case sits at a different layer than case-01 (network scanning) and case-02 (credential brute force). Together, the three cases span network, host, and application layers, three distinct places a SOC analyst needs to know how to look.

## 7. Verdict
**Classification: MALICIOUS (Active Exploitation Attempt)**

The volume, payload content, and tool fingerprint together are conclusive. This was not incidental traffic. Whether any specific request achieved a full data exfiltration would require deeper inspection of the `200` responses' content, noted below as follow-up.

## 8. Recommended Actions
1. **Immediate:** Patch the `username`/`password` parameters in `login.php` with parameterized queries (prepared statements), not just input sanitization.
2. **Containment:** Block `192.168.10.10` at the firewall, review whether any other endpoint shares the same vulnerability pattern.
3. **Detection Tuning:** Build a standing alert on User-Agent strings matching known scanning/exploitation tools (sqlmap, nikto, etc.) hitting authentication endpoints.
4. **Further Investigation:** Review the `200` response bodies from the attack window to confirm whether any injection actually returned unauthorized data, rather than just validating the vulnerability existed.

## Files
