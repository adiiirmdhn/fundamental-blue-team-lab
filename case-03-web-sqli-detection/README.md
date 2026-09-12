# Case-03: Web SQL Injection Detection & Log Analysis

## What Happened
This case simulates a SQL Injection (SQLi) attack against a deliberately vulnerable PHP login form, moving detection into a new layer entirely: application/web traffic, rather than network (case-01) or host authentication (case-02). An automated attack was run using sqlmap, generating a mix of successful and failed injection attempts, and the resulting Apache access log was ingested into Splunk to separate real attack traffic from background noise and identify the tool behind it.

- **Status:** Completed
- **Severity:** High (Initial Access via Application Vulnerability)

## Lab Environment
This case introduces a new victim role, a vulnerable web application, alongside the existing attacker/SIEM setup. For full network architecture and VM configuration, refer to the dedicated infrastructure repository:

**[View Lab Setup Repository](https://github.com/adiiirmdhn/fundamental-blue-team-lab/blob/main/case-03-web-sqli-detection/LAB%20SETUP03.md)**

**Quick Overview:**
- **Attacker:** Kali Linux (`192.168.10.10`), sqlmap v1.10.6, connected via VMnet2 (LAN)
- **Target:** Ubuntu Server 22.04 (`192.168.20.10`), Apache + PHP + MariaDB, connected via VMnet3 (OPT1)
- **Analysis Platform:** Splunk Enterprise, self-hosted on Windows, index `main`, source type `access_combined`
- **Data volume analyzed:** 358 HTTP requests

## 1. The Trigger
Unlike case-01, there was no single real-time alert that kicked off this investigation. The dataset was built as a complete incident to analyze afterward. From an analyst's perspective, the trigger is a sharp, short-lived spike in request volume against `/login.php`, well outside what normal login traffic looks like.

- **Target Parameter:** `username` in `/login.php`
- **Attack Tool Identified:** `sqlmap/1.10.6#stable`
- **Total Requests in Attack Window:** 358
- **Techniques Used:** Boolean-based blind, Time-based blind, UNION query injection

> **Why this matters:** A login form receiving hundreds of requests in a one-minute window, many carrying SQL syntax in the username field, is not a user mistyping a password. It is a tool systematically probing the input for a way in.

## 2. Evidence Collection
Evidence was gathered from the attack simulation plus the resulting dashboard analysis.

### A. Attack Simulation Methodology
The attack was executed from Kali using sqlmap against the unsanitized `username` parameter.

```bash
sqlmap -u "http://192.168.20.10/login.php" \
       --data="username=admin&password=test" \
       --level=3 --risk=2 \
       --batch \
       --technique=BEUSTQ
```

`--level=3 --risk=2` increases payload variety and depth of testing. `--batch` runs non-interactively. `--technique=BEUSTQ` tests all SQLi technique classes (Boolean, Error, Union, Stacked, Time, Query).

**Noise injection:** log entries from unrelated sources (`10.0.0.99`, `172.16.0.5`) probing unrelated paths (`/wp-admin`, `/phpmyadmin`) were manually appended to `access.log` to simulate background scanning traffic and test whether the real attacker's activity could still be isolated from it.

### B. Attack Timeline

<img width="736" height="219" alt="image" src="https://github.com/user-attachments/assets/60737f0b-cb94-4d7d-bc41-c79053f0cbe8" />


Traffic spikes sharply at 14:53, isolated cleanly from baseline request volume once `user_agent` is checked against known sqlmap signatures.

### C. Top Attacking IPs and Tools

<img width="730" height="235" alt="image" src="https://github.com/user-attachments/assets/dfd21d62-e21c-45eb-9664-a99e07a03818" />


`192.168.10.10` accounts for the large majority of the attack traffic, confirming it as the primary attack vector. `sqlmap/1.10.6#stable` is identified as the tool via User-Agent extraction. The secondary IPs (`10.0.0.99`, `172.16.0.5`) show low, unrelated activity — this is the injected noise that had to be separated from the real signal.

### D. SQLi Attempt Detail Table

<img width="743" height="412" alt="image" src="https://github.com/user-attachments/assets/f6cbc0d4-0f90-4102-8289-3f991da5f288" />


A mix of HTTP `200` (payload processed without crashing the application) and `500` (application error, likely from aggressive fuzzing) responses. This table represents the exact data a Tier 1 analyst would use to open an incident ticket for patching and host review — not the request volume alone, but the confirmed injection payloads and their outcomes.

## 3. Reproduction Steps
Here is the exact workflow used to generate this incident.

### Phase 1: Provision the Vulnerable Target
Deploy the vulnerable PHP login form on Ubuntu (Apache + PHP + MariaDB). Full setup in `LAB-SETUP03.md`.

### Phase 2: Run the Attack (From Kali)
```bash
sqlmap -u "http://192.168.20.10/login.php" \
       --data="username=admin&password=test" \
       --level=3 --risk=2 \
       --batch \
       --technique=BEUSTQ
```

### Phase 3: Inject Background Noise
```bash
echo '10.0.0.99 - - [12/Sep/2026:10:15:00 +0000] "GET /wp-admin HTTP/1.1" 404 453 "-" "Mozilla/5.0"' | sudo tee -a /var/log/apache2/access.log
echo '172.16.0.5 - - [12/Sep/2026:10:16:00 +0000] "GET /phpmyadmin HTTP/1.1" 404 453 "-" "Nmap Scripting Engine"' | sudo tee -a /var/log/apache2/access.log
```

### Phase 4: Extract and Transfer the Log
```bash
scp adi@192.168.20.10:/var/log/apache2/access.log ~/case03-access.log
grep -i "union\|select\|or 1=1" ~/case03-access.log | head -5
```

### Phase 5: Ingest into Splunk
1. Pull the completed `access.log` from the Ubuntu target.
2. Upload to Splunk, source type `access_combined`, host value `ubuntu-victim-web`.
3. Where default field extraction failed to parse User-Agent, use `rex` to manually extract the needed fields.

#### Expected Outcome
A dashboard showing a clear traffic spike during the sqlmap run, `192.168.10.10` and `sqlmap` identified as source and tool, and a detail table showing the mix of `200`/`500` responses that confirms the attack's mechanics.

## 4. Context and Baseline
- **Target:** `/login.php` on `192.168.20.10`, a deliberately unsanitized login form.
- **Network Zone:** Isolated segment (OPT1 / `192.168.20.0/24`), same as case-01 and case-02.
- **Normal Behavior:** Legitimate login traffic is low-volume, spread out, and carries normal credential-shaped input. Hundreds of requests in a one-minute window, many with SQL syntax in the username field, has no legitimate equivalent.

## 5. Deep Dive Analysis
Here is what the evidence tells us when analyzed together.

- **Tool fingerprinting:** sqlmap leaves a distinct signature, both in its User-Agent string and in the frequency and sequential nature of its requests. Once the field extraction issue was resolved, the tool was straightforward to identify.
- **Parser limitations:** the default `access_combined` parser did not extract `user_agent` correctly in this environment. Writing a working `rex` pattern was a required step, not an edge case, and reflects a realistic gap the default SIEM tooling doesn't close on its own.
- **Status codes matter beyond 200:** the `500` responses in the detail table are as informative as the `200`s. A cluster of server errors on a login endpoint is itself a signal, often indicating the payload broke the application's query logic rather than passing cleanly.
- **Noise filtering:** the injected traffic from `10.0.0.99` and `172.16.0.5` had to be explicitly excluded from the top-attacker analysis, a rough approximation of the filtering work an analyst does against real background scanning traffic in production.

## 6. MITRE ATT&CK Mapping

| Tactic | Technique ID | Name | Application in This Case |
| :--- | :--- | :--- | :--- |
| **Initial Access** | `T1190` | Exploit Public-Facing Application | sqlmap targeted the unsanitized `username` parameter on the public login form. |
| **Credential Access** | `T1552` | Unsecured Credentials | A successful SQLi against this login form could expose the underlying `users` table directly. |

> **Tactical Insight:** This case sits at a different layer than case-01 (network scanning) and case-02 (credential brute force). Together, the three cases span network, host, and application layers, three distinct places a SOC analyst needs to know how to look.

## 7. Verdict
- **Classification:** MALICIOUS (Active Exploitation Attempt)

The volume, payload content, and tool fingerprint together are conclusive. This was not incidental traffic. Whether any specific request achieved full data exfiltration would require deeper inspection of the `200` responses' content, noted below as follow-up.

## 8. Recommended Actions
What should happen next in a real SOC queue.

1. **Immediate Response:** Patch the `username`/`password` parameters in `login.php` with parameterized queries (prepared statements), not just input sanitization.
2. **Containment:** Block `192.168.10.10` at the firewall, review whether any other endpoint shares the same vulnerability pattern.
3. **Detection Tuning:** Build a standing alert on User-Agent strings matching known scanning/exploitation tools (sqlmap, nikto, etc.) hitting authentication endpoints.
4. **Further Investigation:** Review the `200` response bodies from the attack window to confirm whether any injection actually returned unauthorized data, rather than just validating the vulnerability existed.

## Splunk Queries and Configuration
The dashboard was built from three saved SPL queries against index `main`.

**Query 1 — Attack timeline (SQLi vs. total traffic):**
```spl
index=main host="ubuntu-victim-web"
| eval is_sqli=if(user_agent LIKE "%sqlmap%", 1, 0)
| timechart span=1m sum(is_sqli) as "SQLi Attacks", count as "Total Requests"
```

**Query 2 — Top attacking IPs and tools:**
```spl
index=main host="ubuntu-victim-web"
| rex field=_raw "\"[^\"]*\" \"(?<user_agent>[^\"]+)\""
| fillnull value="Unknown" clientip, user_agent
| stats count by clientip, user_agent
| sort -count
| head 10
```

**Query 3 — SQLi attempt detail:**
```spl
index=main host="ubuntu-victim-web"
| rex field=_raw "\"[^\"]*\" \"(?<user_agent>[^\"]+)\""
| search user_agent="*sqlmap*"
| table _time, clientip, method, uri_path, status, user_agent
| sort -_time
| head 20
```

> **Note on Field Extraction:**
> The default `access_combined` source type extracted most standard fields correctly, but failed to parse `user_agent` reliably in this environment. The `rex` command in Query 2 was necessary to pull it out of the raw event manually, which turned out to be a more realistic exercise than a perfectly clean ingest would have been.

## Key Learnings
- **Tool fingerprinting:** automated tools like sqlmap leave distinct, identifiable signatures in both request frequency and User-Agent strings.
- **Log parsing:** default source types do not always extract fields cleanly, and `rex` is a necessary fallback skill rather than an edge case.
- **Error codes as signal:** HTTP 500 responses on a login endpoint are not noise to ignore, they often indicate a payload aggressive enough to break application logic.
- **Layered detection:** this case, read alongside case-01 and case-02, shows the same underlying skill set (log ingestion, field extraction, pattern isolation) applied across three different layers of a system.

## Disclaimer
All activity was performed in an isolated home lab environment. No external systems were targeted. The SQLi vulnerability was intentionally limited to a single PHP file (`login.php`) with no real sensitive data behind it. Attack simulation used standard security testing tools (sqlmap) against infrastructure owned and controlled for this lab, for educational purposes only.

> **Notes for Future Reference:** Case-01 caught reconnaissance, case-02 caught a credential attack that succeeded, and this case catches an application-layer exploitation attempt. Read together, the three cases trace an attacker's path across three different layers of the same environment, network, host, and application, with three different detection approaches: behavioral IDS, SIEM log correlation on auth logs, and SIEM log correlation on web logs with manual field extraction.
