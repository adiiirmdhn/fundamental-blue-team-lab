# Case-02: SSH Brute Force Detection & Analysis

## What Happened
This case simulates a full-lifecycle SSH brute force attack against the Ubuntu target, picking up where case-01 left off. Rather than a single scan, this is a structured three-phase attack: user enumeration, a targeted high-volume brute force, and a successful login immediately after. Unrelated background noise was manually injected into the log to mimic what a real `auth.log` looks like outside a clean lab. Detection and analysis were done in Splunk Enterprise, ingesting the resulting log and building a dashboard to separate the actual breach from the noise around it.

- **Status:** Completed
- **Severity:** Critical (Credential Access → Successful Compromise)

## Lab Environment
This case reuses the network setup from case-01. For full network architecture and VM configuration, refer to the dedicated infrastructure repository:

**[View Lab Setup Repository](https://github.com/adiiirmdhn/fundamental-blue-team-lab/blob/main/case-02-ssh-bruteforce/LAB-SETUP02.md)**

**Quick Overview:**
- **Attacker:** Kali Linux (`192.168.10.10`), Hydra v9.7, connected via VMnet2 (LAN)
- **Target:** Ubuntu Server (`192.168.20.10`), SSH enabled, connected via VMnet3 (OPT1)
- **Analysis Platform:** Splunk Enterprise, self-hosted on Windows, index `case02_ssh`, source type `linux_secure`
- **Data volume analyzed:** 1,900+ events

## 1. The Trigger
Unlike case-01, there was no single real-time alert that kicked off this investigation. The dataset was built as a complete incident to analyze afterward. From an analyst's perspective, the trigger is the presence of `Accepted password` events for user `adi` sitting directly after a dense cluster of failed logins from the same source.

- **Primary Source IP:** `192.168.10.10` (Kali Linux)
- **Targeted Account:** `adi`
- **Total Login Attempts:** 800+ from the primary attacker IP
- **Successful Logins Recorded:** approximately 6

> **Why this matters:** Thousands of failed attempts on their own are noise. A handful of successful logins buried inside that noise are the actual incident, and finding them is the core challenge this case is built around.

## 2. Evidence Collection
Evidence was gathered from three phases of simulated activity plus the resulting dashboard analysis.

### A. Attack Simulation Methodology
The attack was executed in three phases from Kali using Hydra v9.7.

**Phase 1 — Reconnaissance (user enumeration):** a low-volume dictionary attack against common default usernames (`root`, `admin`, `test`, and others), simulating an attacker mapping valid accounts before committing effort to one target.

**Phase 2 — Targeted brute force:** a high-volume attack against the identified user `adi`, using 8 concurrent Hydra threads.
```bash
hydra -l adi -P wordlist.txt ssh://192.168.20.10 -t 8
```

**Phase 3 — Successful compromise:** a legitimate SSH login as `adi` performed immediately after the brute force phase, producing the `Accepted password` event used as the primary indicator of compromise.

**Noise injection:** log entries from unrelated IPs (`192.168.20.2`, `10.0.0.5`) were manually appended to `auth.log` to simulate background scanning traffic and test whether the real attacker's activity could still be isolated from it.

### B. Attack Timeline (Volume vs. Success)

<img width="745" height="226" alt="image" src="https://github.com/user-attachments/assets/7bf0d908-f7a1-4a4e-84dc-b210939911a6" />


A sharp spike in failed login attempts lines up directly with the Phase 2 targeted Hydra run. Against that volume, the successful-login count stays close to flat — out of thousands of failures, only about 6 logins succeeded. This is the statistical signature of a focused, high-effort attack rather than random credential spraying.

### C. Top Attacking Sources and Targeted Users

<img width="737" height="217" alt="image" src="https://github.com/user-attachments/assets/265acb11-2d3c-4045-b5af-8c3ef681b2a7" />


`192.168.10.10` accounts for the large majority of login attempts (800+), confirming it as the primary attack vector. The username `adi` shows the highest volume of failed attempts, consistent with the Phase 2 targeting. The secondary IP `192.168.20.2` shows lower, unrelated activity — this is the injected noise that had to be separated from the real signal.

### D. Critical Alert: Successful Compromise

<img width="745" height="200" alt="image" src="https://github.com/user-attachments/assets/2c301b06-8c7d-43b0-bb50-e0224a2786b8" />


Multiple `Accepted password` events for user `adi`, timestamped immediately after the brute force peak. This table represents the exact data a Tier 1 analyst would use to open an incident ticket for credential reset and host isolation — not the failed-attempt volume, but the confirmed successful authentication that followed it.

## 3. Reproduction Steps
Here is the exact workflow used to generate this incident.

### Phase 1: Generate the Attack (From Kali)
1. **Enumeration:**
```bash
   hydra -L common-users.txt -p test123 ssh://192.168.20.10 -t 4
```
2. **Targeted brute force:**
```bash
   hydra -l adi -P wordlist.txt ssh://192.168.20.10 -t 8
```
3. **Simulated successful compromise:**
```bash
   ssh adi@192.168.20.10
```

### Phase 2: Inject Background Noise
Manually append unrelated log lines sourced from `192.168.20.2` and `10.0.0.5` into the same `auth.log`, so the dataset isn't artificially clean before ingestion.

### Phase 3: Ingest into Splunk
1. Pull the completed `auth.log` from the Ubuntu target.
2. Upload to Splunk, source type `linux_secure`, index `case02_ssh`.
3. Where default field extraction failed on inconsistent timestamp formatting, use `rex` to manually extract the needed fields.

### Phase 4: Build the Dashboard
Three panels: attack timeline (line chart), top attacker and target identification (bar chart or table), and the critical successful-login table (forensic detail).

#### Expected Outcome
A dashboard showing a clear volume spike during Phase 2, `192.168.10.10` identified as the dominant source, `adi` as the dominant target, and a small but conclusive set of `Accepted password` events confirming the compromise.

## 4. Context and Baseline
- **Target:** Ubuntu Server (`192.168.20.10`) running SSH, same host as case-01.
- **Network Zone:** Isolated segment (OPT1 / `192.168.20.0/24`).
- **Normal Behavior:** A handful of failed logins from a known admin mistyping a password is normal. Enumeration across multiple usernames, followed by a concentrated attack against one account, followed immediately by a successful login, has no legitimate equivalent.

## 5. Deep Dive Analysis
Here is what the evidence tells us when analyzed together.

- **Attack-detection correlation:** the two attack phases, enumeration and targeted brute force, produce statistically distinct patterns in the log. Enumeration is low-volume and spread across usernames; the targeted phase is high-volume and concentrated on one account. Both are visible directly in the timeline panel.
- **The core finding:** volume alone is a weak signal. The attacker IP generated 800+ failed events, but the actual incident is the roughly 6 `Accepted password` events that followed. That distinction, between a lot of noise and a confirmed compromise, is the main thing this case demonstrates.
- **Log parsing:** default `linux_secure` field extraction did not hold up cleanly on every line, particularly around timestamp formatting inconsistencies. Manual `rex` extraction was needed to get usable fields for the queries below.
- **Noise filtering:** the injected traffic from `192.168.20.2` and `10.0.0.5` had to be explicitly excluded from the top-attacker analysis, a rough approximation of the filtering work an analyst does against real background scanning traffic in production.

## 6. MITRE ATT&CK Mapping

| Tactic | Technique ID | Name | Application in This Case |
| :--- | :--- | :--- | :--- |
| **Reconnaissance** | `T1589.001` | Gather Victim Identity Information: Credentials | Phase 1 enumeration against a list of common default usernames. |
| **Credential Access** | `T1110.001` | Brute Force: Password Guessing | Phase 2 targeted Hydra attack against the identified user `adi`. |
| **Initial Access** | `T1078` | Valid Accounts | Phase 3 successful login using the compromised credential. |

> **Tactical Insight:** This case covers three MITRE stages within a single dataset, from account discovery through to confirmed access. Combined with case-01's T1046 finding, the two cases together trace a coherent attack path rather than isolated, unrelated events.

## 7. Verdict
- **Classification:** MALICIOUS (Confirmed Compromise)

Case-01 stopped at reconnaissance. This case goes further: the approximately 6 successful logins for `adi`, occurring immediately after the targeted brute force window, are conclusive evidence of a successful breach rather than a suspected one.

## 8. Recommended Actions
What should happen next in a real SOC queue.

1. **Immediate Response:** Force a password reset for account `adi` and isolate the host pending further investigation.
2. **Containment:** Block `192.168.10.10` at the firewall.
3. **Host Hardening:** Move to key-based SSH authentication, disable password login where feasible.
4. **Detection Tuning:** A rule that alerts on any `Accepted password` event following a dense cluster of failures from the same source and target would catch this in near real time, rather than requiring after-the-fact log review as done here.
5. **Further Investigation:** Review what occurred during the compromised session, commands run, files accessed, any persistence attempts. This case covers detection of the breach itself, not post-compromise activity.

## Splunk Queries and Configuration
The dashboard was built from three saved SPL queries against index `case02_ssh`.

**Query 1 — Attack timeline (failed vs. successful):**
```spl
index=main source="case02-auth.log" 
| rex "Failed password for (?:invalid user )?(?<user>\w+) from (?<src_ip>[\d\.]+)" 
| rex "Accepted password for (?<user>\w+) from (?<src_ip>[\d\.]+)" 
| eval action=if(searchmatch("Accepted"), "Success", "Failed") 
| timechart span=1h count by action
```

**Query 2 — Top attacker identification:**
```spl
index=main source="case02-auth.log" 
| rex "Failed password for (?:invalid user )?(?<user>\w+) from (?<src_ip>[\d\.]+)" 
| rex "Accepted password for (?<user>\w+) from (?<src_ip>[\d\.]+)" 
| stats count by src_ip, user 
| sort -count 
| head 10
```

**Query 3 — Critical success detection:**
```spl
index=main source="case02-auth.log" "Accepted password" 
| rex "Accepted password for (?<user>\w+) from (?<src_ip>[\d\.]+)" 
| table _time, src_ip, user 
| sort -_time
```

> **Note on Field Extraction:**
> The default `linux_secure` source type extracted most fields correctly, but a subset of events failed to parse due to timestamp formatting inconsistencies introduced during the manual noise injection step. The `rex` command in Query 2 was necessary to reliably pull `src_ip` out of raw events that the automatic extraction missed, which turned out to be a more realistic exercise than a perfectly clean ingest would have been.

## Key Learnings
- **Attack-detection correlation:** distinct attack phases leave distinct, identifiable statistical patterns in the same log source, not just in theory but visibly in the dashboard.
- **Log parsing:** default source types do not always extract fields cleanly, and `rex` is a necessary fallback skill rather than an edge case.
- **Dashboard storytelling:** choosing the right visualization per finding, line chart for trend, table for forensic detail, matters as much as the underlying query.
- **Data hygiene:** real-world ingestion involves friction such as timestamp parsing errors, and validating the data before trusting the analysis is part of the actual work, not a separate step.

## Disclaimer
All activity was performed in an isolated home lab environment. No external systems were targeted. Attack simulation used standard security testing tools (Hydra) against infrastructure owned and controlled for this lab, for educational purposes only.

> **Notes for Future Reference:** Case-01 caught the attacker at the reconnaissance stage. This case shows what happens if that reconnaissance is allowed to continue unchecked, from enumeration to a confirmed breach. Read together, the two cases demonstrate why catching activity early at the T1046 stage matters: everything in this case was preventable if the case-01 alert had triggered a block.
