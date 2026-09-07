# Case-02: SSH Brute Force Detection & Analysis (Splunk)

## What Happened
This case simulates a realistic, multi-stage SSH brute force attack against the Ubuntu target, going one step further than case-01: instead of a single scan, this is a full attack lifecycle — user enumeration, targeted brute force, and a successful compromise — deliberately mixed with unrelated background noise to mimic what a real `auth.log` looks like outside a clean lab. Detection and analysis were done in Splunk Enterprise, ingesting the resulting log and building a dashboard to separate the actual breach from the noise around it.

- **Status:** Completed
- **Severity:** Critical (Credential Access → Successful Compromise)

## Lab Environment
Same base topology as case-01, no new VM required for the attack itself. Splunk Enterprise runs self-hosted on Windows (host machine), not inside the isolated lab network.

**Quick overview:**
- **Attacker:** Kali Linux, Hydra v9.7 — `192.168.10.10`
- **Target:** Ubuntu Server, SSH enabled — `192.168.20.10`
- **Analysis platform:** Splunk Enterprise (self-hosted, Windows), source type `linux_secure`
- **Data volume analyzed:** 1,900+ events

---

## 1. The Trigger
Unlike case-01, there wasn't a single alert that kicked this off — the log itself was built as a full incident to investigate after the fact. The trigger, from an analyst's perspective, is the presence of an `Accepted password` event for user `adi` sitting right after a dense cluster of failed logins from the same source.

- **Primary source IP:** `192.168.10.10` (Kali Linux) — 800+ login attempts
- **Targeted account:** `adi`
- **Successful logins recorded:** ~6, against a background of thousands of failures

> **Why this matters:** In a real environment, this is the "needle in a haystack" problem SOC analysts deal with constantly — thousands of failed attempts are noise, but a handful of `Accepted password` events buried in that noise are the actual incident.

---

## 2. Evidence Collection

### A. Attack Simulation (3 phases, Kali)

**Phase 1 — Reconnaissance (user enumeration):** low-volume dictionary attack against common default usernames (`root`, `admin`, `test`, etc.), simulating an attacker mapping valid accounts before committing effort to one target.

**Phase 2 — Targeted brute force:** high-volume attack against the identified user `adi`, 8 concurrent Hydra threads, generating hundreds of failed attempts in a short window.

```bash
hydra -l adi -P wordlist.txt ssh://192.168.20.10 -t 8
```

**Phase 3 — Successful compromise:** a legitimate SSH login as `adi` immediately after the brute force phase, producing the `Accepted password` event used as the primary indicator of compromise.

**Noise injection:** log entries from unrelated IPs (`192.168.20.2`, `10.0.0.5`) manually appended to `auth.log`, simulating background botnet traffic an analyst would need to filter out in a real environment.

### B. Dashboard: Attack Timeline (Volume vs. Success)

![Attack timeline — failed vs successful logins](screenshots/case02-timeline.png)

A sharp spike in failed attempts lines up with the Phase 2 targeted Hydra run. The success line stays nearly flat against that volume — out of thousands of failures, only about 6 successful logins landed, which is the statistical signature of a focused, high-effort attack rather than random credential spraying.

### C. Dashboard: Top Attacking Sources & Targeted Users

![Top attacker IPs and targeted usernames](screenshots/case02-top-ips.png)

`192.168.10.10` accounts for the large majority of attempts (800+), confirming it as the primary attack vector. `adi` is the clear top targeted username, consistent with Phase 2. The secondary IP `192.168.20.2` shows lower, unrelated volume — this is the injected noise, and separating it from the real attacker's traffic was part of the exercise.

### D. Dashboard: Critical Alert — Successful Compromise

![Successful SSH authentication events](screenshots/case02-critical-table.png)

Multiple `Accepted password` events for `adi`, timestamped immediately after the brute force peak. This table is what a Tier 1 analyst would actually use to open an incident ticket — not the failed-attempt volume, but the confirmed successful authentication that followed it.

---

## 3. Reproduction Steps

### Phase 1: Generate the attack

```bash
# recon / user enumeration
hydra -L common-users.txt -p test123 ssh://192.168.20.10 -t 4

# targeted brute force against the identified user
hydra -l adi -P wordlist.txt ssh://192.168.20.10 -t 8

# simulate the successful compromise
ssh adi@192.168.20.10
```

### Phase 2: Inject noise (optional, for realism)

Manually append unrelated log lines from `192.168.20.2` and `10.0.0.5` into the same `auth.log`, so the dataset isn't artificially clean.

### Phase 3: Ingest into Splunk

1. Pull `auth.log` from the Ubuntu target.
2. Upload to Splunk, source type `linux_secure`.
3. Where default field extraction failed (timestamp/format inconsistencies), use `rex` to manually extract fields — see queries below.

### Phase 4: Build the dashboard

Three panels: attack timeline (line chart), top attacker/target identification (bar chart or table), and the critical successful-login table (forensic detail).

---

## 4. Context and Baseline
- **Target:** Ubuntu Server, OpenSSH, same target as case-01.
- **Normal behavior:** A handful of failed logins from an admin mistyping a password, no clustering, no `Accepted password` event following a failure spike. What was simulated here — enumeration, then a concentrated attack, then a successful login right after — has no legitimate equivalent.

---

## 5. Deep Dive Analysis

**Attack-detection correlation:** the two attack phases (enumeration vs. targeted brute force) produce statistically distinct patterns in the log — low-volume/spread-out vs. high-volume/concentrated — and that distinction is visible directly in the timeline panel, not just inferred from knowing what was run.

**Log parsing:** default `linux_secure` field extraction didn't hold up cleanly against every line, particularly around timestamp formatting. Manual `rex` extraction was needed to get consistent fields for the queries below.

**The core finding:** volume alone is a poor signal. `192.168.10.10` generated 800+ failed events, but the actual incident is the ~6 `Accepted password` events — this is the practical difference between "a lot of noise happened" and "an account was compromised."

**Noise filtering:** the injected traffic from `192.168.20.2` and `10.0.0.5` had to be explicitly excluded from the top-attacker analysis to avoid diluting the real signal — a rough approximation of the filtering work a SOC analyst does against real background scanning traffic.

---

## 6. MITRE ATT&CK Mapping

| Tactic | Technique ID | Name | Application in This Case |
|---|---|---|---|
| Reconnaissance | T1589.001 | Gather Victim Identity Information: Credentials | Phase 1 enumeration against common default usernames. |
| Credential Access | T1110.001 | Brute Force: Password Guessing | Phase 2 targeted Hydra attack against the identified user. |
| Initial Access | T1078 | Valid Accounts | Phase 3 successful login using the compromised credential. |

> **Tactical Insight:** This case covers three MITRE stages in a single log, from initial account discovery through to confirmed access — closer to how a real attack actually unfolds than a single isolated technique.

---

## 7. Verdict
**Classification: MALICIOUS (Confirmed Compromise)**

Unlike case-01, which stopped at reconnaissance, this case shows the full path to a successful breach. The ~6 successful logins for `adi`, immediately following the targeted brute force window, are conclusive — this is not a suspected incident, it's a confirmed one.

---

## 8. Recommended Actions
1. **Immediate:** Force password reset for account `adi`, isolate the host pending investigation into what the attacker did after logging in.
2. **Containment:** Block `192.168.10.10` at the firewall.
3. **Hardening:** Move to key-based SSH authentication, disable password login where feasible.
4. **Detection tuning:** A rule alerting on any `Accepted password` event following a dense cluster of failures from the same source/target pair would have caught this in near-real-time rather than requiring after-the-fact log review.
5. **Further investigation:** Review what the attacker did during the compromised session (commands run, files accessed, persistence attempts) — this case only covers detection of the breach itself, not post-compromise activity.

---

## Splunk Queries Used

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

---

## Key Learnings
- **Attack-detection correlation:** distinct attack phases leave distinct, identifiable statistical patterns in the same log source.
- **Log parsing:** default source types don't always extract fields cleanly — `rex` is a necessary fallback skill, not an edge case.
- **Dashboard storytelling:** choosing the right visualization per finding (line chart for trend, table for forensic detail) matters as much as the underlying query.
- **Data hygiene:** real-world ingestion has friction — timestamp parsing issues, inconsistent formatting — and validating the data before trusting the analysis is part of the job.

## Disclaimer
All activity was performed in an isolated home lab environment. No external systems were targeted. Attack simulation used standard security testing tools (Hydra) against infrastructure owned and controlled for this lab, for educational purposes only.

> **Notes for Future Reference:** This case shows the gap between "an attack was attempted" (case-01) and "an attack succeeded" (this case) — and why volume-based metrics alone are a weak signal for a SOC analyst without correlating them against the much smaller set of actual successful events.
