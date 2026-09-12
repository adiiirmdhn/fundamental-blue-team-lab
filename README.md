# 🛡️ Fundamental Blue Team Lab

> **A self-contained incident triage portfolio built in an isolated home lab environment.**

This repository documents a progressive journey through core Blue Team operations. Each case simulates a real-world attack scenario—from network reconnaissance to application-layer exploitation—and focuses on **detection, analysis, and documentation** using industry-standard tools like Suricata, Splunk Enterprise, and Sigma rules.


---

## 📂 Case Studies

| Case | Scenario | Tools Used | Key Skill Demonstrated |
| :--- | :--- | :--- | :--- |
| **[Case 01: Network Port Scan](case-01-port-scan/)** | Detecting Nmap SYN Stealth Scans | pfSense, Suricata IDS, TCPDump | Network Traffic Analysis & Signature Detection |
| **[Case 02: SSH Brute Force](case-02-ssh-bruteforce/)** | Analyzing Auth Logs & Triage | Splunk Enterprise, Hydra, Linux CLI | Log Parsing, SPL Queries & False Positive Reduction |
| **[Case 03: Web SQLi Detection](case-03-web-sqli-detection/)** | Identifying Automated Web Attacks | Apache, sqlmap, Splunk Dashboard | Web Log Forensics, Regex Extraction & Visualization |

---

## 🏗️ Lab Architecture

All cases are executed in an isolated virtualized environment to ensure safety and reproducibility:

-   **Network Boundary:** pfSense Firewall/Router (NAT & LAN segmentation)
-   **Attacker Machine:** Kali Linux (2024.x)
-   **Victim Machines:** Ubuntu Server 22.04 LTS (Apache/SSH), Windows 10 (Splunk Host)
-   **SIEM Platform:** Splunk Enterprise 9.x (Free License)

## 🎯 Why This Repo Exists

I wanted a portfolio that shows **how I actually triage an incident**, not just a list of tools I've installed. Every case follows a structured methodology:
1.  **Simulation:** Executing attacks in a controlled environment.
2.  **Detection:** Capturing logs and writing detection logic (Rules/Queries).
3.  **Analysis:** Investigating the data to distinguish noise from true positives.
4.  **Reporting:** Documenting findings with clear visualizations and actionable insights.

## 📄 Final Report

For a high-level executive summary of all completed cases, key findings, and lessons learned, please refer to the **[Final Report](report/final-report.md)**.

---

## ⚠️ Disclaimer
*This repository is for educational and portfolio purposes only. All attacks were performed in a completely isolated home lab environment against systems I own. Never perform these actions on networks or systems without explicit written permission.*
