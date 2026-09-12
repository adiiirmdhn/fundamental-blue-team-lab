# Final Report: Fundamental Blue Team Lab

**Status:** Completed  
**Author:** Adi Ramadhani  
**Date:** September 11, 2026  

## Executive Summary
This lab series demonstrates a progressive journey through core Blue Team operations, moving from network-layer reconnaissance to system-level brute force detection, and finally application-layer web attack analysis. Each case simulates real-world attack scenarios in an isolated environment and focuses on detecting, analyzing, and documenting threats using industry-standard tools like Suricata, Splunk, and custom Python scripts.

## Case Verdicts & Key Findings

| Case | Scenario | Verdict | Key Finding | Detection Artifact |
| :--- | :--- | :--- | :--- | :--- |
| **Case 01** | Network Port Scan | ✅ Detected | Suricata successfully identified Nmap SYN stealth scans via TCP stream behavior rather than static signatures. | `suricata-port-scan.rules`, PCAP analysis |
| **Case 02** | SSH Brute Force | ✅ Detected | Differentiated 6 successful breaches from 800+ failed attempts using custom Splunk SPL queries and regex parsing. | `sigma-ssh-bruteforce.yml`, Splunk Dashboard |
| **Case 03** | Web SQL Injection | ✅ Detected | Identified automated sqlmap attacks via User-Agent fingerprinting and correlated HTTP 500 errors with exploitation attempts. | Splunk SQLi Dashboard, Apache Log Analysis |

## What This Lab Demonstrated

### 1. Multi-Layered Defense Visibility
-   **Network Layer (L3/L4):** Understanding how IDS/IPS detects reconnaissance at the packet level.
-   **System Layer (L7/Auth):** Analyzing authentication logs to distinguish between noise and actual compromise.
-   **Application Layer (L7/Web):** Parsing unstructured web logs to find injection patterns and tool signatures.

### 2. Practical SIEM Proficiency
-   Built custom dashboards in Splunk Enterprise to visualize attack timelines and top offenders.
-   Overcame parser limitations by writing manual Regex (`rex`) to extract critical fields like User-Agent from raw logs.
-   Learned to correlate different data points (IP + Tool + Status Code) to reduce false positives.

### 3. Incident Response Fundamentals
-   **Identification:** Recognizing attack signatures (e.g., sqlmap user-agent, Nmap SYN flags).
-   **Analysis:** Determining the scope of impact (successful vs. failed attempts).
-   **Documentation:** Creating structured reports and reusable detection rules (Sigma/Suricata).

## Lessons Learned & Future Improvements
-   **Log Quality Matters:** Default parsers often fail; knowing how to manually parse logs is a superpower for SOC analysts.
-   **Context is King:** A single HTTP 500 error means nothing, but 300 of them in 1 minute from one IP is a confirmed incident.
-   **Next Steps:** Plan to integrate these detections into a SOAR platform for automated response and explore Windows Event Log analysis for Active Directory environments.
