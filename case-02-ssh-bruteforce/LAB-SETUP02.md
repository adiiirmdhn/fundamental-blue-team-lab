# Lab Setup — Case 02: SSH Brute Force Detection & Analysis

## 1. Network Topology

The lab simulates a realistic enterprise network segment with an isolated attack path to prevent external leakage.

```text
                       [ Attacker Machine ]          [ Victim Server ]           [ SIEM / Analysis ]
                          (Kali Linux)                (Ubuntu 22.04)              (Splunk Ent.)
                                |                           |                            |
                                |--- SSH (Port 22) -------->|                            |
                                |                           |--- Syslog/Upload --------->|
                                |                           |                            |
                         IP: 192.168.10.10            IP: 192.168.20.10           IP: 192.168.10.5
                       Role: Red Team / Brute Force   Role: Target Host           Role: Blue Team / SOC
```

**Network Mode:** VMware NAT Network (Isolated Segment)
**Connectivity:** Attacker can reach Victim via SSH; Victim sends logs to SIEM via file upload (simulating log forwarding).
**Security Control:** No internet access for Victim/SIEM during simulation to ensure containment.

## 2. Infrastructure Specifications

| Component | OS / Version | Role | Key Configuration |
|---|---|---|---|
| Attacker VM | Kali Linux 2024.1 | Attack Simulation | Hydra v9.7, Rockyou.txt wordlist, Nmap |
| Victim VM | Ubuntu Server 22.04 LTS | Target System | OpenSSH Server enabled, default auth.log logging |
| SIEM Host | Windows 10 Pro | Log Analysis | Splunk Enterprise 9.x (Free License), Port 8000/8089 |
| Hypervisor | VMware Workstation Pro 17 | Virtualization | Shared Folders (HGFS) for log transfer |

## 3. Attack Tooling & Configuration

**Hydra v9.7** was used for brute force simulation.

Recon phase:
```bash
hydra -L unix_users.txt -P rockyou.txt ssh://<target> -t 4
```

Targeted phase:
```bash
hydra -l adi -P rockyou.txt ssh://<target> -t 8
```

**Wordlists:**
- `metasploit/unix_users.txt` — used for the enumeration phase
- `rockyou.txt` — used for the targeted password cracking phase

**Manual log injection:**
```bash
nano /var/log/auth.log
```
Used to append synthetic noise entries from non-existent IPs (`10.0.0.5`, `172.16.0.9`) to test detection filtering capabilities.

## 4. Data Ingestion Pipeline

Since this is a standalone lab without a centralized syslog server, data was transferred manually to simulate log collection:

1. **Generation:** Attacks executed on Kali, logs written to `/var/log/auth.log` on Ubuntu.
2. **Extraction:** Log file copied from Ubuntu to the Windows host via SCP/Shared Folder.
3. **Ingestion:** File uploaded to Splunk via Add Data > Upload.
4. **Parsing:** Source type set to `linux_secure`, with manual `rex` extraction in queries to handle timestamp inconsistencies.

## 5. Safety & Containment Measures

- **Isolation:** All VMs are on a private NAT network with no bridge to the host's physical internet adapter.
- **Credentials:** Test user `adi` was created solely for this lab, with a weak password intentionally placed in `rockyou.txt`.
- **Cleanup:** All generated logs and test users are deleted post-analysis to maintain lab hygiene.
