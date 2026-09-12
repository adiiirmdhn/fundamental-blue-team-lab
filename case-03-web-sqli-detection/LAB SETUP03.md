# Lab Setup — Case 03: Web SQL Injection Detection & Log Analysis

## 1. Objective

Build an isolated lab environment to simulate a SQL Injection (SQLi) attack against a vulnerable web login form, generate Apache access logs from that attack, and prepare the resulting data for ingestion into Splunk for detection analysis.

## 2. Architecture & Topology

```text
[ Attacker Machine ]          [ Victim Server ]           [ SIEM / Analysis ]
      (Kali Linux)                (Ubuntu 22.04)              (Splunk Ent.)
            |                           |                            |
            |--- HTTP/POST (Port 80) -->|                            |
            |   (sqlmap payload)        |--- Access Logs ----------->|
            |                           |   (/var/log/apache2/)      |
   IP: 192.168.10.10            IP: 192.168.20.10           IP: 192.168.10.5
   Role: Red Team               Role: Target Web App        Role: Blue Team / SOC
```

**Network Mode:** VMware NAT Network (Isolated Segment)
**Connectivity:** Attacker reaches the victim over HTTP (port 80). Victim logs are transferred to the SIEM via SCP/upload.
**Containment:** No internet access for the victim during simulation.

## 3. Infrastructure Specifications

| Component | OS / Version | Role | Key Configuration |
|---|---|---|---|
| Attacker VM | Kali Linux 2024.1 | Attack Simulation | sqlmap v1.7+, curl, Nmap |
| Victim VM | Ubuntu Server 22.04 LTS | Vulnerable Web App | Apache 2.4, PHP 8.1, MariaDB 10.6 |
| SIEM Host | Windows 10 Pro | Log Analysis | Splunk Enterprise 9.x (Free License), Port 8000 |
| Hypervisor | VMware Workstation Pro 17 | Virtualization | Shared Folders (HGFS) or SCP for log transfer |

## 4. Step-by-Step Deployment Guide

### Phase A: Victim Server Provisioning (Ubuntu)

**A1. Install the web stack**
```bash
sudo apt update
sudo apt install apache2 php libapache2-mod-php mariadb-server php-mysql -y
sudo systemctl enable --now apache2 mariadb
```

**A2. Initialize the vulnerable database**
```bash
sudo mysql -u root <<EOF
CREATE DATABASE vuln_app;
USE vuln_app;
CREATE TABLE users (id INT AUTO_INCREMENT PRIMARY KEY, username VARCHAR(50), password VARCHAR(50));
INSERT INTO users (username, password) VALUES ('admin', 'secret123');
GRANT ALL PRIVILEGES ON vuln_app.* TO 'root'@'localhost';
FLUSH PRIVILEGES;
EOF
```

**A3. Deploy the vulnerable PHP application**

Create `/var/www/html/login.php`:
```php
<?php
$conn = new mysqli("localhost", "root", "", "vuln_app");
if ($_SERVER["REQUEST_METHOD"] == "POST") {
    // VULNERABILITY: unsanitized input allows SQL injection
    $user = $_POST['username'];
    $pass = $_POST['password'];
    $sql = "SELECT * FROM users WHERE username='$user' AND password='$pass'";
    $result = $conn->query($sql);
    echo ($result && $result->num_rows > 0) ? "<h1>Login Successful!</h1>" : "<h1>Login Failed.</h1>";
}
?>
<form method="POST"><input name="username"><input type="password" name="password"><button>Login</button></form>
```

**A4. Verify logging is active**

Default path: `/var/log/apache2/access.log`
```bash
sudo tail -f /var/log/apache2/access.log
```

### Phase B: Attack Simulation (Kali Linux)

**B1. Connectivity check**
```bash
curl -I http://192.168.20.10/login.php
```

**B2. Run the automated SQLi attack**

Use sqlmap to generate a range of malicious requests with varied payloads:
```bash
sqlmap -u "http://192.168.20.10/login.php" \
       --data="username=admin&password=test" \
       --level=3 --risk=2 \
       --batch \
       --technique=BEUSTQ
```

Flags:
- `--data`: POST parameters to test
- `--level=3 --risk=2`: increases payload variety and depth of testing
- `--batch`: non-interactive mode
- `--technique=BEUSTQ`: tests all SQLi technique classes (Boolean, Error, Union, Stacked, Time, Query)

**B3. Inject background noise (optional)**

Append synthetic scanner traffic to avoid analyzing an artificially clean log:
```bash
echo '10.0.0.99 - - [12/Sep/2026:10:15:00 +0000] "GET /wp-admin HTTP/1.1" 404 453 "-" "Mozilla/5.0"' | sudo tee -a /var/log/apache2/access.log
echo '172.16.0.5 - - [12/Sep/2026:10:16:00 +0000] "GET /phpmyadmin HTTP/1.1" 404 453 "-" "Nmap Scripting Engine"' | sudo tee -a /var/log/apache2/access.log
```

### Phase C: Log Extraction & Transfer

**C1. Extract the log via SCP (from Kali)**
```bash
scp adi@192.168.20.10:/var/log/apache2/access.log ~/case03-access.log
sudo chown kali:kali ~/case03-access.log
```

**C2. Verify the payload is present**
```bash
grep -i "union\|select\|or 1=1" ~/case03-access.log | head -5
```
Expected output shows URL-encoded SQL payloads in the request URI or POST data.

## 5. Data Ingestion Pipeline (Splunk)

1. **Source file:** `~/case03-access.log` (on Kali), or uploaded from the Windows host.
2. **Upload method:** Splunk Web UI > Settings > Add Data > Upload.
3. **Source type:** `access_combined` (built-in Apache parser). This automatically extracts `clientip`, `method`, `uri_path`, `status`, and `user_agent`.
4. **Host value:** `ubuntu-victim-web`.
5. **Index:** `main`, or a custom sandbox index.
6. **Timestamp override:** not required — Apache's standard `[DD/Mon/YYYY:HH:MM:SS]` format is recognized by Splunk automatically.

## 6. Safety & Containment Measures

- **Isolation:** all VMs sit on a private NAT network with no bridge to the physical host's internet adapter.
- **Vulnerability scope:** the SQLi vulnerability is intentionally limited to a single PHP file (`login.php`), with no real sensitive data behind it.
- **Cleanup:** after analysis, drop the `vuln_app` database, remove `/var/www/html/login.php`, and purge the Splunk index data via `| delete` or an index retention policy.
- **Ethical boundary:** the attack was executed only against infrastructure owned and controlled for this lab. No external targets were involved.

## 7. Troubleshooting

| Issue | Cause | Solution |
|---|---|---|
| sqlmap reports "not vulnerable" | WAF/ModSecurity blocking payloads | Disable ModSecurity: `sudo a2dismod security2 && sudo systemctl restart apache2` |
| Empty access.log after the attack | Apache logging disabled | Check `/etc/apache2/apache2.conf` for the `CustomLog` directive |
| Splunk shows the wrong timestamp | Locale mismatch | Ensure Ubuntu locale is `en_US.UTF-8`: `sudo locale-gen en_US.UTF-8` |
| SCP permission denied | SSH key/auth issue | Use password auth, or copy via VMware shared folder drag-and-drop |
