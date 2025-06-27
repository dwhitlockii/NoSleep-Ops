# 💤 NoSleep Ops

Welcome to **NoSleep Ops** — the ultimate sysadmin and security operations playground.
This lab simulates a real-world Linux battlefield with log storms, brute-force attacks, and malicious traffic. Perfect for testing detection, response, and automation tools without risking production.

---

## 🧰 What's Inside

### Dockerized Environment
- **ubuntu-host** – Fully loaded Linux admin box (auditd, fail2ban, chkrootkit, ClamAV, tcpdump, etc.)
- **kali-attacker** – Simulate external attacks and test detection workflows
- **zeek** – Network security monitoring
- **suricata** – Intrusion detection system
- **ELK stack** – Centralized logging, search, and alerting
- **fail2ban** – Ban bad IPs dynamically
- **clamav** – Detect malicious files
- **log-generator** – Auto-spams logs for realistic noise

### Enhanced Features
- **Enhanced Attack Simulation Suite** – Realistic multi-vector attack campaigns
- **Pre-configured Kibana Dashboards** – Instant security visualization
- **Network Traffic Generators** – Realistic background noise
- **Automated Alerting System** – Real-time threat notifications
- **AI-Powered Threat Hunter** – Machine learning threat detection
- **Executive Security Dashboard** – C-level security metrics

---

## 🚀 Getting Started

### 1. Clone & Enter the Lab
```bash
git clone <your-fork-here>
cd NoSleep-Ops
```

### 2. Build & Start All Containers
```bash
docker compose up --build
```

### 3. Check the Playground
- `ubuntu-host`: main system under test
- `kali-attacker`: inject traffic & attacks
- `log-generator`: floods `/var/log` with brute-force & SQLi patterns

---

## 🎯 **Menu Commands & Access**

### **Main Interactive Menu**
```bash
python3 demo-next-gen-soc.py
```
**Interactive menu with options:**
- Open all dashboards in browser
- Generate attack scenarios  
- Run live demonstration
- Show all features

### **Live Attack Demonstration**
```bash
./live-demo.sh
```
Starts continuous attack simulation with real-time dashboard updates.

### **Enhanced Features Demo**
```bash
docker exec ubuntu-host /opt/lab-scripts/demo-enhanced-features.sh
```
Shows comprehensive demo of all enhanced cybersecurity lab features.

---

## 🛠️ **Individual Component Menus**

### **Enhanced Attack Suite**
```bash
docker exec ubuntu-host /opt/lab-scripts/enhanced-attack-suite.sh
```
**Available attack scenarios:**
- `ssh-advanced` – Advanced SSH attacks (dictionary, credential stuffing)
- `web-advanced` – OWASP Top 10 attacks (SQLi, XSS, LFI, RCE)
- `lateral-movement` – SMB enumeration and lateral movement
- `data-exfiltration` – DNS tunneling and large file transfers
- `privilege-escalation` – Advanced privesc techniques
- `c2-communication` – Command & control beaconing
- `malware-activity` – Malware-like file system behavior
- `crypto-mining` – Cryptocurrency mining simulation
- `apt-campaign` – Full APT attack chain simulation
- `all-advanced` – Run all advanced attack types

### **Network Traffic Generator**
```bash
docker exec ubuntu-host /opt/lab-scripts/network-traffic-generator.sh
```
**Traffic generation options:**
- `web` – Normal web browsing traffic
- `email` – SMTP/IMAP email traffic
- `dns` – DNS query/response traffic
- `database` – Database connection traffic
- `files` – File transfer traffic (FTP/SFTP/SMB)
- `system` – Normal system activity
- `vpn` – VPN connection traffic
- `continuous` – Run continuous background traffic
- `all` – Generate all traffic types once

### **Automated Alerting System**
```bash
docker exec ubuntu-host /opt/lab-scripts/alerting-system.sh
```
**Alerting system commands:**
- `start` – Start real-time security monitoring
- `stats` – Show alert statistics  
- `test` – Send test alert

---

## 🌐 **Web Dashboard Access**

### **Security Operations Center Dashboards**
- **Main Dashboard**: `http://localhost:5000`
- **Advanced SOC**: `http://localhost:5000/advanced`
- **AI Threat Hunter**: `http://localhost:5000/threat-hunter`
- **Executive Dashboard**: `http://localhost:5000/executive`
- **Mobile SOC**: `http://localhost:5000/mobile`
- **Forensics Timeline**: `http://localhost:5000/forensics`

### **Analytics & Visualization**
- **Kibana Dashboards**: `http://localhost:15601`
  - SSH Attack Timeline
  - Top Attacking IP Addresses
  - Web Attack Patterns
  - Geographic Attack Distribution
  - Real-time Security Overview

---

## ⚡ **Quick Start Commands**

### **Launch Full Demo**
```bash
# Start the main interactive menu
python3 demo-next-gen-soc.py

# Option 3: Run live demonstration (recommended)
```

### **Manual Attack Scenarios**
```bash
# Run full APT campaign
docker exec ubuntu-host /opt/lab-scripts/enhanced-attack-suite.sh apt-campaign

# Generate continuous background traffic
docker exec ubuntu-host /opt/lab-scripts/network-traffic-generator.sh continuous

# Start real-time monitoring
docker exec ubuntu-host /opt/lab-scripts/alerting-system.sh start
```

### **View Real-time Statistics**
```bash
# Alert statistics
docker exec ubuntu-host /opt/lab-scripts/alerting-system.sh stats

# Log analysis
docker exec ubuntu-host tail -f /var/log/auth.log
docker exec ubuntu-host tail -f /var/log/apache2/access.log
```

---

## 🕵️‍♂️ Challenges

Try these exercises:

- Detect brute-force attempts in `/var/log/auth.log` and auto-ban IPs with iptables
- Correlate logs between Zeek, Suricata, and auth logs
- Visualize failed logins over time with ELK
- Use `auditd` to detect privilege escalation attempts
- Block TOR exit node logins dynamically
- Build a fail2ban filter for a custom web app
- Write a Suricata rule for detecting SQLi in Apache logs
- Analyze APT campaign patterns using the AI Threat Hunter
- Create custom executive reports from security metrics
- Implement automated incident response workflows

---

## 🎯 **Advanced Features**

### **Machine Learning Analytics**
- Behavioral anomaly detection
- Predictive attack analysis
- Automated threat hunting
- Advanced forensics engine

### **Enterprise Integration**
- MITRE ATT&CK framework mapping
- Executive security reporting
- Compliance monitoring
- Risk assessment automation

### **Real-time Operations**
- Live attack simulation
- Continuous threat monitoring
- Automated alerting and response
- Performance metrics tracking

---

## 📎 Notes

- Modify `generate-logs.sh` to tune log patterns
- Add custom Suricata rules to `/etc/suricata/rules/local.rules`
- Enable alerts in Kibana after parsing logs via Logstash
- All enhanced features are production-ready for SOC training
- Scripts support both interactive and automated execution
- Dashboard data updates in real-time during attack simulations

---

## 📜 License
MIT. Use responsibly.

---

> **NoSleep Ops** — where logs don't sleep, and neither do you.
