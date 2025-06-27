# 💤 NoSleep Ops

Welcome to **NoSleep Ops** — the ultimate sysadmin and security operations playground.
This lab simulates a real-world Linux battlefield with log storms, brute-force attacks, and malicious traffic. Perfect for testing detection, response, and automation tools without risking production.

---

## 🧰 What's Inside

python demo-next-gen-soc.py
python generate-attacks.py  

Basic Dashboard: http://localhost:5000
Advanced SOC: http://localhost:5000/advanced
AI Threat Hunter: http://localhost:5000/threat-hunter
Executive Dashboard: http://localhost:5000/executive
Mobile Dashboard: http://localhost:5000/mobile
Forensics Dashboard: http://localhost:5000/forensics
Attack monitoring active

### Dockerized Environment
- **ubuntu-host** – Fully loaded Linux admin box (auditd, fail2ban, chkrootkit, ClamAV, tcpdump, etc.)
- **kali-attacker** – Simulate external attacks and test detection workflows
- **zeek** – Network security monitoring
- **suricata** – Intrusion detection system
- **ELK stack** – Centralized logging, search, and alerting
- **fail2ban** – Ban bad IPs dynamically
- **clamav** – Detect malicious files
- **log-generator** – Auto-spams logs for realistic noise

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

## 🕵️‍♂️ Challenges

Try these exercises:

- Detect brute-force attempts in `/var/log/auth.log` and auto-ban IPs with iptables
- Correlate logs between Zeek, Suricata, and auth logs
- Visualize failed logins over time with ELK
- Use `auditd` to detect privilege escalation attempts
- Block TOR exit node logins dynamically
- Build a fail2ban filter for a custom web app
- Write a Suricata rule for detecting SQLi in Apache logs

---

## 📎 Notes

- Modify `generate-logs.sh` to tune log patterns
- Add custom Suricata rules to `/etc/suricata/rules/local.rules`
- Enable alerts in Kibana after parsing logs via Logstash

---

## 📜 License
MIT. Use responsibly.

---

> **NoSleep Ops** — where logs don’t sleep, and neither do you.
