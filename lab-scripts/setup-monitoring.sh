#!/bin/bash

# NoSleep-Ops Lab Setup Script
# Configures monitoring, logging, and security tools

echo "[+] NoSleep-Ops Lab Environment Setup"
echo "======================================"

# Start essential services
echo "[+] Starting rsyslog..."
service rsyslog start

echo "[+] Starting auditd..."
service auditd start

echo "[+] Starting fail2ban..."
service fail2ban start

# Configure auditd rules for security monitoring
echo "[+] Configuring audit rules..."
auditctl -w /etc/passwd -p wa -k passwd_changes
auditctl -w /etc/shadow -p wa -k shadow_changes
auditctl -w /etc/sudoers -p wa -k sudoers_changes
auditctl -w /bin/su -p x -k privilege_escalation
auditctl -w /usr/bin/sudo -p x -k privilege_escalation

# Set up log rotation
echo "[+] Configuring log rotation..."
cat > /etc/logrotate.d/nosleep-ops << EOF
/var/log/auth.log
/var/log/syslog
/var/log/apache2/*.log {
    daily
    missingok
    rotate 7
    compress
    delaycompress
    notifempty
    sharedscripts
    postrotate
        /bin/kill -HUP \$(cat /var/run/rsyslogd.pid 2> /dev/null) 2> /dev/null || true
    endscript
}
EOF

# Create monitoring directories
mkdir -p /opt/nosleep-ops/logs
mkdir -p /opt/nosleep-ops/alerts

echo "[+] Lab environment setup complete!"
echo "[+] Services status:"
service --status-all | grep -E "(rsyslog|auditd|fail2ban)"

echo ""
echo "Available log files:"
ls -la /var/log/ | grep -E "(auth|syslog|apache)" 