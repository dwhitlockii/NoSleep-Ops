#!/bin/bash

# generate-logs.sh: Spam logs for testing
LOGFILES=(/var/log/auth.log /var/log/syslog /var/log/apache2/access.log)

# Start rsyslog
service rsyslog start

# Start apache2 if available
service apache2 start

echo "[+] Starting log generation..."

while true; do
    echo "$(date) sshd[12345]: Failed password for invalid user test from 192.0.2.$((RANDOM % 255)) port $((10000 + RANDOM % 50000)) ssh2" >> /var/log/auth.log
    echo "$(date) apache2[12345]: GET /index.php?id=' OR 1=1 -- HTTP/1.1" >> /var/log/apache2/access.log
    echo "$(date) systemd[1]: Starting fake.service..." >> /var/log/syslog
    sleep 1
done
