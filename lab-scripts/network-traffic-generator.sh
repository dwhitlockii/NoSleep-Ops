#!/bin/bash

# Network Traffic Generator for NoSleep-Ops
# Generates realistic background network activity

echo "[+] Network Traffic Generator v1.0"
echo "=================================="

# Configuration
LOG_DIR="/var/log"
APACHE_LOG="$LOG_DIR/apache2/access.log"
SYSLOG="$LOG_DIR/syslog"
DNS_LOG="$LOG_DIR/dns.log"

# Ensure log directories exist
mkdir -p /var/log/apache2

# Normal Web Traffic Simulation
generate_normal_web_traffic() {
    echo "[+] Generating normal web traffic..."
    
    # Common legitimate user agents
    USER_AGENTS=(
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36"
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36"
        "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36"
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:89.0) Gecko/20100101 Firefox/89.0"
        "Mozilla/5.0 (iPhone; CPU iPhone OS 14_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.0 Mobile/15E148 Safari/604.1"
    )
    
    # Normal web pages and resources
    WEB_RESOURCES=(
        "/"
        "/index.html"
        "/about.html"
        "/contact.php"
        "/products.html"
        "/services.html"
        "/blog/"
        "/css/style.css"
        "/js/main.js"
        "/images/logo.png"
        "/favicon.ico"
        "/robots.txt"
        "/api/v1/status"
        "/login.html"
        "/dashboard.php"
    )
    
    # Generate normal traffic
    for i in {1..20}; do
        CLIENT_IP="203.0.113.$((RANDOM % 255))"
        USER_AGENT=${USER_AGENTS[$RANDOM % ${#USER_AGENTS[@]}]}
        RESOURCE=${WEB_RESOURCES[$RANDOM % ${#WEB_RESOURCES[@]}]}
        
        # Normal HTTP status codes
        STATUS_CODES=(200 200 200 200 200 404 302)
        STATUS=${STATUS_CODES[$RANDOM % ${#STATUS_CODES[@]}]}
        
        # Realistic response sizes
        case $STATUS in
            200) SIZE=$((1000 + RANDOM % 50000)) ;;
            404) SIZE=$((500 + RANDOM % 1000)) ;;
            302) SIZE=$((200 + RANDOM % 300)) ;;
        esac
        
        echo "$CLIENT_IP - - [$(date '+%d/%b/%Y:%H:%M:%S %z')] \"GET $RESOURCE HTTP/1.1\" $STATUS $SIZE \"-\" \"$USER_AGENT\"" >> $APACHE_LOG
        sleep 0.5
    done
}

# Email Traffic Simulation
generate_email_traffic() {
    echo "[+] Generating email traffic..."
    
    EMAIL_SERVERS=("mail.company.com" "smtp.gmail.com" "outlook.office365.com" "mail.yahoo.com")
    
    for i in {1..8}; do
        SERVER=${EMAIL_SERVERS[$RANDOM % ${#EMAIL_SERVERS[@]}]}
        CLIENT_IP="10.0.1.$((100 + RANDOM % 50))"
        
        # SMTP connections
        echo "$(date) postfix/smtp[$$]: connect from unknown[$CLIENT_IP]" >> $SYSLOG
        echo "$(date) postfix/smtp[$$]: $CLIENT_IP: client=mail-client[$CLIENT_IP]" >> $SYSLOG
        echo "$(date) postfix/smtp[$$]: NOQUEUE: client=$CLIENT_IP, sasl_method=PLAIN, sasl_username=user@company.com" >> $SYSLOG
        
        # Successful email delivery
        if [ $((RANDOM % 4)) -ne 0 ]; then
            echo "$(date) postfix/smtp[$$]: $CLIENT_IP: to=<recipient@company.com>, relay=$SERVER[198.51.100.10]:25, delay=0.5, delays=0.1/0/0.2/0.2, dsn=2.0.0, status=sent (250 2.0.0 OK)" >> $SYSLOG
        fi
        
        sleep 2
    done
}

# DNS Traffic Simulation
generate_dns_traffic() {
    echo "[+] Generating DNS traffic..."
    
    DOMAINS=(
        "google.com"
        "microsoft.com"
        "amazon.com"
        "github.com"
        "company.com"
        "mail.company.com"
    )
    
    for i in {1..10}; do
        DOMAIN=${DOMAINS[$RANDOM % ${#DOMAINS[@]}]}
        CLIENT_IP="10.0.1.$((10 + RANDOM % 90))"
        
        echo "$(date) named[$$]: client $CLIENT_IP#$((40000 + RANDOM % 20000)): query: $DOMAIN IN A +" >> $SYSLOG
        echo "$(date) named[$$]: client $CLIENT_IP: query response: $DOMAIN IN A 192.0.2.$((RANDOM % 255))" >> $SYSLOG
        sleep 1
    done
}

# Database Connection Simulation
generate_database_traffic() {
    echo "[+] Generating database connection traffic..."
    
    DB_TYPES=("mysql" "postgresql" "mongodb" "redis")
    
    for db in "${DB_TYPES[@]}"; do
        CLIENT_IP="10.0.1.$((20 + RANDOM % 30))"
        
        case $db in
            "mysql")
                echo "$(date) mysqld[$$]: [Note] Access granted for user 'app_user'@'$CLIENT_IP' (using password: YES)" >> $SYSLOG
                echo "$(date) mysqld[$$]: [Note] Connection from $CLIENT_IP:$((30000 + RANDOM % 10000)) established" >> $SYSLOG
                ;;
            "postgresql")
                echo "$(date) postgres[$$]: [$$] LOG: connection received: host=$CLIENT_IP port=$((40000 + RANDOM % 10000))" >> $SYSLOG
                echo "$(date) postgres[$$]: [$$] LOG: connection authorized: user=app_user database=production" >> $SYSLOG
                ;;
            "mongodb")
                echo "$(date) mongod[$$]: [conn$$] received client metadata from $CLIENT_IP:$((50000 + RANDOM % 10000)) conn$$: { driver: { name: \"nodejs\", version: \"3.6.0\" } }" >> $SYSLOG
                ;;
            "redis")
                echo "$(date) redis-server[$$]: [$$] $CLIENT_IP:$((60000 + RANDOM % 5000)) - \"PING\"" >> $SYSLOG
                echo "$(date) redis-server[$$]: [$$] $CLIENT_IP:$((60000 + RANDOM % 5000)) - \"GET\" \"session:user123\"" >> $SYSLOG
                ;;
        esac
        
        sleep 1.5
    done
}

# File Transfer Simulation
generate_file_transfer_traffic() {
    echo "[+] Generating file transfer traffic..."
    
    # FTP traffic
    CLIENT_IP="10.0.1.$((50 + RANDOM % 50))"
    echo "$(date) vsftpd[$$]: CONNECT: Client \"$CLIENT_IP\"" >> $SYSLOG
    echo "$(date) vsftpd[$$]: [user] OK LOGIN: Client \"$CLIENT_IP\"" >> $SYSLOG
    echo "$(date) vsftpd[$$]: [user] OK DOWNLOAD: Client \"$CLIENT_IP\", \"/files/document.pdf\", $((1000000 + RANDOM % 5000000)) bytes" >> $SYSLOG
    
    # SFTP traffic
    echo "$(date) sshd[$$]: Accepted publickey for fileuser from $CLIENT_IP port $((20000 + RANDOM % 10000)) ssh2: RSA SHA256:abc123..." >> $SYSLOG
    echo "$(date) sshd[$$]: pam_unix(sshd:session): session opened for user fileuser by (uid=0)" >> $SYSLOG
    
    # SMB traffic (Windows file sharing)
    SMB_CLIENT="10.0.1.$((60 + RANDOM % 40))"
    echo "$(date) smbd[$$]: [2021/06/23 $(date '+%H:%M:%S')] connect to service shared from $SMB_CLIENT (10.0.1.60)" >> $SYSLOG
    echo "$(date) smbd[$$]: [2021/06/23 $(date '+%H:%M:%S')] opened file /shared/reports/monthly_report.xlsx read=Yes write=No (numopen=1)" >> $SYSLOG
}

# System Activity Simulation
generate_system_activity() {
    echo "[+] Generating normal system activity..."
    
    echo "$(date) cron[$$]: (root) CMD (/usr/bin/updatedb)" >> $SYSLOG
    echo "$(date) systemd[1]: Started Daily apt download activities." >> $SYSLOG
    echo "$(date) sshd[$$]: Accepted publickey for admin from 10.0.1.50 port 22 ssh2" >> $SYSLOG
}

# VPN Connection Simulation
generate_vpn_traffic() {
    echo "[+] Generating VPN connection traffic..."
    
    VPN_CLIENTS=("192.168.100.10" "192.168.100.15" "192.168.100.20")
    
    for client in "${VPN_CLIENTS[@]}"; do
        echo "$(date) openvpn[$$]: $client:$((40000 + RANDOM % 10000)) TLS: Initial packet from [AF_INET]$client:$((40000 + RANDOM % 10000))" >> $SYSLOG
        echo "$(date) openvpn[$$]: $client:$((40000 + RANDOM % 10000)) VERIFY OK: depth=1, CN=VPN-CA" >> $SYSLOG
        echo "$(date) openvpn[$$]: $client:$((40000 + RANDOM % 10000)) peer info: IV_VER=2.4.7" >> $SYSLOG
        echo "$(date) openvpn[$$]: $client:$((40000 + RANDOM % 10000)) Control Channel: TLSv1.2, cipher TLSv1.2 ECDHE-RSA-AES256-GCM-SHA384" >> $SYSLOG
        
        sleep 2
    done
}

# Main traffic generation function
generate_traffic() {
    case "$1" in
        "web")
            generate_normal_web_traffic
            ;;
        "email")
            generate_email_traffic
            ;;
        "dns")
            generate_dns_traffic
            ;;
        "database")
            generate_database_traffic
            ;;
        "files")
            generate_file_transfer_traffic
            ;;
        "system")
            generate_system_activity
            ;;
        "vpn")
            generate_vpn_traffic
            ;;
        "continuous")
            echo "[+] Starting continuous traffic generation..."
            while true; do
                generate_normal_web_traffic &
                sleep 30
                generate_dns_traffic &
                sleep 45
                generate_system_activity &
                sleep 60
                wait
            done
            ;;
        "all")
            echo "[+] Generating all types of network traffic..."
            generate_normal_web_traffic
            generate_email_traffic
            generate_dns_traffic
            generate_database_traffic
            generate_file_transfer_traffic
            generate_system_activity
            generate_vpn_traffic
            ;;
        *)
            echo "Network Traffic Generator"
            echo "Usage: $0 {web|email|dns|database|files|system|vpn|continuous|all}"
            echo ""
            echo "Traffic Types:"
            echo "  web        - Normal web browsing traffic"
            echo "  email      - SMTP/IMAP email traffic"
            echo "  dns        - DNS query/response traffic"
            echo "  database   - Database connection traffic"
            echo "  files      - File transfer traffic (FTP/SFTP/SMB)"
            echo "  system     - Normal system activity"
            echo "  vpn        - VPN connection traffic"
            echo "  continuous - Run continuous background traffic"
            echo "  all        - Generate all traffic types once"
            exit 1
            ;;
    esac
    
    echo "[+] Network traffic generation complete!"
}

# Execute traffic generation
generate_traffic "$1" 