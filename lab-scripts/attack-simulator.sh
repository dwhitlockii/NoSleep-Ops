#!/bin/bash

# NoSleep-Ops Attack Simulator
# Generates realistic attack patterns for testing

echo "[+] NoSleep-Ops Attack Simulator"
echo "================================="

# Function to simulate SSH brute force
simulate_ssh_bruteforce() {
    echo "[+] Simulating SSH brute force attacks..."
    for i in {1..10}; do
        FAKE_IP="192.0.2.$((RANDOM % 255))"
        FAKE_USER="user$((RANDOM % 100))"
        FAKE_PORT="$((20000 + RANDOM % 10000))"
        
        echo "$(date) sshd[$$]: Failed password for invalid user $FAKE_USER from $FAKE_IP port $FAKE_PORT ssh2" >> /var/log/auth.log
        echo "$(date) sshd[$$]: Connection closed by invalid user $FAKE_USER $FAKE_IP port $FAKE_PORT [preauth]" >> /var/log/auth.log
        
        sleep 0.5
    done
}

# Function to simulate web attacks
simulate_web_attacks() {
    echo "[+] Simulating web application attacks..."
    
    WEB_ATTACKS=(
        "GET /admin/login.php?user=admin&pass=' OR 1=1-- HTTP/1.1"
        "POST /search.php?q=<script>alert('XSS')</script> HTTP/1.1"
        "GET /../../etc/passwd HTTP/1.1"
        "POST /upload.php?file=../../../shell.php HTTP/1.1"
        "GET /wp-admin/admin-ajax.php?action=revslider_show_image&img=../wp-config.php HTTP/1.1"
    )
    
    for attack in "${WEB_ATTACKS[@]}"; do
        FAKE_IP="10.0.0.$((RANDOM % 255))"
        echo "$(date) $FAKE_IP - - [$(date '+%d/%b/%Y:%H:%M:%S %z')] \"$attack\" 404 -" >> /var/log/apache2/access.log
        sleep 1
    done
}

# Function to simulate privilege escalation attempts
simulate_privilege_escalation() {
    echo "[+] Simulating privilege escalation attempts..."
    
    PRIV_ESC_COMMANDS=(
        "sudo -l"
        "su - root"
        "sudo /bin/bash"
        "sudo cat /etc/shadow"
        "sudo chmod 777 /etc/passwd"
    )
    
    for cmd in "${PRIV_ESC_COMMANDS[@]}"; do
        FAKE_USER="user$((RANDOM % 10))"
        echo "$(date) audit[$$]: USER_CMD pid=$$ uid=1000 auid=1000 ses=1 msg='cwd=\"/home/$FAKE_USER\" cmd=\"$cmd\" terminal=pts/0 res=failed'" >> /var/log/audit/audit.log
        sleep 2
    done
}

# Function to simulate malware-like behavior
simulate_malware_activity() {
    echo "[+] Simulating suspicious file activity..."
    
    # Create temporary suspicious files
    mkdir -p /tmp/nosleep-test
    echo "#!/bin/bash" > /tmp/nosleep-test/suspicious.sh
    echo "nc -l -p 4444 -e /bin/bash" >> /tmp/nosleep-test/suspicious.sh
    
    # Log the activity
    echo "$(date) kernel: [$$] audit: type=1300 audit($(date +%s).000:123): arch=c000003e syscall=2 success=yes exit=3 a0=7fff12345678 a1=241 a2=1b6 a3=0 items=2 ppid=1234 pid=$$ auid=1000 uid=0 gid=0 euid=0 suid=0 fsuid=0 egid=0 sgid=0 fsgid=0 tty=pts0 ses=1 comm=\"suspicious.sh\" exe=\"/bin/bash\"" >> /var/log/audit/audit.log
    
    # Clean up
    rm -rf /tmp/nosleep-test
}

# Main execution
case "$1" in
    "ssh")
        simulate_ssh_bruteforce
        ;;
    "web")
        simulate_web_attacks
        ;;
    "privesc")
        simulate_privilege_escalation
        ;;
    "malware")
        simulate_malware_activity
        ;;
    "all")
        simulate_ssh_bruteforce
        simulate_web_attacks
        simulate_privilege_escalation
        simulate_malware_activity
        ;;
    *)
        echo "Usage: $0 {ssh|web|privesc|malware|all}"
        echo ""
        echo "Attack types:"
        echo "  ssh     - SSH brute force attacks"
        echo "  web     - Web application attacks (SQLi, XSS, LFI)"
        echo "  privesc - Privilege escalation attempts"
        echo "  malware - Suspicious file/process activity"
        echo "  all     - Run all attack simulations"
        exit 1
        ;;
esac

echo "[+] Attack simulation complete!" 