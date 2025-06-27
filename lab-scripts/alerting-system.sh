#!/bin/bash

# NoSleep-Ops Real-time Alerting System
# Monitors logs for security events and sends alerts

echo "[+] NoSleep-Ops Alerting System v1.0"
echo "===================================="

# Configuration
LOG_DIR="/var/log"
AUTH_LOG="$LOG_DIR/auth.log"
APACHE_LOG="$LOG_DIR/apache2/access.log"
SYSLOG="$LOG_DIR/syslog"
ALERT_LOG="$LOG_DIR/security-alerts.log"

# Alert thresholds
SSH_FAIL_THRESHOLD=5
WEB_ATTACK_THRESHOLD=3

# Create alert log
touch $ALERT_LOG

# Alert functions
send_alert() {
    local severity="$1"
    local event_type="$2"
    local message="$3"
    local source_ip="$4"
    
    local timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    local alert_id="ALERT-$(date +%s)-$RANDOM"
    
    # Format alert message
    local alert_msg="[$timestamp] [$severity] [$alert_id] $event_type: $message (Source: $source_ip)"
    
    # Log to alert file
    echo "$alert_msg" >> $ALERT_LOG
    
    # Display alert with colors
    case $severity in
        "CRITICAL")
            echo -e "\033[1;31m🚨 CRITICAL ALERT: $alert_msg\033[0m"
            ;;
        "HIGH")
            echo -e "\033[1;33m⚠️  HIGH ALERT: $alert_msg\033[0m"
            ;;
        "MEDIUM")
            echo -e "\033[1;34mℹ️  MEDIUM ALERT: $alert_msg\033[0m"
            ;;
    esac
}

# SSH Brute Force Detection
monitor_ssh_attacks() {
    echo "[+] Monitoring SSH brute force attacks..."
    
    tail -F $AUTH_LOG 2>/dev/null | while read line; do
        if echo "$line" | grep -q "Failed password"; then
            # Extract IP address
            source_ip=$(echo "$line" | grep -oE '[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+' | head -1)
            
            if [ -n "$source_ip" ]; then
                # Count recent failures from this IP
                recent_failures=$(grep "Failed password.*$source_ip" $AUTH_LOG | tail -20 | wc -l)
                
                if [ "$recent_failures" -ge "$SSH_FAIL_THRESHOLD" ]; then
                    send_alert "HIGH" "SSH_BRUTE_FORCE" \
                        "Multiple failed SSH login attempts detected ($recent_failures attempts)" \
                        "$source_ip"
                fi
            fi
        fi
    done &
}

# Web Attack Detection
monitor_web_attacks() {
    echo "[+] Monitoring web application attacks..."
    
    tail -F $APACHE_LOG 2>/dev/null | while read line; do
        source_ip=$(echo "$line" | awk '{print $1}')
        
        # SQL Injection detection
        if echo "$line" | grep -qiE "(union|select|drop|or 1=1|' or ')"; then
            send_alert "HIGH" "SQL_INJECTION" \
                "SQL injection attempt detected" \
                "$source_ip"
        fi
        
        # XSS detection
        if echo "$line" | grep -qiE "(<script|javascript:|alert\()"; then
            send_alert "HIGH" "XSS_ATTEMPT" \
                "Cross-site scripting attempt detected" \
                "$source_ip"
        fi
        
        # Directory traversal
        if echo "$line" | grep -qE "(\.\.\/|etc\/passwd)"; then
            send_alert "HIGH" "DIRECTORY_TRAVERSAL" \
                "Directory traversal attempt detected" \
                "$source_ip"
        fi
    done &
}

# System Activity Monitoring
monitor_system_activity() {
    echo "[+] Monitoring system activity..."
    
    tail -F $SYSLOG 2>/dev/null | while read line; do
        # Cryptocurrency mining detection
        if echo "$line" | grep -qE "(xmrig|mining|CPU usage spike)"; then
            send_alert "CRITICAL" "CRYPTOCURRENCY_MINING" \
                "Cryptocurrency mining activity detected" \
                "localhost"
        fi
        
        # Suspicious connections
        if echo "$line" | grep -q "TCP connection established.*evil\.com"; then
            source_ip=$(echo "$line" | grep -oE '[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+' | head -1)
            send_alert "CRITICAL" "MALICIOUS_CONNECTION" \
                "Connection to suspicious domain detected" \
                "$source_ip"
        fi
    done &
}

# Main monitoring function
start_monitoring() {
    echo "[+] Starting comprehensive security monitoring..."
    echo "[+] Alert log: $ALERT_LOG"
    echo "[+] Press Ctrl+C to stop monitoring"
    echo "=============================================="
    
    # Start all monitoring functions
    monitor_ssh_attacks
    monitor_web_attacks
    monitor_system_activity
    
    # Keep the script running
    wait
}

# Alert statistics
show_alert_stats() {
    echo "[+] Security Alert Statistics"
    echo "============================="
    
    if [ -f "$ALERT_LOG" ]; then
        echo "Total alerts: $(wc -l < $ALERT_LOG)"
        echo ""
        echo "Alert severity breakdown:"
        grep -o '\[CRITICAL\]' $ALERT_LOG | wc -l | xargs echo "CRITICAL:"
        grep -o '\[HIGH\]' $ALERT_LOG | wc -l | xargs echo "HIGH:"
        grep -o '\[MEDIUM\]' $ALERT_LOG | wc -l | xargs echo "MEDIUM:"
        echo ""
        echo "Recent alerts (last 5):"
        tail -5 $ALERT_LOG
    else
        echo "No alerts found."
    fi
}

# Test alert function
test_alert() {
    echo "[+] Testing alert system..."
    send_alert "HIGH" "TEST_ALERT" "This is a test alert" "127.0.0.1"
    echo "[+] Test alert sent. Check $ALERT_LOG"
}

# Main execution
case "$1" in
    "start")
        start_monitoring
        ;;
    "stats")
        show_alert_stats
        ;;
    "test")
        test_alert
        ;;
    *)
        echo "NoSleep-Ops Alerting System"
        echo "Usage: $0 {start|stats|test}"
        echo ""
        echo "Commands:"
        echo "  start  - Start real-time security monitoring"
        echo "  stats  - Show alert statistics"
        echo "  test   - Send a test alert"
        exit 1
        ;;
esac 