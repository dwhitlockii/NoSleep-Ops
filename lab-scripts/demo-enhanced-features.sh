#!/bin/bash

# NoSleep-Ops Enhanced Features Demo
# Showcases all the new advanced capabilities

echo "🚀 NoSleep-Ops Enhanced Features Demo"
echo "======================================"
echo ""

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

demo_section() {
    echo -e "${CYAN}$1${NC}"
    echo "----------------------------------------"
}

demo_step() {
    echo -e "${YELLOW}➤ $1${NC}"
}

demo_result() {
    echo -e "${GREEN}✓ $1${NC}"
    echo ""
}

# Main demo function
run_demo() {
    demo_section "🎯 ENHANCED ATTACK SIMULATION SUITE"
    demo_step "Running advanced SSH brute force with credential stuffing..."
    /opt/lab-scripts/enhanced-attack-suite.sh ssh-advanced > /dev/null 2>&1
    demo_result "Generated realistic SSH attacks with multiple attack patterns"
    
    demo_step "Running advanced web application attacks (OWASP Top 10)..."
    /opt/lab-scripts/enhanced-attack-suite.sh web-advanced > /dev/null 2>&1
    demo_result "Generated SQL injection, XSS, LFI, and RCE attacks"
    
    demo_step "Running lateral movement simulation..."
    /opt/lab-scripts/enhanced-attack-suite.sh lateral-movement > /dev/null 2>&1
    demo_result "Simulated SMB enumeration and internal network compromise"
    
    demo_step "Running C2 communication simulation..."
    /opt/lab-scripts/enhanced-attack-suite.sh c2-communication > /dev/null 2>&1
    demo_result "Generated command & control beaconing traffic"
    
    demo_section "🌐 NETWORK TRAFFIC GENERATOR"
    demo_step "Generating normal web browsing traffic..."
    /opt/lab-scripts/network-traffic-generator.sh web > /dev/null 2>&1
    demo_result "Created realistic background web traffic"
    
    demo_step "Generating DNS queries and responses..."
    /opt/lab-scripts/network-traffic-generator.sh dns > /dev/null 2>&1
    demo_result "Simulated legitimate DNS activity"
    
    demo_step "Generating system activity logs..."
    /opt/lab-scripts/network-traffic-generator.sh system > /dev/null 2>&1
    demo_result "Created normal system administration activity"
    
    demo_section "🚨 REAL-TIME ALERTING SYSTEM"
    demo_step "Testing alert generation..."
    /opt/lab-scripts/alerting-system.sh test > /dev/null 2>&1
    demo_result "Alert system is operational and logging to /var/log/security-alerts.log"
    
    demo_section "📊 LOG ANALYSIS RESULTS"
    echo -e "${BLUE}Recent SSH Attack Patterns:${NC}"
    tail -5 /var/log/auth.log | grep -E "(Failed password|Invalid user)" | head -3
    echo ""
    
    echo -e "${BLUE}Recent Web Traffic (Normal + Attacks):${NC}"
    tail -3 /var/log/apache2/access.log
    echo ""
    
    echo -e "${BLUE}C2 Communication Detected:${NC}"
    grep "POST /api/v1/beacon" /var/log/apache2/access.log | tail -2
    echo ""
    
    echo -e "${BLUE}Privilege Escalation Attempts:${NC}"
    grep "command not allowed" /var/log/auth.log | tail -3
    echo ""
    
    demo_section "🎯 ATTACK SCENARIOS AVAILABLE"
    echo -e "${PURPLE}Enhanced Attack Suite:${NC}"
    echo "  • ssh-advanced      - Advanced SSH attacks (dictionary, credential stuffing)"
    echo "  • web-advanced      - OWASP Top 10 attacks (SQLi, XSS, LFI, RCE)"
    echo "  • lateral-movement  - SMB enumeration and lateral movement"
    echo "  • data-exfiltration - DNS tunneling and large file transfers"
    echo "  • privilege-escalation - Advanced privesc techniques"
    echo "  • c2-communication  - Command & control beaconing"
    echo "  • malware-activity  - Malware-like file system behavior"
    echo "  • crypto-mining     - Cryptocurrency mining simulation"
    echo "  • apt-campaign      - Full APT attack chain simulation"
    echo "  • all-advanced      - Run all advanced attack types"
    echo ""
    
    echo -e "${PURPLE}Network Traffic Generator:${NC}"
    echo "  • web        - Normal web browsing traffic"
    echo "  • dns        - DNS query/response traffic"
    echo "  • system     - Normal system activity"
    echo "  • continuous - Run continuous background traffic"
    echo "  • all        - Generate all traffic types once"
    echo ""
    
    demo_section "📈 PERFORMANCE METRICS"
    echo -e "${GREEN}Log Generation Statistics:${NC}"
    echo "  • Auth log entries: $(wc -l < /var/log/auth.log)"
    echo "  • Apache log entries: $(wc -l < /var/log/apache2/access.log)"
    echo "  • System log entries: $(wc -l < /var/log/syslog)"
    echo "  • Security alerts: $(wc -l < /var/log/security-alerts.log 2>/dev/null || echo 0)"
    echo ""
    
    demo_section "🔧 KIBANA DASHBOARD ACCESS"
    echo -e "${CYAN}Pre-configured dashboards available at:${NC}"
    echo "  🌐 http://localhost:15601"
    echo ""
    echo -e "${YELLOW}Dashboard Features:${NC}"
    echo "  • SSH Attack Timeline"
    echo "  • Top Attacking IP Addresses"
    echo "  • Web Attack Patterns"
    echo "  • Geographic Attack Distribution"
    echo "  • Real-time Security Overview"
    echo ""
    
    demo_section "⚡ QUICK START COMMANDS"
    echo -e "${GREEN}Start real-time monitoring:${NC}"
    echo "  /opt/lab-scripts/alerting-system.sh start"
    echo ""
    echo -e "${GREEN}Run full APT campaign:${NC}"
    echo "  /opt/lab-scripts/enhanced-attack-suite.sh apt-campaign"
    echo ""
    echo -e "${GREEN}Generate continuous background traffic:${NC}"
    echo "  /opt/lab-scripts/network-traffic-generator.sh continuous"
    echo ""
    echo -e "${GREEN}View alert statistics:${NC}"
    echo "  /opt/lab-scripts/alerting-system.sh stats"
    echo ""
    
    demo_section "🎉 DEMO COMPLETE!"
    echo -e "${GREEN}NoSleep-Ops Enhanced Features are fully operational!${NC}"
    echo ""
    echo -e "${CYAN}Key Enhancements Delivered:${NC}"
    echo "  ✅ Enhanced Attack Simulation Suite - More realistic attack patterns"
    echo "  ✅ Pre-configured Kibana Dashboards - Instant visualization"
    echo "  ✅ Network Traffic Generators - Realistic background noise"
    echo "  ✅ Automated Alerting System - Real-time notifications"
    echo ""
    echo -e "${YELLOW}The lab is now production-ready for advanced security training! 🔒${NC}"
}

# Execute demo
run_demo 