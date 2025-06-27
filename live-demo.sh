#!/bin/bash

echo "🚀 NoSleep-Ops Live Attack Demonstration"
echo "========================================"
echo "🎯 Watch your dashboards at:"
echo "   • Basic Dashboard: http://localhost:5000"
echo "   • Advanced SOC: http://localhost:5000/advanced"
echo ""
echo "🔴 Starting continuous attack simulation..."
echo "   Press Ctrl+C to stop"
echo ""

# Function to show current stats
show_stats() {
    echo "📊 Current Attack Statistics:"
    curl -s http://localhost:5000/api/stats | python -m json.tool | grep -E "(total_attacks|unique_ips)" | head -2
    echo ""
}

# Continuous attack simulation
counter=1
while true; do
    echo "🎯 Attack Wave $counter - $(date)"
    
    # Rotate through different attack types
    case $((counter % 6)) in
        1)
            echo "   🔴 SSH Brute Force Campaign"
            docker exec ubuntu-host /opt/lab-scripts/enhanced-attack-suite.sh ssh-advanced
            ;;
        2)
            echo "   🌐 Web Application Attacks"
            docker exec ubuntu-host /opt/lab-scripts/enhanced-attack-suite.sh web-advanced
            ;;
        3)
            echo "   🔄 Lateral Movement Simulation"
            docker exec ubuntu-host /opt/lab-scripts/enhanced-attack-suite.sh lateral-movement
            ;;
        4)
            echo "   💾 Data Exfiltration Attempt"
            docker exec ubuntu-host /opt/lab-scripts/enhanced-attack-suite.sh data-exfiltration
            ;;
        5)
            echo "   📡 C2 Communication"
            docker exec ubuntu-host /opt/lab-scripts/enhanced-attack-suite.sh c2-communication
            ;;
        0)
            echo "   🎯 Full APT Campaign"
            docker exec ubuntu-host /opt/lab-scripts/enhanced-attack-suite.sh apt-campaign
            ;;
    esac
    
    # Show updated stats
    sleep 5
    show_stats
    
    echo "   ⏱️ Waiting 15 seconds before next wave..."
    echo "   📊 Check your web dashboard for real-time updates!"
    echo ""
    
    sleep 15
    counter=$((counter + 1))
done 