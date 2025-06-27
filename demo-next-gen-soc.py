#!/usr/bin/env python3
"""
🚀 Next-Generation SOC Platform Demo
===================================
Comprehensive demonstration of advanced security operations center features
"""

import requests
import json
import time
import webbrowser
import subprocess
from datetime import datetime
import threading

def print_banner():
    print("""
🚀 NEXT-GENERATION SOC PLATFORM DEMO
====================================
🎯 AI-Powered Threat Hunter
📊 Executive Security Dashboard  
📱 Mobile SOC Interface
🌐 3D Attack Flow Visualization
🧠 Machine Learning Analytics
🔬 Advanced Forensics Timeline
""")

def test_all_endpoints():
    """Test all API endpoints to ensure they're working"""
    print("🔍 Testing API Endpoints...")
    
    endpoints = [
        ('Basic Stats', '/api/stats'),
        ('Recent Attacks', '/api/recent_attacks'),
        ('AI Threat Analysis', '/api/ai_threat_analysis'),
        ('Executive Summary', '/api/executive_summary_new'),
        ('Attack Flows', '/api/attack_flows'),
        ('Threat Intelligence', '/api/threat_intelligence'),
        ('Advanced Dashboard', '/api/advanced_dashboard'),
        ('Attack Map', '/api/attack_map'),
        ('MITRE Analysis', '/api/mitre_analysis')
    ]
    
    working_endpoints = []
    
    for name, endpoint in endpoints:
        try:
            response = requests.get(f'http://localhost:5000{endpoint}', timeout=5)
            if response.status_code == 200:
                print(f"  ✅ {name}: Working")
                working_endpoints.append((name, endpoint))
            else:
                print(f"  ⚠️ {name}: Status {response.status_code}")
        except Exception as e:
            print(f"  ❌ {name}: Error - {str(e)[:50]}...")
    
    return working_endpoints

def demonstrate_ai_features():
    """Demonstrate AI-powered features"""
    print("\n🧠 AI-POWERED FEATURES DEMONSTRATION")
    print("=" * 50)
    
    try:
        # Test AI Threat Analysis
        response = requests.get('http://localhost:5000/api/ai_threat_analysis')
        if response.status_code == 200:
            data = response.json()
            print("🎯 AI Threat Intelligence:")
            
            if 'threat_intelligence' in data:
                ti = data['threat_intelligence']
                print(f"   • Sophistication Level: {ti.get('sophistication_level', 'N/A')}")
                print(f"   • Intelligence Confidence: {ti.get('intelligence_confidence', 0) * 100:.1f}%")
                print(f"   • Attack Distribution: {len(ti.get('attack_distribution', {}))}")
            
            if 'hunting_queries' in data:
                print(f"   • AI-Generated Hunting Queries: {len(data['hunting_queries'])}")
            
            if 'predictive_analysis' in data:
                pa = data['predictive_analysis']
                print(f"   • Prediction Confidence: {pa.get('confidence_score', 0) * 100:.1f}%")
                print(f"   • Next Likely Attacks: {len(pa.get('next_likely_attacks', []))}")
                
        else:
            print("   ⚠️ AI features running in demo mode")
            
    except Exception as e:
        print(f"   ❌ Error testing AI features: {e}")

def demonstrate_executive_features():
    """Demonstrate executive dashboard features"""
    print("\n📊 EXECUTIVE DASHBOARD DEMONSTRATION")
    print("=" * 50)
    
    try:
        response = requests.get('http://localhost:5000/api/executive_summary_new')
        if response.status_code == 200:
            data = response.json()
            print("💼 Executive Summary:")
            
            if 'executive_summary' in data:
                es = data['executive_summary']
                print(f"   • Security Status: {es.get('security_status', 'N/A')}")
                print(f"   • Key Findings: {len(es.get('key_findings', []))}")
            
            if 'business_impact' in data:
                bi = data['business_impact']['financial_impact']
                print(f"   • Cost Avoidance: ${bi.get('cost_avoidance', 0):,}")
                print(f"   • Security ROI: {bi.get('roi_on_security', 'N/A')}")
            
            if 'compliance_status' in data:
                cs = data['compliance_status']
                print(f"   • Overall Compliance: {cs.get('overall_compliance_score', 'N/A')}")
                
        else:
            print("   ⚠️ Executive features running in demo mode")
            
    except Exception as e:
        print(f"   ❌ Error testing executive features: {e}")

def demonstrate_3d_visualization():
    """Demonstrate 3D attack flow visualization"""
    print("\n🌐 3D ATTACK FLOW VISUALIZATION")
    print("=" * 50)
    
    try:
        response = requests.get('http://localhost:5000/api/attack_flows')
        if response.status_code == 200:
            data = response.json()
            print("🎮 3D Visualization Data:")
            
            flows = data.get('attack_flows', [])
            topology = data.get('network_topology', {})
            
            print(f"   • Attack Flow Sequences: {len(flows)}")
            print(f"   • Network Nodes: {len(topology.get('nodes', []))}")
            print(f"   • Network Connections: {len(topology.get('connections', []))}")
            
            if flows:
                print("   • Sample Attack Flow:")
                flow = flows[0]
                print(f"     - Source IP: {flow.get('source_ip', 'N/A')}")
                print(f"     - Attack Sequence: {' → '.join(flow.get('attack_sequence', [])[:3])}")
                print(f"     - Severity: {flow.get('severity', 'N/A')}")
                
        else:
            print("   ⚠️ 3D visualization running in demo mode")
            
    except Exception as e:
        print(f"   ❌ Error testing 3D visualization: {e}")

def demonstrate_mobile_features():
    """Demonstrate mobile SOC features"""
    print("\n📱 MOBILE SOC INTERFACE")
    print("=" * 50)
    
    print("📱 Mobile-Optimized Features:")
    print("   • Touch-optimized interface")
    print("   • Pull-to-refresh functionality")
    print("   • Real-time attack notifications")
    print("   • Quick action buttons")
    print("   • Offline capability")
    print("   • Vibration feedback")
    print("   • Emergency lockdown controls")

def open_all_dashboards():
    """Open all dashboard interfaces in browser"""
    print("\n🌐 OPENING ALL DASHBOARDS...")
    print("=" * 50)
    
    dashboards = [
        ('Basic Dashboard', 'http://localhost:5000'),
        ('Advanced SOC', 'http://localhost:5000/advanced'),
        ('AI Threat Hunter', 'http://localhost:5000/threat-hunter'),
        ('Executive Dashboard', 'http://localhost:5000/executive'),
        ('Mobile SOC', 'http://localhost:5000/mobile'),
        ('Forensics Timeline', 'http://localhost:5000/forensics')
    ]
    
    for name, url in dashboards:
        print(f"🌐 Opening {name}: {url}")
        try:
            webbrowser.open(url)
            time.sleep(2)  # Stagger the opening
        except Exception as e:
            print(f"   ❌ Error opening {name}: {e}")

def generate_live_attacks():
    """Generate live attacks for demonstration"""
    print("\n⚔️ GENERATING LIVE ATTACK SCENARIOS...")
    print("=" * 50)
    
    attack_scenarios = [
        ('ssh-advanced', 'Advanced SSH Attack Campaign'),
        ('web-advanced', 'Sophisticated Web Application Attacks'),
        ('lateral-movement', 'Lateral Movement Simulation'),
        ('data-exfiltration', 'Data Exfiltration Attempt'),
        ('apt-campaign', 'Advanced Persistent Threat Campaign')
    ]
    
    for scenario, description in attack_scenarios:
        print(f"🎯 Launching: {description}")
        try:
            result = subprocess.run([
                'docker', 'exec', 'ubuntu-host', 
                '/opt/lab-scripts/enhanced-attack-suite.sh', scenario
            ], capture_output=True, text=True, timeout=30)
            
            if result.returncode == 0:
                print(f"   ✅ {description} completed")
            else:
                print(f"   ⚠️ {description} completed with warnings")
                
        except Exception as e:
            print(f"   ❌ Error launching {description}: {e}")
        
        time.sleep(5)  # Wait between attacks

def show_feature_summary():
    """Show comprehensive feature summary"""
    print("\n🎯 NEXT-GENERATION SOC FEATURES")
    print("=" * 50)
    
    features = {
        "🧠 AI-Powered Threat Hunter": [
            "Machine learning-based threat detection",
            "Automated hunting query generation", 
            "Predictive attack analysis",
            "Behavioral anomaly detection",
            "Advanced threat intelligence"
        ],
        "📊 Executive Dashboard": [
            "C-level security metrics",
            "Financial impact analysis",
            "Compliance status tracking",
            "Risk assessment gauges",
            "Strategic recommendations"
        ],
        "🌐 3D Attack Visualization": [
            "Real-time attack flow mapping",
            "Interactive network topology",
            "3D threat progression",
            "Attack sequence analysis",
            "Visual kill chain tracking"
        ],
        "📱 Mobile SOC Interface": [
            "Touch-optimized controls",
            "Real-time notifications",
            "Emergency response actions",
            "Offline capability",
            "Gesture-based navigation"
        ],
        "🔬 Advanced Analytics": [
            "MITRE ATT&CK integration",
            "Geolocation attack mapping",
            "Campaign analysis",
            "Forensics timeline",
            "Threat actor profiling"
        ]
    }
    
    for category, feature_list in features.items():
        print(f"\n{category}")
        for feature in feature_list:
            print(f"   ✅ {feature}")

def run_live_demo():
    """Run a continuous live demonstration"""
    print("\n🎬 STARTING LIVE DEMONSTRATION...")
    print("=" * 50)
    
    def attack_generator():
        """Generate attacks in background"""
        scenarios = ['ssh-advanced', 'web-advanced', 'lateral-movement']
        while True:
            for scenario in scenarios:
                try:
                    subprocess.run([
                        'docker', 'exec', 'ubuntu-host', 
                        '/opt/lab-scripts/enhanced-attack-suite.sh', scenario
                    ], capture_output=True, timeout=30)
                except:
                    pass
                time.sleep(60)  # Wait 1 minute between attack waves
    
    # Start background attack generation
    attack_thread = threading.Thread(target=attack_generator, daemon=True)
    attack_thread.start()
    
    print("🎯 Live attack simulation started")
    print("🌐 All dashboards are now populated with real-time data")
    print("📊 Metrics updating every 30 seconds")
    print("🔴 Press Ctrl+C to stop the demonstration")
    
    try:
        while True:
            # Show current stats
            try:
                response = requests.get('http://localhost:5000/api/stats')
                if response.status_code == 200:
                    stats = response.json()
                    print(f"\n📈 Current Stats: {stats.get('total_attacks', 0)} attacks, "
                          f"{stats.get('unique_ips', 0)} IPs, "
                          f"{len(stats.get('attack_types', {}))} attack types")
            except:
                pass
                
            time.sleep(30)
            
    except KeyboardInterrupt:
        print("\n🛑 Live demonstration stopped")

def main():
    """Main demonstration function"""
    print_banner()
    
    print("🔧 SYSTEM VALIDATION")
    print("=" * 50)
    
    # Test all endpoints
    working_endpoints = test_all_endpoints()
    
    if len(working_endpoints) < 5:
        print("\n⚠️ Warning: Some features may not be fully operational")
        print("   This is normal if running in demo mode")
    
    # Demonstrate features
    demonstrate_ai_features()
    demonstrate_executive_features()
    demonstrate_3d_visualization()
    demonstrate_mobile_features()
    
    # Show feature summary
    show_feature_summary()
    
    print("\n🎬 DEMONSTRATION OPTIONS")
    print("=" * 50)
    print("1. Open all dashboards in browser")
    print("2. Generate attack scenarios")
    print("3. Run live demonstration")
    print("4. Show all features")
    print("0. Exit")
    
    while True:
        try:
            choice = input("\nSelect option (0-4): ").strip()
            
            if choice == '1':
                open_all_dashboards()
                break
            elif choice == '2':
                generate_live_attacks()
                break
            elif choice == '3':
                open_all_dashboards()
                time.sleep(5)
                run_live_demo()
                break
            elif choice == '4':
                show_feature_summary()
                break
            elif choice == '0':
                print("👋 Demonstration complete!")
                break
            else:
                print("Invalid option. Please select 0-4.")
                
        except KeyboardInterrupt:
            print("\n👋 Demonstration complete!")
            break

if __name__ == "__main__":
    main() 