#!/usr/bin/env python3
"""
NoSleep-Ops ML Analytics Demo
Demonstrates AI-powered security analytics capabilities
"""

import sys
import os
import time
from datetime import datetime, timedelta

# Add the ML analytics path
sys.path.append('ml_analytics')

try:
    from ml_analytics.behavioral_analyzer import BehavioralAnalyzer
    from ml_analytics.threat_predictor import ThreatPredictor
    from ml_analytics.forensics_engine import ForensicsEngine
    print("✅ Successfully imported ML analytics modules")
except ImportError as e:
    print(f"❌ Import error: {e}")
    print("Installing required dependencies...")
    os.system("pip install scikit-learn numpy pandas")
    try:
        from ml_analytics.behavioral_analyzer import BehavioralAnalyzer
        from ml_analytics.threat_predictor import ThreatPredictor
        from ml_analytics.forensics_engine import ForensicsEngine
        print("✅ Successfully imported ML analytics modules after installation")
    except ImportError as e2:
        print(f"❌ Still failing after installation: {e2}")
        sys.exit(1)

def generate_demo_attacks():
    """Generate realistic attack data for demonstration"""
    demo_attacks = [
        {
            'timestamp': datetime.now() - timedelta(minutes=30),
            'source_ip': '192.168.1.100',
            'attack_type': 'SSH_BRUTE_FORCE',
            'target': 'SSH_SERVICE',
            'details': 'Failed password for root from 192.168.1.100 port 22',
            'severity': 'HIGH',
            'port': 22,
            'message': 'Failed password for root'
        },
        {
            'timestamp': datetime.now() - timedelta(minutes=25),
            'source_ip': '192.168.1.100',
            'attack_type': 'LATERAL_MOVEMENT',
            'target': 'NETWORK',
            'details': 'Suspicious network scanning activity',
            'severity': 'HIGH',
            'port': 445,
            'message': 'SMB enumeration attempt'
        },
        {
            'timestamp': datetime.now() - timedelta(minutes=20),
            'source_ip': '10.0.0.50',
            'attack_type': 'SQL_INJECTION',
            'target': 'WEB_SERVICE',
            'details': 'union select * from users',
            'severity': 'HIGH',
            'port': 80,
            'message': 'union select * from users'
        },
        {
            'timestamp': datetime.now() - timedelta(minutes=15),
            'source_ip': '10.0.0.50',
            'attack_type': 'XSS_ATTEMPT',
            'target': 'WEB_SERVICE',
            'details': '<script>alert("xss")</script>',
            'severity': 'MEDIUM',
            'port': 80,
            'message': '<script>alert("xss")</script>'
        },
        {
            'timestamp': datetime.now() - timedelta(minutes=10),
            'source_ip': '203.0.113.50',
            'attack_type': 'DIRECTORY_TRAVERSAL',
            'target': 'WEB_SERVICE',
            'details': '../../../etc/passwd',
            'severity': 'HIGH',
            'port': 80,
            'message': '../../../etc/passwd'
        },
        {
            'timestamp': datetime.now() - timedelta(minutes=5),
            'source_ip': '192.168.1.100',
            'attack_type': 'PRIVILEGE_ESCALATION',
            'target': 'SYSTEM',
            'details': 'sudo privilege escalation attempt',
            'severity': 'CRITICAL',
            'port': 22,
            'message': 'sudo privilege escalation attempt'
        },
        {
            'timestamp': datetime.now() - timedelta(minutes=2),
            'source_ip': '192.168.1.100',
            'attack_type': 'DATA_EXFILTRATION',
            'target': 'FILE_SYSTEM',
            'details': 'Large file transfer detected',
            'severity': 'CRITICAL',
            'port': 22,
            'message': 'Large file transfer detected'
        }
    ]
    return demo_attacks

def demo_behavioral_analysis(analyzer, attacks):
    """Demonstrate behavioral analysis capabilities"""
    print("\n" + "="*60)
    print("🧠 BEHAVIORAL ANALYSIS DEMONSTRATION")
    print("="*60)
    
    # Feed attack data to analyzer
    for attack in attacks:
        analyzer.update_profile(attack)
    
    # Analyze behavior for each unique IP
    unique_ips = list(set(attack['source_ip'] for attack in attacks))
    
    for ip in unique_ips:
        print(f"\n📊 Behavioral Analysis for {ip}:")
        print("-" * 40)
        
        analysis = analyzer.analyze_behavior(ip)
        
        if analysis['status'] == 'analyzed':
            print(f"🎯 Risk Level: {analysis['risk_level']}")
            print(f"📈 Behavioral Score: {analysis['behavioral_score']}/100")
            print(f"🔢 Total Requests: {analysis['total_requests']}")
            print(f"⚠️  Anomalies Detected: {', '.join(analysis['anomalies']) if analysis['anomalies'] else 'None'}")
            
            # Show pattern analysis
            patterns = analysis['patterns']
            if 'timing' in patterns:
                timing = patterns['timing']
                if timing['is_anomalous']:
                    print(f"⏱️  Timing Pattern: {'Automated' if timing.get('is_automated') else 'Burst'} attack pattern detected")
            
            if 'attacks' in patterns:
                attack_pattern = patterns['attacks']
                if attack_pattern['is_anomalous']:
                    print(f"🎯 Attack Pattern: {attack_pattern['primary_attack_type']} (Multi-vector: {attack_pattern['is_multi_vector']})")
        else:
            print(f"ℹ️  Status: {analysis['status']}")
    
    # Show summary
    summary = analyzer.get_behavioral_summary()
    print(f"\n📋 BEHAVIORAL SUMMARY:")
    print(f"   • Total Events Processed: {summary['total_events_processed']}")
    print(f"   • Active IP Profiles: {summary['active_ip_profiles']}")
    print(f"   • Profiles with Baseline: {summary['profiles_with_baseline']}")
    print(f"   • Risk Distribution: {summary['recent_risk_distribution']}")

def demo_threat_prediction(predictor, attacks):
    """Demonstrate threat prediction capabilities"""
    print("\n" + "="*60)
    print("🔮 THREAT PREDICTION DEMONSTRATION")
    print("="*60)
    
    # Feed attack data to predictor
    for attack in attacks:
        predictor.update_threat_data(attack)
    
    # Global threat predictions
    print("\n🌍 Global Threat Landscape:")
    print("-" * 30)
    
    global_prediction = predictor.predict_threats()
    if global_prediction['status'] == 'predicted':
        print(f"🚨 Global Risk Level: {global_prediction['global_risk_level']}")
        print(f"📊 Recent Attacks: {global_prediction['total_recent_attacks']}")
        print(f"🎯 Attack Distribution: {global_prediction['attack_distribution']}")
        
        if global_prediction['emerging_threats']:
            print("\n⚡ Emerging Threats:")
            for threat in global_prediction['emerging_threats'][:3]:
                print(f"   • {threat['attack_type']}: {threat['frequency']} occurrences ({threat['severity']})")
    
    # IP-specific predictions
    unique_ips = list(set(attack['source_ip'] for attack in attacks))
    
    for ip in unique_ips:
        print(f"\n🎯 Threat Prediction for {ip}:")
        print("-" * 40)
        
        prediction = predictor.predict_threats(ip)
        
        if prediction['status'] == 'predicted':
            print(f"⚠️  Threat Level: {prediction['threat_level']}")
            print(f"📈 Current Risk Score: {prediction['current_risk_score']}/100")
            print(f"🎲 Prediction Confidence: {prediction['prediction_confidence']:.2f}")
            
            if prediction['predicted_attacks']:
                print("🔮 Predicted Next Attacks:")
                for pred_attack in prediction['predicted_attacks'][:2]:
                    print(f"   • {pred_attack['attack_type']} (Confidence: {pred_attack['confidence']:.2f})")
                    print(f"     Trigger: {pred_attack['trigger']}, Severity: {pred_attack['severity']}")
        else:
            print(f"ℹ️  Status: {prediction['status']}")
    
    # High-risk IPs
    high_risk = predictor.get_high_risk_ips(5)
    if high_risk:
        print("\n🚨 TOP HIGH-RISK IP ADDRESSES:")
        print("-" * 35)
        for risk_ip in high_risk:
            print(f"   • {risk_ip['ip']}: Risk Score {risk_ip['risk_score']}/100 ({risk_ip['threat_level']})")
            print(f"     Recent Attacks: {', '.join(risk_ip['recent_attacks'][-3:])}")

def demo_forensics_analysis(forensics, attacks):
    """Demonstrate forensics and incident reconstruction"""
    print("\n" + "="*60)
    print("🔍 FORENSICS & INCIDENT RECONSTRUCTION")
    print("="*60)
    
    # Collect evidence
    for attack in attacks:
        forensics.collect_evidence(attack)
    
    # Incident reconstruction for each IP
    unique_ips = list(set(attack['source_ip'] for attack in attacks))
    
    for ip in unique_ips:
        print(f"\n🕵️ Incident Reconstruction for {ip}:")
        print("-" * 45)
        
        reconstruction = forensics.reconstruct_incident(ip, 24)
        
        if reconstruction['status'] == 'reconstructed':
            print(f"📅 Time Window: {reconstruction['time_window']}")
            print(f"📊 Total Events: {reconstruction['total_events']}")
            
            # Attack progression
            progression = reconstruction['attack_progression']
            print(f"🔗 Attack Chain: {' → '.join(progression)}")
            
            # Pattern analysis
            pattern = reconstruction['pattern_analysis']
            print(f"🎭 Pattern Type: {pattern['pattern_type'].upper()}")
            print(f"⚠️  Severity: {pattern['severity']}")
            print(f"📝 Description: {pattern['description']}")
            
            if pattern['pattern_type'] == 'apt_campaign':
                print(f"🎯 APT Stages: {', '.join(pattern['stages'])}")
            elif pattern['pattern_type'] == 'automated_attack':
                print(f"🤖 Indicators: {', '.join(pattern['indicators'])}")
        else:
            print(f"ℹ️  Status: {reconstruction['status']}")
    
    # Forensics report
    report = forensics.generate_forensics_report()
    print(f"\n📋 FORENSICS SUMMARY REPORT:")
    print("-" * 30)
    print(f"   • Total Evidence Items: {report['evidence_summary']['total_evidence_items']}")
    print(f"   • Unique Source IPs: {report['evidence_summary']['unique_source_ips']}")
    print(f"   • Attack Distribution: {report['evidence_summary']['attack_type_distribution']}")
    print(f"   • Severity Distribution: {report['evidence_summary']['severity_distribution']}")
    
    if report['top_attacking_ips']:
        print("\n🎯 Top Attacking IPs:")
        for attacker in report['top_attacking_ips'][:3]:
            print(f"   • {attacker['ip']}: {attacker['attack_count']} attacks")

def main():
    """Main demonstration function"""
    print("🚀 NoSleep-Ops ML Analytics Demo")
    print("="*60)
    print("🤖 Initializing AI-Powered Security Analytics...")
    
    # Initialize ML engines
    try:
        behavioral_analyzer = BehavioralAnalyzer()
        threat_predictor = ThreatPredictor()
        forensics_engine = ForensicsEngine()
        print("✅ ML Analytics engines initialized successfully")
    except Exception as e:
        print(f"❌ Failed to initialize ML engines: {e}")
        return
    
    # Generate demo attack data
    print("🎯 Generating realistic attack scenarios...")
    demo_attacks = generate_demo_attacks()
    print(f"✅ Generated {len(demo_attacks)} attack events")
    
    # Run demonstrations
    try:
        demo_behavioral_analysis(behavioral_analyzer, demo_attacks)
        demo_threat_prediction(threat_predictor, demo_attacks)
        demo_forensics_analysis(forensics_engine, demo_attacks)
        
        print("\n" + "="*60)
        print("🎉 ML ANALYTICS DEMONSTRATION COMPLETE")
        print("="*60)
        print("🔬 Advanced Features Demonstrated:")
        print("   ✅ Behavioral Pattern Analysis")
        print("   ✅ Threat Prediction & Risk Scoring")
        print("   ✅ Automated Incident Reconstruction")
        print("   ✅ APT Campaign Detection")
        print("   ✅ Forensics Evidence Collection")
        print("\n💡 This showcases enterprise-grade AI security capabilities!")
        
    except Exception as e:
        print(f"❌ Demo error: {e}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    main() 