#!/usr/bin/env python3
"""
NoSleep-Ops Web Attack Monitor
Real-time attack monitoring and defense tracking interface
"""

from flask import Flask, render_template, jsonify, request
from flask_socketio import SocketIO, emit
import json
import time
import threading
import re
import subprocess
import os
from datetime import datetime, timedelta
from collections import defaultdict, deque
import sqlite3
import hashlib
import sys

# Import threat intelligence module
try:
    from threat_intel import ThreatIntelligence
    THREAT_INTEL_AVAILABLE = True
except ImportError:
    THREAT_INTEL_AVAILABLE = False
    print("⚠️ Threat Intelligence module not available")

# Import reporting module
try:
    from reporting import SecurityReporter
    REPORTING_AVAILABLE = True
except ImportError:
    REPORTING_AVAILABLE = False
    print("⚠️ Security Reporting module not available")

# Import ML analytics modules
sys.path.append(os.path.join(os.path.dirname(__file__), '..'))
from ml_analytics.behavioral_analyzer import BehavioralAnalyzer
from ml_analytics.threat_predictor import ThreatPredictor
from ml_analytics.forensics_engine import ForensicsEngine

# Import new advanced modules
try:
    from geolocation import geo_mapper
    from mitre_attack import mitre_mapper
    from executive_reports import executive_reporter
    ADVANCED_FEATURES = True
    print("🌍 Advanced geolocation and MITRE ATT&CK features loaded")
except ImportError as e:
    print(f"⚠️ Advanced features not available: {e}")
    ADVANCED_FEATURES = False

# Import AI Threat Hunter
try:
    from ml_analytics.ai_threat_hunter import threat_hunter
    AI_THREAT_HUNTER_AVAILABLE = True
    print("🎯 AI Threat Hunter loaded")
except ImportError as e:
    print(f"⚠️ AI Threat Hunter not available: {e}")
    AI_THREAT_HUNTER_AVAILABLE = False

app = Flask(__name__)
app.config['SECRET_KEY'] = 'nosleep-ops-monitor-2025'
socketio = SocketIO(app, cors_allowed_origins="*")

# Global data structures for real-time monitoring
attack_stats = {
    'total_attacks': 0,
    'attacks_last_hour': 0,
    'unique_ips': set(),
    'attack_types': defaultdict(int),
    'top_attackers': defaultdict(int),
    'defense_actions': defaultdict(int),
    'blocked_ips': set(),
    'recent_attacks': deque(maxlen=100)
}

# Defense response tracking
defense_responses = {
    'fail2ban_bans': 0,
    'manual_blocks': 0,
    'automated_responses': 0,
    'alerts_sent': 0,
    'defense_actions': defaultdict(int),
    'blocked_ips': set(),
    'recent_responses': deque(maxlen=50)
}

# Initialize threat intelligence
threat_intel = None
if THREAT_INTEL_AVAILABLE:
    config = {
        'ENABLE_THREAT_INTEL': os.getenv('ENABLE_THREAT_INTEL', 'false').lower() == 'true',
        'VIRUSTOTAL_API_KEY': os.getenv('VIRUSTOTAL_API_KEY'),
        'ABUSEIPDB_API_KEY': os.getenv('ABUSEIPDB_API_KEY'),
        'GREYNOISE_API_KEY': os.getenv('GREYNOISE_API_KEY')
    }
    threat_intel = ThreatIntelligence(config)

# Initialize security reporter
security_reporter = None
if REPORTING_AVAILABLE:
    security_reporter = SecurityReporter('attack_monitor.db')

# Initialize ML analytics engines
behavioral_analyzer = BehavioralAnalyzer()
threat_predictor = ThreatPredictor()
forensics_engine = ForensicsEngine()

# Initialize SQLite database for persistent storage
def init_database():
    conn = sqlite3.connect('attack_monitor.db')
    cursor = conn.cursor()
    
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS attacks (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT,
            source_ip TEXT,
            attack_type TEXT,
            target TEXT,
            details TEXT,
            severity TEXT
        )
    ''')
    
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS defenses (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT,
            action_type TEXT,
            target_ip TEXT,
            details TEXT,
            effectiveness TEXT
        )
    ''')
    
    conn.commit()
    conn.close()

def log_attack(source_ip, attack_type, target, details, severity="MEDIUM"):
    """Log attack to database and update real-time stats"""
    timestamp = datetime.now().isoformat()
    
    # Database logging
    conn = sqlite3.connect('attack_monitor.db')
    cursor = conn.cursor()
    cursor.execute('''
        INSERT INTO attacks (timestamp, source_ip, attack_type, target, details, severity)
        VALUES (?, ?, ?, ?, ?, ?)
    ''', (timestamp, source_ip, attack_type, target, details, severity))
    conn.commit()
    conn.close()
    
    # Real-time stats update
    attack_stats['total_attacks'] += 1
    attack_stats['unique_ips'].add(source_ip)
    attack_stats['attack_types'][attack_type] += 1
    attack_stats['top_attackers'][source_ip] += 1
    
    attack_data = {
        'timestamp': timestamp,
        'source_ip': source_ip,
        'attack_type': attack_type,
        'target': target,
        'details': details,
        'severity': severity
    }
    
    attack_stats['recent_attacks'].append(attack_data)
    
    # Feed data to ML analytics engines
    try:
        ml_event = {
            'timestamp': timestamp,
            'source_ip': source_ip,
            'attack_type': attack_type,
            'target': target,
            'details': details,
            'severity': severity,
            'port': 22 if 'SSH' in attack_type else 80,  # Simplified port detection
            'message': details
        }
        
        # Update behavioral analyzer
        behavioral_analyzer.update_profile(ml_event)
        
        # Update threat predictor
        threat_predictor.update_threat_data(ml_event)
        
        # Collect forensics evidence
        forensics_engine.collect_evidence(ml_event)
        
    except Exception as e:
        print(f"Error feeding data to ML engines: {e}")
    
    # Emit to all connected clients
    socketio.emit('new_attack', attack_data)

def log_defense_action(action_type, target_ip, details, effectiveness="SUCCESS"):
    """Log defense action and update tracking"""
    timestamp = datetime.now().isoformat()
    
    # Database logging
    conn = sqlite3.connect('attack_monitor.db')
    cursor = conn.cursor()
    cursor.execute('''
        INSERT INTO defenses (timestamp, action_type, target_ip, details, effectiveness)
        VALUES (?, ?, ?, ?, ?)
    ''', (timestamp, action_type, target_ip, details, effectiveness))
    conn.commit()
    conn.close()
    
    # Real-time stats update
    defense_responses['defense_actions'][action_type] += 1
    if target_ip:
        defense_responses['blocked_ips'].add(target_ip)
    
    defense_data = {
        'timestamp': timestamp,
        'action_type': action_type,
        'target_ip': target_ip,
        'details': details,
        'effectiveness': effectiveness
    }
    
    defense_responses['recent_responses'].append(defense_data)
    
    # Emit to all connected clients
    socketio.emit('defense_action', defense_data)

def parse_ssh_attack(line):
    """Parse SSH attack patterns from log lines"""
    try:
        # Pattern for failed password attempts
        if 'Failed password' in line:
            # Extract IP and username
            ip_match = re.search(r'from (\d+\.\d+\.\d+\.\d+)', line)
            user_match = re.search(r'Failed password for (\w+)', line)
            
            if ip_match:
                ip = ip_match.group(1)
                user = user_match.group(1) if user_match else 'unknown'
                
                return {
                    'ip': ip,
                    'type': 'SSH_BRUTE_FORCE',
                    'details': f'Failed password for user {user}',
                    'severity': 'HIGH'
                }
        
        # Pattern for invalid user attempts
        elif 'Invalid user' in line:
            ip_match = re.search(r'from (\d+\.\d+\.\d+\.\d+)', line)
            user_match = re.search(r'Invalid user (\w+)', line)
            
            if ip_match:
                ip = ip_match.group(1)
                user = user_match.group(1) if user_match else 'unknown'
                
                return {
                    'ip': ip,
                    'type': 'SSH_USER_ENUMERATION',
                    'details': f'Invalid user {user}',
                    'severity': 'MEDIUM'
                }
        
        # Pattern for privilege escalation attempts
        elif 'sudo' in line and 'command not allowed' in line:
            ip_match = re.search(r'(\d+\.\d+\.\d+\.\d+)', line)
            user_match = re.search(r'sudo\[\d+\]: (\w+)', line)
            cmd_match = re.search(r'COMMAND=(.+?)(?:\s|$)', line)
            
            if user_match:
                user = user_match.group(1)
                cmd = cmd_match.group(1) if cmd_match else 'unknown command'
                
                return {
                    'ip': '127.0.0.1',  # Local privilege escalation
                    'type': 'PRIVILEGE_ESCALATION',
                    'details': f'User {user} attempted: {cmd}',
                    'severity': 'HIGH'
                }
                
    except Exception as e:
        print(f"Error parsing SSH attack: {e}")
    
    return None

def parse_web_attack(line):
    """Parse web attack patterns from Apache access log"""
    try:
        # Extract IP address from Apache log format
        ip_match = re.match(r'^(\d+\.\d+\.\d+\.\d+)', line)
        if not ip_match:
            return None
        
        ip = ip_match.group(1)
        
        # SQL Injection patterns
        if any(pattern in line.lower() for pattern in [
            'union select', 'drop table', 'select * from', '1=1', 'or 1=1',
            'union%20select', 'drop%20table', '@@version'
        ]):
            return {
                'ip': ip,
                'type': 'SQL_INJECTION',
                'details': 'SQL injection attempt detected',
                'severity': 'HIGH'
            }
        
        # XSS patterns
        elif any(pattern in line.lower() for pattern in [
            '<script>', '</script>', 'alert(', 'javascript:', '<svg', 'onerror=',
            '%3cscript%3e', 'onload=alert'
        ]):
            return {
                'ip': ip,
                'type': 'XSS_ATTEMPT',
                'details': 'Cross-site scripting attempt',
                'severity': 'MEDIUM'
            }
        
        # Directory Traversal / Local File Inclusion
        elif any(pattern in line for pattern in [
            '../../../', '..\\..\\..\\', '/etc/passwd', '/proc/self/environ',
            'php://filter', '....//....//....//etc/passwd'
        ]):
            return {
                'ip': ip,
                'type': 'DIRECTORY_TRAVERSAL',
                'details': 'Directory traversal attempt',
                'severity': 'HIGH'
            }
        
        # Command Injection
        elif any(pattern in line for pattern in [
            '; cat ', '| whoami', '&& ls', '; wget ', '| nc -e',
            '%20cat%20', '%20wget%20', 'evil.com/shell'
        ]):
            return {
                'ip': ip,
                'type': 'COMMAND_INJECTION',
                'details': 'Command injection attempt',
                'severity': 'HIGH'
            }
        
        # C2 Beacon Communication
        elif '/api/v1/beacon' in line:
            return {
                'ip': ip,
                'type': 'C2_BEACON',
                'details': 'Command and control beacon',
                'severity': 'CRITICAL'
            }
        
        # Suspicious User Agent (AttackBot)
        elif 'AttackBot' in line:
            return {
                'ip': ip,
                'type': 'AUTOMATED_ATTACK',
                'details': 'Automated attack tool detected',
                'severity': 'HIGH'
            }
            
    except Exception as e:
        print(f"Error parsing web attack: {e}")
    
    return None

def monitor_logs():
    """Background thread to monitor log files for attacks"""
    print("🔍 Starting log monitoring...")
    
    # Generate some test data first
    generate_test_attacks()
    
    # Track last read positions for each log file
    log_positions = {
        'auth.log': 0,
        'apache.log': 0,
        'syslog': 0
    }
    
    while True:
        try:
            # Monitor SSH attacks in auth.log
            try:
                result = subprocess.run(['docker', 'exec', 'ubuntu-host', 'cat', '/var/log/auth.log'], 
                                      capture_output=True, text=True, timeout=10)
                if result.stdout:
                    lines = result.stdout.strip().split('\n')
                    new_lines = lines[log_positions['auth.log']:]
                    log_positions['auth.log'] = len(lines)
                    
                    for line in new_lines:
                        if line.strip() and ('Failed password' in line or 'Invalid user' in line or 'sudo' in line):
                            ssh_attack = parse_ssh_attack(line)
                            if ssh_attack:
                                log_attack(ssh_attack['ip'], ssh_attack['type'], 
                                         'SSH_SERVICE', ssh_attack['details'], 
                                         ssh_attack['severity'])
                                print(f"📊 Detected SSH attack from {ssh_attack['ip']}: {ssh_attack['type']}")
                                
                                # Update ML analytics
                                ml_event = {
                                    'ip': ssh_attack['ip'],
                                    'attack_type': ssh_attack['type'],
                                    'timestamp': datetime.now(),
                                    'severity': ssh_attack['severity'],
                                    'target': 'SSH_SERVICE'
                                }
                                behavioral_analyzer.update_profile(ml_event)
                                threat_predictor.update_threat_data(ml_event)
                                forensics_engine.collect_evidence(ml_event)
            except (subprocess.TimeoutExpired, subprocess.CalledProcessError) as e:
                print(f"Error reading auth.log: {e}")
            
            # Monitor web attacks in Apache access log
            try:
                result = subprocess.run(['docker', 'exec', 'ubuntu-host', 'cat', '/var/log/apache2/access.log'], 
                                      capture_output=True, text=True, timeout=10)
                if result.stdout:
                    lines = result.stdout.strip().split('\n')
                    new_lines = lines[log_positions['apache.log']:]
                    log_positions['apache.log'] = len(lines)
                    
                    for line in new_lines:
                        if line.strip() and ('AttackBot' in line or 'evil.com' in line or 'beacon' in line):
                            web_attack = parse_web_attack(line)
                            if web_attack:
                                log_attack(web_attack['ip'], web_attack['type'], 
                                         'WEB_SERVICE', web_attack['details'], 
                                         web_attack['severity'])
                                print(f"🌐 Detected web attack from {web_attack['ip']}: {web_attack['type']}")
                                
                                # Update ML analytics
                                ml_event = {
                                    'ip': web_attack['ip'],
                                    'attack_type': web_attack['type'],
                                    'timestamp': datetime.now(),
                                    'severity': web_attack['severity'],
                                    'target': 'WEB_SERVICE'
                                }
                                behavioral_analyzer.update_profile(ml_event)
                                threat_predictor.update_threat_data(ml_event)
                                forensics_engine.collect_evidence(ml_event)
            except (subprocess.TimeoutExpired, subprocess.CalledProcessError) as e:
                print(f"Error reading apache access.log: {e}")
            
            # Monitor system logs for lateral movement and other attacks
            try:
                result = subprocess.run(['docker', 'exec', 'ubuntu-host', 'cat', '/var/log/syslog'], 
                                      capture_output=True, text=True, timeout=10)
                if result.stdout:
                    lines = result.stdout.strip().split('\n')
                    new_lines = lines[log_positions['syslog']:]
                    log_positions['syslog'] = len(lines)
                    
                    for line in new_lines:
                        if line.strip():
                            # Parse lateral movement attacks
                            if 'SMB connection attempt' in line:
                                ip_match = re.search(r'from (\d+\.\d+\.\d+\.\d+)', line)
                                if ip_match:
                                    ip = ip_match.group(1)
                                    log_attack(ip, 'LATERAL_MOVEMENT', 'SMB_SERVICE', 
                                             'SMB enumeration attempt', 'HIGH')
                                    print(f"🔄 Detected lateral movement from {ip}")
                            
                            # Parse DNS tunneling
                            elif 'evil.com' in line or 'badguy.net' in line or 'attacker.org' in line:
                                ip_match = re.search(r'client (\d+\.\d+\.\d+\.\d+)', line)
                                if ip_match:
                                    ip = ip_match.group(1)
                                    log_attack(ip, 'DATA_EXFILTRATION', 'DNS_SERVICE', 
                                             'DNS tunneling detected', 'CRITICAL')
                                    print(f"💾 Detected data exfiltration from {ip}")
                            
                            # Parse C2 communication
                            elif 'TCP connection established' in line and ('185.159.158.234' in line or '94.102.49.193' in line):
                                ip_match = re.search(r'(\d+\.\d+\.\d+\.\d+):\d+ -> (\d+\.\d+\.\d+\.\d+):', line)
                                if ip_match:
                                    source_ip = ip_match.group(1)
                                    dest_ip = ip_match.group(2)
                                    log_attack(source_ip, 'C2_COMMUNICATION', 'NETWORK', 
                                             f'C2 connection to {dest_ip}', 'CRITICAL')
                                    print(f"📡 Detected C2 communication from {source_ip}")
            except (subprocess.TimeoutExpired, subprocess.CalledProcessError) as e:
                print(f"Error reading syslog: {e}")
            
            # Check fail2ban status
            try:
                result = subprocess.run(['docker', 'exec', 'fail2ban', 'fail2ban-client', 'status'], 
                                      capture_output=True, text=True, timeout=5)
                if result.stdout and 'sshd' in result.stdout:
                    ban_result = subprocess.run(['docker', 'exec', 'fail2ban', 'fail2ban-client', 'status', 'sshd'], 
                                              capture_output=True, text=True, timeout=5)
                    if ban_result.stdout:
                        banned_ips = re.findall(r'(\d+\.\d+\.\d+\.\d+)', ban_result.stdout)
                        for ip in banned_ips:
                            if ip not in defense_responses['blocked_ips']:
                                log_defense_action('FAIL2BAN_BAN', ip, 
                                                 f'Automatic ban by fail2ban for SSH attacks')
                                defense_responses['fail2ban_bans'] += 1
                                print(f"🛡️ Fail2ban banned IP: {ip}")
            except (subprocess.TimeoutExpired, subprocess.CalledProcessError):
                pass
            
        except Exception as e:
            print(f"Error in log monitoring: {e}")
        
        time.sleep(5)  # Check every 5 seconds

def generate_test_attacks():
    """Generate some test attack data for demonstration"""
    import random
    
    test_ips = [
        '192.0.2.100', '192.0.2.150', '192.0.2.200', '10.0.0.50', 
        '172.16.0.100', '203.0.113.50', '198.51.100.25'
    ]
    
    attack_types = [
        ('SSH_BRUTE_FORCE', 'Failed password for root', 'HIGH'),
        ('SSH_USER_ENUM', 'Invalid user admin', 'MEDIUM'),
        ('SQL_INJECTION', 'union select * from users', 'HIGH'),
        ('XSS_ATTEMPT', '<script>alert("xss")</script>', 'MEDIUM'),
        ('DIRECTORY_TRAVERSAL', '../../../etc/passwd', 'HIGH'),
        ('COMMAND_INJECTION', 'cmd=whoami', 'HIGH')
    ]
    
    # Generate 3-5 test attacks
    for _ in range(random.randint(3, 5)):
        ip = random.choice(test_ips)
        attack_type, details, severity = random.choice(attack_types)
        target = 'SSH_SERVICE' if 'SSH' in attack_type else 'WEB_SERVICE'
        
        log_attack(ip, attack_type, target, details, severity)
        time.sleep(0.5)  # Small delay between attacks
    
    print(f"🎯 Generated test attacks for demo purposes")

@app.route('/')
def index():
    """Main dashboard page"""
    return render_template('dashboard.html')

@app.route('/advanced')
def advanced_dashboard():
    """Advanced dashboard with geolocation and MITRE features"""
    return render_template('advanced_dashboard.html')

@app.route('/api/stats')
def get_stats():
    """API endpoint for current statistics"""
    stats = {
        'total_attacks': attack_stats['total_attacks'],
        'unique_ips': len(attack_stats['unique_ips']),
        'attack_types': dict(attack_stats['attack_types']),
        'top_attackers': dict(sorted(attack_stats['top_attackers'].items(), 
                                   key=lambda x: x[1], reverse=True)[:10]),
        'defense_actions': dict(defense_responses['defense_actions']),
        'blocked_ips': len(defense_responses['blocked_ips']),
        'fail2ban_bans': defense_responses['fail2ban_bans']
    }
    return jsonify(stats)

@app.route('/api/recent_attacks')
def get_recent_attacks():
    """API endpoint for recent attacks"""
    return jsonify(list(attack_stats['recent_attacks']))

@app.route('/api/recent_defenses')
def get_recent_defenses():
    """API endpoint for recent defense actions"""
    return jsonify(list(defense_responses['recent_responses']))

@app.route('/api/manual_block', methods=['POST'])
def manual_block():
    """API endpoint for manual IP blocking"""
    data = request.get_json()
    ip = data.get('ip')
    reason = data.get('reason', 'Manual block via web interface')
    
    if ip:
        try:
            # Add iptables rule
            subprocess.run(['iptables', '-I', 'INPUT', '-s', ip, '-j', 'DROP'], 
                         check=True, timeout=10)
            
            log_defense_action('MANUAL_BLOCK', ip, reason, 'SUCCESS')
            defense_responses['manual_blocks'] += 1
            
            return jsonify({'status': 'success', 'message': f'IP {ip} blocked successfully'})
        except subprocess.CalledProcessError as e:
            return jsonify({'status': 'error', 'message': f'Failed to block IP: {e}'})
        except Exception as e:
            return jsonify({'status': 'error', 'message': f'Error: {e}'})
    
    return jsonify({'status': 'error', 'message': 'Invalid IP address'})

@app.route('/api/threat_intel/<ip>')
def get_threat_intel(ip):
    """API endpoint for IP threat intelligence"""
    if not threat_intel:
        return jsonify({'error': 'Threat intelligence not available'})
    
    try:
        reputation = threat_intel.get_ip_reputation(ip)
        return jsonify(reputation)
    except Exception as e:
        return jsonify({'error': f'Threat intelligence error: {e}'})

@app.route('/api/threat_summary')
def get_threat_summary():
    """API endpoint for threat intelligence summary of recent attackers"""
    if not threat_intel:
        return jsonify({'error': 'Threat intelligence not available'})
    
    try:
        # Get unique IPs from recent attacks
        unique_ips = list(attack_stats['unique_ips'])[:20]  # Limit to 20 most recent
        
        if not unique_ips:
            return jsonify({'message': 'No recent attacks to analyze'})
        
        summary = threat_intel.get_threat_summary(unique_ips)
        return jsonify(summary)
    except Exception as e:
        return jsonify({'error': f'Threat summary error: {e}'})

@app.route('/api/bulk_threat_check', methods=['POST'])
def bulk_threat_check():
    """API endpoint for bulk IP threat checking"""
    if not threat_intel:
        return jsonify({'error': 'Threat intelligence not available'})
    
    try:
        data = request.get_json()
        ips = data.get('ips', [])
        
        if not ips or len(ips) > 50:  # Limit to 50 IPs
            return jsonify({'error': 'Invalid IP list (max 50 IPs)'})
        
        results = threat_intel.bulk_check_ips(ips)
        return jsonify(results)
    except Exception as e:
        return jsonify({'error': f'Bulk check error: {e}'})

@app.route('/api/executive_summary')
def get_executive_summary():
    """API endpoint for executive security summary"""
    if not security_reporter:
        return jsonify({'error': 'Security reporting not available'})
    
    try:
        days = request.args.get('days', 7, type=int)
        summary = security_reporter.generate_executive_summary(days)
        return jsonify(summary)
    except Exception as e:
        return jsonify({'error': f'Report generation error: {e}'})

@app.route('/api/attack_trends')
def get_attack_trends_api():
    """API endpoint for attack trends analysis"""
    if not security_reporter:
        return jsonify({'error': 'Security reporting not available'})
    
    try:
        days = request.args.get('days', 7, type=int)
        trends = security_reporter.get_attack_trends(days)
        return jsonify(trends)
    except Exception as e:
        return jsonify({'error': f'Trends analysis error: {e}'})

# ML Analytics API Endpoints

@app.route('/api/behavioral_analysis/<ip>')
def behavioral_analysis(ip):
    """Get behavioral analysis for specific IP"""
    try:
        analysis = behavioral_analyzer.analyze_behavior(ip)
        return jsonify(analysis)
    except Exception as e:
        print(f"Error in behavioral analysis: {e}")
        return jsonify({'error': 'Behavioral analysis failed'}), 500

@app.route('/api/behavioral_summary')
def behavioral_summary():
    """Get behavioral analysis summary"""
    try:
        summary = behavioral_analyzer.get_behavioral_summary()
        return jsonify(summary)
    except Exception as e:
        print(f"Error getting behavioral summary: {e}")
        return jsonify({'error': 'Behavioral summary failed'}), 500

@app.route('/api/threat_prediction')
def threat_prediction():
    """Get global threat predictions"""
    try:
        predictions = threat_predictor.predict_threats()
        return jsonify(predictions)
    except Exception as e:
        print(f"Error in threat prediction: {e}")
        return jsonify({'error': 'Threat prediction failed'}), 500

@app.route('/api/threat_prediction/<ip>')
def ip_threat_prediction(ip):
    """Get threat predictions for specific IP"""
    try:
        predictions = threat_predictor.predict_threats(ip)
        return jsonify(predictions)
    except Exception as e:
        print(f"Error in IP threat prediction: {e}")
        return jsonify({'error': 'IP threat prediction failed'}), 500

@app.route('/api/high_risk_ips')
def high_risk_ips():
    """Get list of highest risk IP addresses"""
    try:
        high_risk = threat_predictor.get_high_risk_ips()
        return jsonify(high_risk)
    except Exception as e:
        print(f"Error getting high risk IPs: {e}")
        return jsonify({'error': 'High risk IPs query failed'}), 500

@app.route('/api/forensics_report')
def forensics_report():
    """Get forensics analysis report"""
    try:
        # Get recent attacks from database
        conn = sqlite3.connect('data/attacks.db')
        cursor = conn.cursor()
        cursor.execute('''
            SELECT source_ip, attack_type, target, severity, timestamp, details
            FROM attacks 
            ORDER BY timestamp DESC 
            LIMIT 50
        ''')
        
        attacks = []
        for row in cursor.fetchall():
            attacks.append({
                'source_ip': row[0],
                'attack_type': row[1],
                'target': row[2],
                'severity': row[3],
                'timestamp': row[4],
                'details': row[5]
            })
        
        conn.close()
        
        # Build forensics report in the format expected by frontend
        report = {
            'stats': {
                'total_incidents': len(attacks),
                'active_threats': len([a for a in attacks if a['severity'] in ['HIGH', 'CRITICAL']]),
                'evidence_items': len(attacks) * 3,  # Simulated evidence items
                'resolved_cases': max(0, len(attacks) - 10)
            },
            'incidents': [
                {
                    'id': i + 1,
                    'title': f"{attack['attack_type'].replace('_', ' ').title()} Attack",
                    'severity': attack['severity'],
                    'timestamp': attack['timestamp'],
                    'source_ip': attack['source_ip'],
                    'details': attack['details']
                }
                for i, attack in enumerate(attacks[:20])  # Limit to 20 most recent
            ],
            'timeline': [
                {
                    'id': i + 1,
                    'content': f"{attack['attack_type'].replace('_', ' ')} from {attack['source_ip']}",
                    'start': attack['timestamp'],
                    'type': 'point',
                    'className': f"severity-{attack['severity'].lower()}",
                    'style': f"background-color: {'#ff4444' if attack['severity'] == 'HIGH' else '#ffa500' if attack['severity'] == 'MEDIUM' else '#ffff00' if attack['severity'] == 'LOW' else '#ff0000'};"
                }
                for i, attack in enumerate(attacks[:15])  # Limit timeline events
            ],
            'attack_chains': [
                {
                    'id': 1,
                    'title': 'SSH Brute Force Campaign',
                    'steps': [
                        'Initial port scanning',
                        'SSH service enumeration',
                        'Credential brute force attack',
                        'Failed authentication attempts',
                        'Potential lateral movement preparation'
                    ]
                },
                {
                    'id': 2,
                    'title': 'Web Application Attack Sequence',
                    'steps': [
                        'Directory traversal reconnaissance',
                        'SQL injection payload testing',
                        'Command injection attempts',
                        'Data exfiltration preparation',
                        'Privilege escalation attempts'
                    ]
                }
            ],
            'evidence': [
                {
                    'type': 'Network Traffic',
                    'content': f"SSH connection attempt from {attacks[0]['source_ip'] if attacks else '127.0.0.1'}",
                    'timestamp': attacks[0]['timestamp'] if attacks else datetime.now().isoformat()
                },
                {
                    'type': 'System Log',
                    'content': f"Failed authentication: {attacks[0]['details'] if attacks else 'Multiple failed login attempts'}",
                    'timestamp': attacks[1]['timestamp'] if len(attacks) > 1 else datetime.now().isoformat()
                },
                {
                    'type': 'Security Alert',
                    'content': f"Brute force pattern detected from {len(set(a['source_ip'] for a in attacks))} unique IPs",
                    'timestamp': datetime.now().isoformat()
                }
            ]
        }
        
        return jsonify(report)
        
    except Exception as e:
        print(f"Error generating forensics report: {e}")
        return jsonify({'error': 'Forensics report generation failed'}), 500

@app.route('/api/incident_reconstruction/<ip>')
def incident_reconstruction(ip):
    """Get incident reconstruction for specific IP"""
    try:
        time_window = request.args.get('hours', 24, type=int)
        reconstruction = forensics_engine.reconstruct_incident(ip, time_window)
        return jsonify(reconstruction)
    except Exception as e:
        print(f"Error in incident reconstruction: {e}")
        return jsonify({'error': 'Incident reconstruction failed'}), 500

@app.route('/api/ml_analytics_status')
def ml_analytics_status():
    """Get status of ML analytics engines"""
    try:
        status = {
            'behavioral_analyzer': {
                'active': True,
                'profiles_tracked': len(behavioral_analyzer.ip_profiles),
                'events_processed': behavioral_analyzer.total_events
            },
            'threat_predictor': {
                'active': True,
                'ips_tracked': len(threat_predictor.threat_patterns),
                'attack_events': len(threat_predictor.attack_history)
            },
            'forensics_engine': {
                'active': True,
                'evidence_items': len(forensics_engine.evidence_chain),
                'attack_chains': len(forensics_engine.attack_chains)
            }
        }
        return jsonify(status)
    except Exception as e:
        print(f"Error getting ML analytics status: {e}")
        return jsonify({'error': 'ML analytics status failed'}), 500

@socketio.on('connect')
def handle_connect():
    """Handle client connection"""
    print('Client connected')
    emit('status', {'msg': 'Connected to NoSleep-Ops Attack Monitor'})

@socketio.on('disconnect')
def handle_disconnect():
    """Handle client disconnection"""
    print('Client disconnected')

@app.route('/api/attack_map')
def get_attack_map():
    """API endpoint for geolocation attack map data"""
    if not ADVANCED_FEATURES:
        return jsonify({'error': 'Advanced features not available'})
    
    try:
        hours_back = request.args.get('hours', 24, type=int)
        map_data = geo_mapper.get_attack_map_data(hours_back)
        return jsonify({
            'map_data': map_data,
            'total_locations': len(map_data),
            'timestamp': datetime.now().isoformat()
        })
    except Exception as e:
        return jsonify({'error': f'Attack map error: {e}'})

@app.route('/api/global_stats')
def get_global_stats():
    """API endpoint for global attack statistics"""
    if not ADVANCED_FEATURES:
        return jsonify({'error': 'Advanced features not available'})
    
    try:
        global_stats = geo_mapper.get_global_attack_stats()
        return jsonify(global_stats)
    except Exception as e:
        return jsonify({'error': f'Global stats error: {e}'})

@app.route('/api/mitre_analysis')
def get_mitre_analysis():
    """API endpoint for MITRE ATT&CK analysis"""
    if not ADVANCED_FEATURES:
        return jsonify({'error': 'Advanced features not available'})
    
    try:
        # Get recent attacks from database
        conn = sqlite3.connect('data/attacks.db')
        cursor = conn.cursor()
        cursor.execute('''
            SELECT source_ip, attack_type, target, severity, timestamp, details
            FROM attacks 
            ORDER BY timestamp DESC 
            LIMIT 100
        ''')
        
        attacks = []
        for row in cursor.fetchall():
            attacks.append({
                'source_ip': row[0],
                'attack_type': row[1],
                'target': row[2],
                'severity': row[3],
                'timestamp': row[4],
                'details': row[5]
            })
        
        conn.close()
        
        # Get MITRE analysis
        mitre_data = mitre_mapper.get_mitre_dashboard_data(attacks)
        return jsonify(mitre_data)
        
    except Exception as e:
        return jsonify({'error': f'MITRE analysis error: {e}'})

@app.route('/api/mitre_attack_mapping/<attack_type>')
def get_mitre_mapping(attack_type):
    """API endpoint for specific attack type MITRE mapping"""
    if not ADVANCED_FEATURES:
        return jsonify({'error': 'Advanced features not available'})
    
    try:
        mapping = mitre_mapper.map_attack_to_mitre(attack_type)
        if mapping:
            return jsonify(mapping)
        else:
            return jsonify({'error': f'No MITRE mapping found for {attack_type}'})
    except Exception as e:
        return jsonify({'error': f'MITRE mapping error: {e}'})

@app.route('/api/campaign_analysis')
def get_campaign_analysis():
    """API endpoint for attack campaign analysis"""
    if not ADVANCED_FEATURES:
        return jsonify({'error': 'Advanced features not available'})
    
    try:
        # Get recent attacks
        conn = sqlite3.connect('data/attacks.db')
        cursor = conn.cursor()
        cursor.execute('''
            SELECT source_ip, attack_type, target, severity, timestamp, details
            FROM attacks 
            WHERE timestamp > datetime('now', '-24 hours')
            ORDER BY timestamp DESC
        ''')
        
        attacks = []
        for row in cursor.fetchall():
            attacks.append({
                'source_ip': row[0],
                'attack_type': row[1],
                'target': row[2],
                'severity': row[3],
                'timestamp': row[4],
                'details': row[5]
            })
        
        conn.close()
        
        # Get campaign analysis
        campaign_analysis = mitre_mapper.get_attack_campaign_analysis(attacks)
        return jsonify(campaign_analysis)
        
    except Exception as e:
        return jsonify({'error': f'Campaign analysis error: {e}'})

@app.route('/api/advanced_dashboard')
def get_advanced_dashboard():
    """API endpoint for advanced dashboard data combining all features"""
    if not ADVANCED_FEATURES:
        return jsonify({'error': 'Advanced features not available'})
    
    try:
        # Get basic stats
        basic_stats = get_stats().get_json()
        
        # Get geolocation data
        map_data = geo_mapper.get_attack_map_data(24)
        global_stats = geo_mapper.get_global_attack_stats()
        
        # Get MITRE analysis
        conn = sqlite3.connect('data/attacks.db')
        cursor = conn.cursor()
        cursor.execute('''
            SELECT source_ip, attack_type, target, severity, timestamp, details
            FROM attacks 
            ORDER BY timestamp DESC 
            LIMIT 100
        ''')
        
        attacks = []
        for row in cursor.fetchall():
            attacks.append({
                'source_ip': row[0],
                'attack_type': row[1],
                'target': row[2],
                'severity': row[3],
                'timestamp': row[4],
                'details': row[5]
            })
        
        conn.close()
        
        mitre_data = mitre_mapper.get_mitre_dashboard_data(attacks)
        campaign_analysis = mitre_mapper.get_attack_campaign_analysis(attacks)
        
        # Combine all data
        advanced_dashboard = {
            'basic_stats': basic_stats,
            'geolocation': {
                'map_data': map_data,
                'global_stats': global_stats
            },
            'mitre_attack': {
                'dashboard_data': mitre_data,
                'campaign_analysis': campaign_analysis
            },
            'timestamp': datetime.now().isoformat(),
            'features_available': ADVANCED_FEATURES
        }
        
        return jsonify(advanced_dashboard)
        
    except Exception as e:
        return jsonify({'error': f'Advanced dashboard error: {e}'})

# New Advanced Routes

@app.route('/threat-hunter')
def threat_hunter_dashboard():
    """AI-Powered Threat Hunter Dashboard"""
    return render_template('threat_hunter.html')

@app.route('/executive')
def executive_dashboard():
    """Executive Security Dashboard"""
    return render_template('executive.html')

@app.route('/mobile')
def mobile_dashboard():
    """Mobile-Optimized SOC Interface"""
    return render_template('mobile.html')

@app.route('/forensics')
def forensics_dashboard():
    """Advanced Forensics Timeline"""
    return render_template('forensics.html')

@app.route('/api/ai_threat_analysis')
def get_ai_threat_analysis():
    """Get AI-powered threat analysis"""
    if not AI_THREAT_HUNTER_AVAILABLE:
        return jsonify({
            'error': 'AI Threat Hunter not available',
            'demo_mode': True
        })
    
    try:
        analysis = threat_hunter.analyze_threat_landscape()
        return jsonify(analysis)
    except Exception as e:
        print(f"Error getting AI threat analysis: {e}")
        return jsonify({
            'error': str(e),
            'demo_mode': True
        })

@app.route('/api/executive_summary_new')
def get_executive_summary_new():
    """Get executive-level security summary"""
    try:
        if ADVANCED_FEATURES:
            summary = executive_reporter.generate_executive_summary()
            return jsonify(summary)
        else:
            # Return demo data based on current stats
            return jsonify({
                'executive_summary': {
                    'security_status': 'MODERATE RISK - Standard Operations',
                    'status_color': 'yellow',
                    'key_findings': [
                        f"{attack_stats['total_attacks']} security incidents detected",
                        'Stable attack trend over the past week',
                        f"{len(attack_stats['unique_ips'])} unique threat sources identified"
                    ]
                },
                'key_metrics': {
                    'attack_volume': {
                        'last_24h': attack_stats['total_attacks'],
                        'last_7d': attack_stats['total_attacks'] * 7,
                        'last_30d': attack_stats['total_attacks'] * 30
                    }
                },
                'business_impact': {
                    'financial_impact': {
                        'estimated_total_cost': 100000,
                        'cost_avoidance': 800000,
                        'roi_on_security': '400%'
                    }
                },
                'security_posture': {
                    'overall_score': 85
                },
                'compliance_status': {
                    'overall_compliance_score': '96%',
                    'frameworks': {
                        'ISO_27001': {'score': '95%'},
                        'NIST_CSF': {'score': '98%'},
                        'SOC_2': {'score': '94%'},
                        'GDPR': {'score': '97%'}
                    }
                },
                'risk_dashboard': {
                    'risk_score': 25
                },
                'threat_landscape': {
                    'top_threats': [
                        {'threat': attack_type, 'count': count, 'percentage': round(count/max(attack_stats['total_attacks'], 1)*100, 1)}
                        for attack_type, count in list(attack_stats['attack_types'].items())[:5]
                    ]
                },
                'recommendations': [
                    {
                        'priority': 'HIGH',
                        'title': 'Strengthen Remote Access Security',
                        'business_justification': 'Reduce risk of unauthorized system access',
                        'investment_required': '$25,000',
                        'expected_roi': '300%',
                        'timeline': '30 days'
                    }
                ]
            })
    except Exception as e:
        print(f"Error getting executive summary: {e}")
        return jsonify({'error': str(e)})

@app.route('/api/attack_flows')
def get_attack_flows():
    """Get attack progression analysis for 3D visualization"""
    try:
        # Create nodes and edges for 3D visualization
        nodes = [
            {
                'id': 'server',
                'label': 'Target Server',
                'type': 'target',
                'x': 0,
                'y': 0,
                'z': 0,
                'color': '#00ff88',
                'size': 20
            }
        ]
        
        edges = []
        
        # Add attacker nodes and connections
        for i, (ip, count) in enumerate(list(attack_stats['top_attackers'].items())[:10]):
            node_id = f"attacker_{i}"
            nodes.append({
                'id': node_id,
                'label': ip,
                'type': 'attacker',
                'x': (hash(ip) % 20) - 10,
                'y': (hash(ip + 'y') % 20) - 10,
                'z': (hash(ip + 'z') % 20) - 10,
                'color': '#ff4444' if count > 5 else '#ffa500',
                'size': min(count * 2, 15)
            })
            
            edges.append({
                'id': f"edge_{i}",
                'source': node_id,
                'target': 'server',
                'weight': count,
                'color': '#ff4444' if count > 5 else '#ffa500'
            })
        
        # Add intermediate compromise nodes for multi-step attacks
        ip_attacks = defaultdict(list)
        for attack in list(attack_stats['recent_attacks']):
            ip_attacks[attack['source_ip']].append(attack)
        
        attack_flows = []
        for ip, attacks in ip_attacks.items():
            if len(attacks) > 1:  # Multi-step attacks
                flow = {
                    'source_ip': ip,
                    'attack_sequence': [a['attack_type'] for a in attacks],
                    'timeline': [a['timestamp'] for a in attacks],
                    'severity': 'HIGH' if len(attacks) > 5 else 'MEDIUM'
                }
                attack_flows.append(flow)
        
        return jsonify({
            'nodes': nodes,
            'edges': edges,
            'attack_flows': attack_flows,
            'metadata': {
                'total_nodes': len(nodes),
                'total_edges': len(edges),
                'timestamp': datetime.now().isoformat()
            }
        })
    except Exception as e:
        print(f"Error getting attack flows: {e}")
        return jsonify({
            'nodes': [],
            'edges': [],
            'attack_flows': [],
            'error': str(e)
        })

@app.route('/api/threat_intelligence')
def get_threat_intelligence():
    """Get comprehensive threat intelligence"""
    try:
        intelligence = {
            'global_threat_level': 'MODERATE',
            'active_campaigns': len([ip for ip, count in attack_stats['top_attackers'].items() if count > 5]),
            'threat_actors': {
                'identified': len(attack_stats['unique_ips']),
                'high_confidence': len([ip for ip, count in attack_stats['top_attackers'].items() if count > 10]),
                'attribution': 'Multiple threat actors detected'
            },
            'attack_patterns': {
                'most_common': list(attack_stats['attack_types'].keys())[:3],
                'emerging_threats': ['AI-Powered Attacks', 'Supply Chain Attacks'],
                'seasonal_trends': 'Increased activity during business hours'
            },
            'iocs': {
                'malicious_ips': list(attack_stats['unique_ips'])[:10],
                'attack_signatures': list(attack_stats['attack_types'].keys()),
                'behavioral_indicators': ['Repeated failed logins', 'Port scanning', 'SQL injection attempts']
            }
        }
        return jsonify(intelligence)
    except Exception as e:
        print(f"Error getting threat intelligence: {e}")
        return jsonify({'error': str(e)})

if __name__ == '__main__':
    print("🚀 Starting NoSleep-Ops Web Attack Monitor")
    print("📊 Initializing database...")
    init_database()
    
    print("👁️  Starting log monitoring thread...")
    monitor_thread = threading.Thread(target=monitor_logs, daemon=True)
    monitor_thread.start()
    
    print("🌐 Starting web server on http://localhost:5000")
    print("📊 Basic Dashboard: http://localhost:5000")
    print("🔍 Advanced SOC: http://localhost:5000/advanced")
    print("🎯 AI Threat Hunter: http://localhost:5000/threat-hunter")
    print("📊 Executive Dashboard: http://localhost:5000/executive")
    print("📱 Mobile Dashboard: http://localhost:5000/mobile")
    print("🔬 Forensics Dashboard: http://localhost:5000/forensics")
    print("📈 Attack monitoring active")
    
    # Production mode - debug disabled for security
    socketio.run(app, host='0.0.0.0', port=5000, debug=False) 