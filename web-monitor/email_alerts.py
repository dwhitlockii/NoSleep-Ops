#!/usr/bin/env python3
"""
NoSleep-Ops Email Alerting System
Sends email notifications for critical security events
"""

import smtplib
import os
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from datetime import datetime
from typing import List, Dict, Optional
import logging
import json

logger = logging.getLogger(__name__)

class EmailAlerter:
    """Email alerting system for security events"""
    
    def __init__(self, config: Optional[Dict] = None):
        self.config = config or {}
        self.enabled = self.config.get('ENABLE_EMAIL_ALERTS', False)
        
        if self.enabled:
            self.smtp_server = self.config.get('SMTP_SERVER', 'smtp.gmail.com')
            self.smtp_port = self.config.get('SMTP_PORT', 587)
            self.username = self.config.get('SMTP_USERNAME')
            self.password = self.config.get('SMTP_PASSWORD')
            self.recipients = self.config.get('ALERT_RECIPIENTS', '').split(',')
            
            if not all([self.username, self.password, self.recipients]):
                logger.warning("Email alerting enabled but missing configuration")
                self.enabled = False
    
    def send_critical_alert(self, title: str, details: Dict, attack_data: Dict = None):
        """Send critical security alert via email"""
        if not self.enabled:
            return False
        
        try:
            subject = f"🚨 CRITICAL SECURITY ALERT: {title}"
            body = self._create_alert_body(title, details, attack_data)
            
            return self._send_email(subject, body)
        except Exception as e:
            logger.error(f"Failed to send critical alert: {e}")
            return False
    
    def send_summary_report(self, summary: Dict):
        """Send daily/weekly security summary report"""
        if not self.enabled:
            return False
        
        try:
            risk_level = summary.get('risk_assessment', {}).get('overall_risk_level', 'UNKNOWN')
            total_attacks = summary.get('key_metrics', {}).get('total_attacks', 0)
            
            subject = f"📊 Security Summary Report - Risk Level: {risk_level}"
            body = self._create_summary_body(summary)
            
            return self._send_email(subject, body)
        except Exception as e:
            logger.error(f"Failed to send summary report: {e}")
            return False
    
    def send_threat_intel_alert(self, ip: str, reputation: Dict):
        """Send threat intelligence alert for high-risk IPs"""
        if not self.enabled:
            return False
        
        reputation_score = reputation.get('reputation_score', 0)
        if reputation_score < 80:  # Only send for very high-risk IPs
            return False
        
        try:
            subject = f"🎯 THREAT INTELLIGENCE ALERT: High-Risk IP {ip}"
            body = self._create_threat_intel_body(ip, reputation)
            
            return self._send_email(subject, body)
        except Exception as e:
            logger.error(f"Failed to send threat intel alert: {e}")
            return False
    
    def _create_alert_body(self, title: str, details: Dict, attack_data: Dict = None) -> str:
        """Create email body for critical alerts"""
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S UTC")
        
        body = f"""
NOSLEEP-OPS SECURITY ALERT
==========================

Alert: {title}
Timestamp: {timestamp}
Severity: CRITICAL

ALERT DETAILS:
--------------
"""
        
        for key, value in details.items():
            body += f"{key.replace('_', ' ').title()}: {value}\n"
        
        if attack_data:
            body += f"""

ATTACK INFORMATION:
-------------------
Source IP: {attack_data.get('source_ip', 'Unknown')}
Attack Type: {attack_data.get('attack_type', 'Unknown')}
Target: {attack_data.get('target', 'Unknown')}
Details: {attack_data.get('details', 'No details available')}
Severity: {attack_data.get('severity', 'Unknown')}
"""
        
        body += f"""

RECOMMENDED ACTIONS:
--------------------
1. Investigate the source IP immediately
2. Check for additional compromise indicators
3. Review recent authentication logs
4. Consider blocking the source IP if confirmed malicious
5. Update security team and management

This is an automated alert from NoSleep-Ops Security Monitoring System.
For questions, contact your security team.
"""
        
        return body
    
    def _create_summary_body(self, summary: Dict) -> str:
        """Create email body for summary reports"""
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S UTC")
        
        key_metrics = summary.get('key_metrics', {})
        risk_assessment = summary.get('risk_assessment', {})
        attack_summary = summary.get('attack_summary', {})
        
        body = f"""
NOSLEEP-OPS SECURITY SUMMARY REPORT
===================================

Report Generated: {timestamp}
Analysis Period: {summary.get('analysis_period', 'Unknown')}

EXECUTIVE SUMMARY:
------------------
Overall Risk Level: {risk_assessment.get('overall_risk_level', 'Unknown')}
Total Attacks: {key_metrics.get('total_attacks', 0)}
Unique Attackers: {key_metrics.get('unique_attackers', 0)}
Average Attacks/Day: {key_metrics.get('attacks_per_day', 0):.1f}

ATTACK BREAKDOWN:
-----------------
Most Common Attack: {attack_summary.get('most_common_attack', 'None')}
"""
        
        # Add attack distribution
        attack_dist = attack_summary.get('attack_distribution', {})
        if attack_dist:
            body += "\nAttack Type Distribution:\n"
            for attack_type, count in attack_dist.items():
                body += f"  • {attack_type}: {count} attacks\n"
        
        # Add recommendations
        recommendations = risk_assessment.get('recommendations', [])
        if recommendations:
            body += "\nSECURITY RECOMMENDATIONS:\n"
            body += "-------------------------\n"
            for i, rec in enumerate(recommendations, 1):
                body += f"{i}. {rec}\n"
        
        body += f"""

TREND ANALYSIS:
---------------
Risk Level: {risk_assessment.get('overall_risk_level', 'Unknown')}
"""
        
        if key_metrics.get('total_attacks', 0) > 50:
            body += "⚠️  High attack volume detected - immediate attention recommended\n"
        elif key_metrics.get('total_attacks', 0) > 20:
            body += "⚡ Moderate attack activity - continue monitoring\n"
        else:
            body += "✅ Low attack activity - normal operations\n"
        
        body += """
This is an automated report from NoSleep-Ops Security Monitoring System.
For detailed analysis, access the web dashboard or contact the security team.
"""
        
        return body
    
    def _create_threat_intel_body(self, ip: str, reputation: Dict) -> str:
        """Create email body for threat intelligence alerts"""
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S UTC")
        
        body = f"""
NOSLEEP-OPS THREAT INTELLIGENCE ALERT
=====================================

High-Risk IP Detected: {ip}
Timestamp: {timestamp}
Reputation Score: {reputation.get('reputation_score', 0)}/100

THREAT ANALYSIS:
----------------
Malicious: {reputation.get('is_malicious', False)}
Tor Exit Node: {reputation.get('is_tor', False)}
Known Scanner: {reputation.get('is_scanner', False)}
Country: {reputation.get('country', 'Unknown')}
"""
        
        threat_types = reputation.get('threat_types', [])
        if threat_types:
            body += f"\nThreat Types:\n"
            for threat in threat_types:
                body += f"  • {threat.replace('_', ' ').title()}\n"
        
        sources = reputation.get('sources', {})
        if sources:
            body += f"\nIntelligence Sources:\n"
            for source, data in sources.items():
                body += f"  • {source.title()}: {data}\n"
        
        body += f"""

IMMEDIATE ACTIONS REQUIRED:
---------------------------
1. Block IP {ip} immediately if not already blocked
2. Review all recent connections from this IP
3. Check for signs of successful compromise
4. Update threat intelligence feeds
5. Monitor for related indicators

This IP has been flagged as high-risk by multiple threat intelligence sources.
Immediate action is recommended to prevent potential security incidents.
"""
        
        return body
    
    def _send_email(self, subject: str, body: str) -> bool:
        """Send email using SMTP"""
        try:
            # Create message
            msg = MIMEMultipart()
            msg['From'] = self.username
            msg['To'] = ', '.join(self.recipients)
            msg['Subject'] = subject
            
            # Add body
            msg.attach(MIMEText(body, 'plain'))
            
            # Connect to server and send
            server = smtplib.SMTP(self.smtp_server, self.smtp_port)
            server.starttls()
            server.login(self.username, self.password)
            
            text = msg.as_string()
            server.sendmail(self.username, self.recipients, text)
            server.quit()
            
            logger.info(f"Email alert sent successfully to {len(self.recipients)} recipients")
            return True
            
        except Exception as e:
            logger.error(f"Failed to send email: {e}")
            return False
    
    def test_email_config(self) -> Dict:
        """Test email configuration"""
        if not self.enabled:
            return {'status': 'disabled', 'message': 'Email alerting is disabled'}
        
        try:
            # Test SMTP connection
            server = smtplib.SMTP(self.smtp_server, self.smtp_port)
            server.starttls()
            server.login(self.username, self.password)
            server.quit()
            
            return {
                'status': 'success',
                'message': 'Email configuration is valid',
                'smtp_server': self.smtp_server,
                'recipients': len(self.recipients)
            }
        except Exception as e:
            return {
                'status': 'error',
                'message': f'Email configuration test failed: {e}'
            }

# Example usage
if __name__ == "__main__":
    # Test configuration
    config = {
        'ENABLE_EMAIL_ALERTS': True,
        'SMTP_SERVER': 'smtp.gmail.com',
        'SMTP_PORT': 587,
        'SMTP_USERNAME': 'your-email@gmail.com',
        'SMTP_PASSWORD': 'your-app-password',
        'ALERT_RECIPIENTS': 'admin@company.com,security@company.com'
    }
    
    alerter = EmailAlerter(config)
    
    # Test configuration
    test_result = alerter.test_email_config()
    print(f"Email Config Test: {test_result}")
    
    # Test critical alert
    if test_result['status'] == 'success':
        alert_details = {
            'attack_count': 50,
            'source_ip': '192.168.1.100',
            'attack_type': 'SSH_BRUTE_FORCE',
            'time_window': '5 minutes'
        }
        
        attack_data = {
            'source_ip': '192.168.1.100',
            'attack_type': 'SSH_BRUTE_FORCE',
            'target': 'SSH_SERVICE',
            'details': 'Rapid brute force attack detected',
            'severity': 'HIGH'
        }
        
        success = alerter.send_critical_alert(
            "Rapid Brute Force Attack Detected", 
            alert_details, 
            attack_data
        )
        
        print(f"Test Alert Sent: {success}") 