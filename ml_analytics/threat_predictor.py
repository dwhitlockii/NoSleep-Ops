"""
Threat Prediction Engine
Uses historical patterns to predict future attack vectors and risks
"""

from datetime import datetime, timedelta
from typing import Dict, List, Tuple
from collections import defaultdict, deque
import logging
import json

class ThreatPredictor:
    """
    Predicts future threats based on historical attack patterns
    """
    
    def __init__(self, prediction_window: int = 24):
        self.prediction_window = prediction_window  # Hours to predict ahead
        self.logger = self._setup_logging()
        
        # Historical data for prediction
        self.attack_history = deque(maxlen=10000)
        self.threat_patterns = defaultdict(list)
        self.risk_scores = {}
        
        # Prediction models (simplified rule-based for now)
        self.attack_escalation_rules = {
            'SSH_BRUTE_FORCE': ['LATERAL_MOVEMENT', 'PRIVILEGE_ESCALATION'],
            'DIRECTORY_TRAVERSAL': ['FILE_INCLUSION', 'REMOTE_CODE_EXECUTION'],
            'SQL_INJECTION': ['DATA_EXFILTRATION', 'PRIVILEGE_ESCALATION'],
            'XSS': ['SESSION_HIJACKING', 'CREDENTIAL_THEFT'],
            'COMMAND_INJECTION': ['REMOTE_CODE_EXECUTION', 'SYSTEM_COMPROMISE']
        }
        
        self.threat_indicators = {
            'CRITICAL': ['REMOTE_CODE_EXECUTION', 'SYSTEM_COMPROMISE', 'DATA_EXFILTRATION'],
            'HIGH': ['PRIVILEGE_ESCALATION', 'LATERAL_MOVEMENT', 'CREDENTIAL_THEFT'],
            'MEDIUM': ['SQL_INJECTION', 'COMMAND_INJECTION', 'FILE_INCLUSION'],
            'LOW': ['DIRECTORY_TRAVERSAL', 'XSS', 'SSH_BRUTE_FORCE']
        }
    
    def _setup_logging(self) -> logging.Logger:
        """Setup logging for threat predictor"""
        logger = logging.getLogger('ThreatPredictor')
        logger.setLevel(logging.INFO)
        
        if not logger.handlers:
            handler = logging.StreamHandler()
            formatter = logging.Formatter(
                '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
            )
            handler.setFormatter(formatter)
            logger.addHandler(handler)
        
        return logger
    
    def update_threat_data(self, attack_event: Dict):
        """Update threat prediction models with new attack data"""
        timestamp = self._parse_timestamp(attack_event.get('timestamp'))
        source_ip = attack_event.get('source_ip', 'unknown')
        attack_type = attack_event.get('attack_type', 'UNKNOWN')
        
        # Store in attack history
        event = {
            'timestamp': timestamp,
            'source_ip': source_ip,
            'attack_type': attack_type,
            'severity': self._calculate_attack_severity(attack_type),
            'metadata': attack_event
        }
        
        self.attack_history.append(event)
        
        # Update threat patterns by IP
        self.threat_patterns[source_ip].append(event)
        
        # Update risk scores
        self._update_risk_scores(source_ip, attack_type)
    
    def _parse_timestamp(self, timestamp) -> datetime:
        """Parse timestamp from various formats"""
        if isinstance(timestamp, datetime):
            return timestamp
        elif isinstance(timestamp, str):
            try:
                return datetime.fromisoformat(timestamp.replace('Z', '+00:00'))
            except:
                return datetime.now()
        else:
            return datetime.now()
    
    def _calculate_attack_severity(self, attack_type: str) -> str:
        """Calculate severity level of attack type"""
        for severity, attacks in self.threat_indicators.items():
            if attack_type in attacks:
                return severity
        return 'UNKNOWN'
    
    def _update_risk_scores(self, source_ip: str, attack_type: str):
        """Update risk scores for IP addresses"""
        if source_ip not in self.risk_scores:
            self.risk_scores[source_ip] = {
                'base_score': 0,
                'escalation_score': 0,
                'frequency_score': 0,
                'total_score': 0,
                'last_updated': datetime.now()
            }
        
        risk = self.risk_scores[source_ip]
        
        # Base score based on attack severity
        severity_scores = {'CRITICAL': 40, 'HIGH': 30, 'MEDIUM': 20, 'LOW': 10, 'UNKNOWN': 5}
        severity = self._calculate_attack_severity(attack_type)
        risk['base_score'] = max(risk['base_score'], severity_scores.get(severity, 5))
        
        # Escalation score if attack follows escalation pattern
        ip_attacks = [event['attack_type'] for event in self.threat_patterns[source_ip]]
        for prev_attack in ip_attacks[:-1]:  # Check previous attacks
            if prev_attack in self.attack_escalation_rules:
                expected_escalations = self.attack_escalation_rules[prev_attack]
                if attack_type in expected_escalations:
                    risk['escalation_score'] += 25
                    break
        
        # Frequency score based on attack frequency
        recent_attacks = [e for e in self.threat_patterns[source_ip] 
                         if (datetime.now() - e['timestamp']).total_seconds() < 3600]
        risk['frequency_score'] = min(len(recent_attacks) * 5, 50)
        
        # Calculate total score
        risk['total_score'] = min(risk['base_score'] + risk['escalation_score'] + risk['frequency_score'], 100)
        risk['last_updated'] = datetime.now()
    
    def predict_threats(self, source_ip: str = None) -> Dict:
        """Predict future threats for specific IP or globally"""
        if source_ip:
            return self._predict_ip_threats(source_ip)
        else:
            return self._predict_global_threats()
    
    def _predict_ip_threats(self, source_ip: str) -> Dict:
        """Predict threats for a specific IP address"""
        if source_ip not in self.threat_patterns:
            return {
                'ip': source_ip,
                'status': 'no_data',
                'message': 'No historical data available for threat prediction'
            }
        
        ip_events = self.threat_patterns[source_ip]
        if len(ip_events) < 3:
            return {
                'ip': source_ip,
                'status': 'insufficient_data',
                'message': 'Insufficient attack history for reliable prediction',
                'event_count': len(ip_events)
            }
        
        # Analyze attack patterns
        attack_sequence = [event['attack_type'] for event in ip_events[-10:]]  # Last 10 attacks
        predicted_attacks = []
        prediction_confidence = 0
        
        # Rule-based prediction using escalation patterns
        for attack in reversed(attack_sequence):  # Start from most recent
            if attack in self.attack_escalation_rules:
                next_attacks = self.attack_escalation_rules[attack]
                for next_attack in next_attacks:
                    if next_attack not in attack_sequence:  # Not already executed
                        predicted_attacks.append({
                            'attack_type': next_attack,
                            'confidence': 0.7,
                            'time_window': f"{self.prediction_window} hours",
                            'trigger': attack,
                            'severity': self._calculate_attack_severity(next_attack)
                        })
                        prediction_confidence += 0.2
                break
        
        # Frequency-based prediction
        attack_frequency = defaultdict(int)
        for event in ip_events:
            attack_frequency[event['attack_type']] += 1
        
        most_common = max(attack_frequency, key=attack_frequency.get)
        if attack_frequency[most_common] >= 3:
            predicted_attacks.append({
                'attack_type': most_common,
                'confidence': min(attack_frequency[most_common] * 0.15, 0.8),
                'time_window': f"{self.prediction_window} hours",
                'trigger': 'frequency_pattern',
                'severity': self._calculate_attack_severity(most_common)
            })
            prediction_confidence += 0.3
        
        # Calculate overall threat level
        current_risk = self.risk_scores.get(source_ip, {}).get('total_score', 0)
        if current_risk >= 80:
            threat_level = 'CRITICAL'
        elif current_risk >= 60:
            threat_level = 'HIGH'
        elif current_risk >= 40:
            threat_level = 'MEDIUM'
        else:
            threat_level = 'LOW'
        
        return {
            'ip': source_ip,
            'status': 'predicted',
            'threat_level': threat_level,
            'current_risk_score': current_risk,
            'prediction_confidence': min(prediction_confidence, 1.0),
            'predicted_attacks': predicted_attacks,
            'attack_history': attack_sequence,
            'prediction_window': f"{self.prediction_window} hours",
            'timestamp': datetime.now().isoformat()
        }
    
    def _predict_global_threats(self) -> Dict:
        """Predict global threat landscape"""
        if len(self.attack_history) < 10:
            return {
                'status': 'insufficient_data',
                'message': 'Insufficient global attack data for prediction',
                'total_events': len(self.attack_history)
            }
        
        # Analyze global attack trends
        recent_attacks = [event for event in self.attack_history 
                         if (datetime.now() - event['timestamp']).total_seconds() < 86400]  # Last 24h
        
        # Attack type distribution
        attack_distribution = defaultdict(int)
        severity_distribution = defaultdict(int)
        hourly_distribution = defaultdict(int)
        
        for event in recent_attacks:
            attack_distribution[event['attack_type']] += 1
            severity_distribution[event['severity']] += 1
            hourly_distribution[event['timestamp'].hour] += 1
        
        # Predict peak attack times
        if hourly_distribution:
            peak_hour = max(hourly_distribution, key=hourly_distribution.get)
            current_hour = datetime.now().hour
            hours_to_peak = (peak_hour - current_hour) % 24
        else:
            peak_hour = None
            hours_to_peak = None
        
        # Predict emerging threats
        emerging_threats = []
        for attack_type, count in attack_distribution.items():
            if count >= 5:  # Significant activity
                severity = self._calculate_attack_severity(attack_type)
                emerging_threats.append({
                    'attack_type': attack_type,
                    'frequency': count,
                    'severity': severity,
                    'trend': 'increasing' if count > 3 else 'stable'
                })
        
        # Sort by severity and frequency
        emerging_threats.sort(key=lambda x: (
            {'CRITICAL': 4, 'HIGH': 3, 'MEDIUM': 2, 'LOW': 1}.get(x['severity'], 0),
            x['frequency']
        ), reverse=True)
        
        # Calculate global risk level
        critical_count = severity_distribution.get('CRITICAL', 0)
        high_count = severity_distribution.get('HIGH', 0)
        
        if critical_count >= 5 or high_count >= 10:
            global_risk = 'CRITICAL'
        elif critical_count >= 2 or high_count >= 5:
            global_risk = 'HIGH'
        elif high_count >= 2:
            global_risk = 'MEDIUM'
        else:
            global_risk = 'LOW'
        
        return {
            'status': 'predicted',
            'global_risk_level': global_risk,
            'total_recent_attacks': len(recent_attacks),
            'attack_distribution': dict(attack_distribution),
            'severity_distribution': dict(severity_distribution),
            'emerging_threats': emerging_threats[:10],  # Top 10
            'peak_attack_prediction': {
                'hour': peak_hour,
                'hours_until_peak': hours_to_peak,
                'expected_activity': 'high' if peak_hour else 'unknown'
            },
            'prediction_window': f"{self.prediction_window} hours",
            'timestamp': datetime.now().isoformat()
        }
    
    def get_high_risk_ips(self, limit: int = 10) -> List[Dict]:
        """Get list of highest risk IP addresses"""
        # Sort IPs by total risk score
        sorted_ips = sorted(
            self.risk_scores.items(),
            key=lambda x: x[1]['total_score'],
            reverse=True
        )
        
        high_risk_ips = []
        for ip, risk_data in sorted_ips[:limit]:
            ip_info = {
                'ip': ip,
                'risk_score': risk_data['total_score'],
                'base_score': risk_data['base_score'],
                'escalation_score': risk_data['escalation_score'],
                'frequency_score': risk_data['frequency_score'],
                'last_updated': risk_data['last_updated'].isoformat(),
                'attack_count': len(self.threat_patterns.get(ip, [])),
                'recent_attacks': [
                    event['attack_type'] for event in 
                    self.threat_patterns.get(ip, [])[-5:]  # Last 5 attacks
                ]
            }
            
            # Add threat level
            if risk_data['total_score'] >= 80:
                ip_info['threat_level'] = 'CRITICAL'
            elif risk_data['total_score'] >= 60:
                ip_info['threat_level'] = 'HIGH'
            elif risk_data['total_score'] >= 40:
                ip_info['threat_level'] = 'MEDIUM'
            else:
                ip_info['threat_level'] = 'LOW'
            
            high_risk_ips.append(ip_info)
        
        return high_risk_ips
    
    def get_prediction_summary(self) -> Dict:
        """Get summary of threat prediction capabilities"""
        total_ips = len(self.threat_patterns)
        total_events = len(self.attack_history)
        
        # Risk distribution
        risk_distribution = {'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0}
        for risk_data in self.risk_scores.values():
            score = risk_data['total_score']
            if score >= 80:
                risk_distribution['CRITICAL'] += 1
            elif score >= 60:
                risk_distribution['HIGH'] += 1
            elif score >= 40:
                risk_distribution['MEDIUM'] += 1
            else:
                risk_distribution['LOW'] += 1
        
        return {
            'total_tracked_ips': total_ips,
            'total_attack_events': total_events,
            'risk_distribution': risk_distribution,
            'prediction_window_hours': self.prediction_window,
            'supported_escalation_patterns': len(self.attack_escalation_rules),
            'last_updated': datetime.now().isoformat()
        } 