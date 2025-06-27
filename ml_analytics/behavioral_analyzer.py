"""
Behavioral Analysis Engine
Analyzes user and network behavior patterns to detect deviations
"""

from collections import defaultdict, deque
from datetime import datetime, timedelta
from typing import Dict, List
import logging
import statistics

class BehavioralAnalyzer:
    """Analyzes behavioral patterns in network traffic"""
    
    def __init__(self, window_size: int = 100):
        self.window_size = window_size
        self.logger = self._setup_logging()
        self.ip_profiles = defaultdict(lambda: {
            'request_patterns': deque(maxlen=window_size),
            'timing_patterns': deque(maxlen=window_size),
            'port_patterns': defaultdict(int),
            'attack_patterns': defaultdict(int),
            'first_seen': None,
            'last_seen': None,
            'total_requests': 0,
            'baseline_established': False
        })
        self.total_events = 0
        self.analysis_history = deque(maxlen=1000)
    
    def _setup_logging(self) -> logging.Logger:
        """Setup logging"""
        logger = logging.getLogger('BehavioralAnalyzer')
        logger.setLevel(logging.INFO)
        if not logger.handlers:
            handler = logging.StreamHandler()
            formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
            handler.setFormatter(formatter)
            logger.addHandler(handler)
        return logger
    
    def update_profile(self, log_entry: Dict):
        """Update behavioral profile with new log entry"""
        source_ip = log_entry.get('source_ip', 'unknown')
        timestamp = self._parse_timestamp(log_entry.get('timestamp'))
        attack_type = log_entry.get('attack_type', 'UNKNOWN')
        port = log_entry.get('port', 0)
        
        profile = self.ip_profiles[source_ip]
        
        if profile['first_seen'] is None:
            profile['first_seen'] = timestamp
        profile['last_seen'] = timestamp
        profile['total_requests'] += 1
        
        profile['request_patterns'].append({
            'timestamp': timestamp,
            'attack_type': attack_type,
            'port': port
        })
        
        profile['timing_patterns'].append(timestamp)
        profile['port_patterns'][port] += 1
        profile['attack_patterns'][attack_type] += 1
        
        if profile['total_requests'] >= 20:
            profile['baseline_established'] = True
        
        self.total_events += 1
    
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
    
    def analyze_behavior(self, source_ip: str) -> Dict:
        """Analyze behavioral patterns for a specific IP"""
        if source_ip not in self.ip_profiles:
            return {
                'ip': source_ip,
                'status': 'no_data',
                'message': 'No behavioral data available for this IP'
            }
        
        profile = self.ip_profiles[source_ip]
        
        if not profile['baseline_established']:
            return {
                'ip': source_ip,
                'status': 'insufficient_data',
                'message': 'Insufficient data to establish behavioral baseline',
                'total_requests': profile['total_requests']
            }
        
        analysis = {
            'ip': source_ip,
            'status': 'analyzed',
            'total_requests': profile['total_requests'],
            'first_seen': profile['first_seen'].isoformat() if profile['first_seen'] else None,
            'last_seen': profile['last_seen'].isoformat() if profile['last_seen'] else None,
            'behavioral_score': 0,
            'anomalies': [],
            'patterns': {}
        }
        
        # Analyze timing patterns
        timing_analysis = self._analyze_timing_patterns(profile)
        analysis['patterns']['timing'] = timing_analysis
        if timing_analysis['is_anomalous']:
            analysis['anomalies'].append('unusual_timing_pattern')
            analysis['behavioral_score'] += 25
        
        # Analyze port patterns
        port_analysis = self._analyze_port_patterns(profile)
        analysis['patterns']['ports'] = port_analysis
        if port_analysis['is_anomalous']:
            analysis['anomalies'].append('unusual_port_usage')
            analysis['behavioral_score'] += 20
        
        # Analyze attack patterns
        attack_analysis = self._analyze_attack_patterns(profile)
        analysis['patterns']['attacks'] = attack_analysis
        if attack_analysis['is_anomalous']:
            analysis['anomalies'].append('unusual_attack_pattern')
            analysis['behavioral_score'] += 35
        
        # Determine risk level
        if analysis['behavioral_score'] >= 60:
            analysis['risk_level'] = 'HIGH'
        elif analysis['behavioral_score'] >= 30:
            analysis['risk_level'] = 'MEDIUM'
        else:
            analysis['risk_level'] = 'LOW'
        
        self.analysis_history.append(analysis)
        return analysis
    
    def _analyze_timing_patterns(self, profile: Dict) -> Dict:
        """Analyze timing patterns between requests"""
        timestamps = list(profile['timing_patterns'])
        if len(timestamps) < 5:
            return {'is_anomalous': False, 'reason': 'insufficient_data'}
        
        intervals = []
        for i in range(1, len(timestamps)):
            interval = (timestamps[i] - timestamps[i-1]).total_seconds()
            intervals.append(interval)
        
        if not intervals:
            return {'is_anomalous': False, 'reason': 'no_intervals'}
        
        avg_interval = statistics.mean(intervals)
        std_interval = statistics.stdev(intervals) if len(intervals) > 1 else 0
        
        # Detect automation (very regular patterns)
        is_automated = std_interval < 0.1 and avg_interval < 10
        
        # Detect burst patterns
        short_intervals = [i for i in intervals if i < 1.0]
        burst_ratio = len(short_intervals) / len(intervals)
        is_burst_pattern = burst_ratio > 0.7
        
        is_anomalous = is_automated or is_burst_pattern
        
        return {
            'is_anomalous': is_anomalous,
            'avg_interval': avg_interval,
            'std_interval': std_interval,
            'is_automated': is_automated,
            'is_burst_pattern': is_burst_pattern,
            'burst_ratio': burst_ratio
        }
    
    def _analyze_port_patterns(self, profile: Dict) -> Dict:
        """Analyze port usage patterns"""
        port_counts = profile['port_patterns']
        if not port_counts:
            return {'is_anomalous': False, 'reason': 'no_port_data'}
        
        unique_ports = len(port_counts)
        total_requests = sum(port_counts.values())
        port_diversity = unique_ports / max(total_requests, 1)
        
        # Check for unusual ports
        common_ports = {80, 443, 22, 21, 25, 53, 110, 143, 993, 995}
        unusual_ports = [p for p in port_counts if p not in common_ports and port_counts[p] > 5]
        
        # Check for port scanning
        is_port_scanning = unique_ports > 10 and port_diversity > 0.5
        
        is_anomalous = len(unusual_ports) > 3 or is_port_scanning
        
        return {
            'is_anomalous': is_anomalous,
            'unique_ports': unique_ports,
            'port_diversity': port_diversity,
            'unusual_ports': unusual_ports,
            'is_port_scanning': is_port_scanning,
            'most_targeted_port': max(port_counts, key=port_counts.get)
        }
    
    def _analyze_attack_patterns(self, profile: Dict) -> Dict:
        """Analyze attack type patterns"""
        attack_counts = profile['attack_patterns']
        if not attack_counts:
            return {'is_anomalous': False, 'reason': 'no_attack_data'}
        
        unique_attacks = len(attack_counts)
        total_attacks = sum(attack_counts.values())
        
        # Check for multi-vector attacks
        is_multi_vector = unique_attacks > 3
        
        # Check for persistent attacks
        max_attack_count = max(attack_counts.values())
        attack_persistence = max_attack_count / total_attacks
        is_persistent_attack = attack_persistence > 0.8 and total_attacks > 10
        
        # Check for escalation patterns
        escalation_indicators = ['PRIVILEGE_ESCALATION', 'LATERAL_MOVEMENT', 'DATA_EXFILTRATION']
        has_escalation = any(attack in attack_counts for attack in escalation_indicators)
        
        is_anomalous = is_multi_vector or is_persistent_attack or has_escalation
        
        return {
            'is_anomalous': is_anomalous,
            'unique_attacks': unique_attacks,
            'is_multi_vector': is_multi_vector,
            'is_persistent_attack': is_persistent_attack,
            'has_escalation': has_escalation,
            'primary_attack_type': max(attack_counts, key=attack_counts.get),
            'attack_distribution': dict(attack_counts)
        }
    
    def get_behavioral_summary(self) -> Dict:
        """Get summary of all behavioral analysis"""
        active_ips = len(self.ip_profiles)
        profiles_with_baseline = sum(1 for p in self.ip_profiles.values() if p['baseline_established'])
        
        risk_distribution = {'HIGH': 0, 'MEDIUM': 0, 'LOW': 0}
        for analysis in list(self.analysis_history)[-50:]:
            if 'risk_level' in analysis:
                risk_distribution[analysis['risk_level']] += 1
        
        return {
            'total_events_processed': self.total_events,
            'active_ip_profiles': active_ips,
            'profiles_with_baseline': profiles_with_baseline,
            'recent_risk_distribution': risk_distribution
        } 