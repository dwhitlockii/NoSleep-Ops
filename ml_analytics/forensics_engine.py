"""
Forensics Engine
Automated incident reconstruction and evidence collection
"""

from datetime import datetime, timedelta
from typing import Dict, List
from collections import defaultdict, deque
import logging
import json

class ForensicsEngine:
    """Automated forensics and incident reconstruction"""
    
    def __init__(self):
        self.logger = self._setup_logging()
        self.incidents = {}
        self.evidence_chain = deque(maxlen=50000)
        self.attack_chains = defaultdict(list)
        
    def _setup_logging(self) -> logging.Logger:
        """Setup logging"""
        logger = logging.getLogger('ForensicsEngine')
        logger.setLevel(logging.INFO)
        if not logger.handlers:
            handler = logging.StreamHandler()
            formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
            handler.setFormatter(formatter)
            logger.addHandler(handler)
        return logger
    
    def collect_evidence(self, attack_event: Dict):
        """Collect and store evidence from attack events"""
        evidence = {
            'timestamp': datetime.now().isoformat(),
            'event_data': attack_event,
            'source_ip': attack_event.get('source_ip'),
            'attack_type': attack_event.get('attack_type'),
            'evidence_id': len(self.evidence_chain) + 1,
            'chain_of_custody': f"Collected by ForensicsEngine at {datetime.now().isoformat()}"
        }
        
        self.evidence_chain.append(evidence)
        
        # Build attack chains
        source_ip = attack_event.get('source_ip')
        if source_ip:
            self.attack_chains[source_ip].append(evidence)
    
    def reconstruct_incident(self, source_ip: str, time_window: int = 24) -> Dict:
        """Reconstruct incident timeline for specific IP"""
        if source_ip not in self.attack_chains:
            return {'status': 'no_data', 'ip': source_ip}
        
        cutoff_time = datetime.now() - timedelta(hours=time_window)
        
        # Get relevant evidence
        relevant_evidence = []
        for evidence in self.attack_chains[source_ip]:
            event_time = datetime.fromisoformat(evidence['timestamp'])
            if event_time >= cutoff_time:
                relevant_evidence.append(evidence)
        
        if not relevant_evidence:
            return {'status': 'no_recent_activity', 'ip': source_ip}
        
        # Reconstruct timeline
        timeline = []
        attack_progression = []
        
        for evidence in sorted(relevant_evidence, key=lambda x: x['timestamp']):
            timeline.append({
                'timestamp': evidence['timestamp'],
                'attack_type': evidence['attack_type'],
                'evidence_id': evidence['evidence_id'],
                'details': evidence['event_data']
            })
            
            attack_progression.append(evidence['attack_type'])
        
        # Analyze attack pattern
        pattern_analysis = self._analyze_attack_pattern(attack_progression)
        
        # Generate incident summary
        incident_summary = {
            'ip': source_ip,
            'status': 'reconstructed',
            'time_window': f"{time_window} hours",
            'total_events': len(relevant_evidence),
            'attack_timeline': timeline,
            'attack_progression': attack_progression,
            'pattern_analysis': pattern_analysis,
            'reconstruction_time': datetime.now().isoformat()
        }
        
        return incident_summary
    
    def _analyze_attack_pattern(self, attack_progression: List[str]) -> Dict:
        """Analyze attack progression patterns"""
        if not attack_progression:
            return {'pattern_type': 'no_attacks'}
        
        # Check for known attack patterns
        if self._is_apt_pattern(attack_progression):
            return {
                'pattern_type': 'apt_campaign',
                'severity': 'CRITICAL',
                'description': 'Advanced Persistent Threat campaign detected',
                'stages': self._identify_apt_stages(attack_progression)
            }
        elif self._is_automated_pattern(attack_progression):
            return {
                'pattern_type': 'automated_attack',
                'severity': 'HIGH',
                'description': 'Automated attack tool detected',
                'indicators': ['repeated_attacks', 'short_intervals']
            }
        elif self._is_reconnaissance_pattern(attack_progression):
            return {
                'pattern_type': 'reconnaissance',
                'severity': 'MEDIUM',
                'description': 'Reconnaissance and information gathering',
                'phase': 'initial_discovery'
            }
        else:
            return {
                'pattern_type': 'opportunistic',
                'severity': 'LOW',
                'description': 'Opportunistic attack attempts',
                'characteristics': ['random_attacks', 'no_clear_progression']
            }
    
    def _is_apt_pattern(self, attacks: List[str]) -> bool:
        """Detect APT-like attack patterns"""
        apt_indicators = [
            'SSH_BRUTE_FORCE',
            'LATERAL_MOVEMENT', 
            'PRIVILEGE_ESCALATION',
            'DATA_EXFILTRATION'
        ]
        
        found_stages = sum(1 for attack in attacks if attack in apt_indicators)
        return found_stages >= 3
    
    def _is_automated_pattern(self, attacks: List[str]) -> bool:
        """Detect automated attack patterns"""
        if len(attacks) < 5:
            return False
        
        # Check for repetitive patterns
        unique_attacks = len(set(attacks))
        total_attacks = len(attacks)
        
        # If less than 30% unique attacks, likely automated
        return (unique_attacks / total_attacks) < 0.3
    
    def _is_reconnaissance_pattern(self, attacks: List[str]) -> bool:
        """Detect reconnaissance patterns"""
        recon_indicators = [
            'DIRECTORY_TRAVERSAL',
            'PORT_SCAN',
            'SERVICE_ENUMERATION',
            'VULNERABILITY_SCAN'
        ]
        
        return any(attack in recon_indicators for attack in attacks)
    
    def _identify_apt_stages(self, attacks: List[str]) -> List[str]:
        """Identify APT attack stages"""
        stages = []
        
        stage_mapping = {
            'SSH_BRUTE_FORCE': 'initial_access',
            'LATERAL_MOVEMENT': 'lateral_movement',
            'PRIVILEGE_ESCALATION': 'privilege_escalation',
            'DATA_EXFILTRATION': 'exfiltration',
            'COMMAND_INJECTION': 'execution',
            'REMOTE_CODE_EXECUTION': 'execution'
        }
        
        for attack in attacks:
            if attack in stage_mapping:
                stage = stage_mapping[attack]
                if stage not in stages:
                    stages.append(stage)
        
        return stages
    
    def generate_forensics_report(self, incident_id: str = None) -> Dict:
        """Generate comprehensive forensics report"""
        if incident_id and incident_id in self.incidents:
            # Generate report for specific incident
            return self._generate_incident_report(incident_id)
        else:
            # Generate summary report
            return self._generate_summary_report()
    
    def _generate_summary_report(self) -> Dict:
        """Generate summary forensics report"""
        total_evidence = len(self.evidence_chain)
        unique_ips = len(self.attack_chains)
        
        # Analyze evidence by attack type
        attack_type_counts = defaultdict(int)
        severity_counts = defaultdict(int)
        
        for evidence in self.evidence_chain:
            attack_type = evidence.get('attack_type', 'UNKNOWN')
            attack_type_counts[attack_type] += 1
            
            # Determine severity (simplified)
            if attack_type in ['REMOTE_CODE_EXECUTION', 'DATA_EXFILTRATION']:
                severity_counts['CRITICAL'] += 1
            elif attack_type in ['PRIVILEGE_ESCALATION', 'LATERAL_MOVEMENT']:
                severity_counts['HIGH'] += 1
            elif attack_type in ['SQL_INJECTION', 'COMMAND_INJECTION']:
                severity_counts['MEDIUM'] += 1
            else:
                severity_counts['LOW'] += 1
        
        # Get top attacking IPs
        ip_activity = {ip: len(chain) for ip, chain in self.attack_chains.items()}
        top_ips = sorted(ip_activity.items(), key=lambda x: x[1], reverse=True)[:10]
        
        return {
            'report_type': 'forensics_summary',
            'generation_time': datetime.now().isoformat(),
            'evidence_summary': {
                'total_evidence_items': total_evidence,
                'unique_source_ips': unique_ips,
                'attack_type_distribution': dict(attack_type_counts),
                'severity_distribution': dict(severity_counts)
            },
            'top_attacking_ips': [
                {'ip': ip, 'attack_count': count} for ip, count in top_ips
            ],
            'forensics_capabilities': {
                'evidence_collection': 'active',
                'incident_reconstruction': 'active',
                'pattern_analysis': 'active',
                'chain_of_custody': 'maintained'
            }
        }
    
    def get_evidence_for_ip(self, source_ip: str) -> List[Dict]:
        """Get all evidence for specific IP address"""
        if source_ip not in self.attack_chains:
            return []
        
        return [
            {
                'evidence_id': evidence['evidence_id'],
                'timestamp': evidence['timestamp'],
                'attack_type': evidence['attack_type'],
                'event_data': evidence['event_data']
            }
            for evidence in self.attack_chains[source_ip]
        ] 