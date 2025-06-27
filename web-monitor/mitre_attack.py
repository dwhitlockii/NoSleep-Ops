#!/usr/bin/env python3
"""
NoSleep-Ops MITRE ATT&CK Framework Integration
Professional threat intelligence mapping for attacks
"""

import json
from typing import Dict, List, Optional, Tuple
from datetime import datetime
import logging

class MITREAttackMapper:
    """Map attacks to MITRE ATT&CK framework tactics and techniques"""
    
    def __init__(self):
        self.attack_mappings = self._initialize_attack_mappings()
        self.tactics = self._initialize_tactics()
        self.techniques = self._initialize_techniques()
    
    def _initialize_tactics(self) -> Dict:
        """Initialize MITRE ATT&CK tactics"""
        return {
            'TA0001': {
                'name': 'Initial Access',
                'description': 'Techniques used to gain an initial foothold within a network',
                'color': '#FF6B6B'
            },
            'TA0002': {
                'name': 'Execution',
                'description': 'Techniques that result in adversary-controlled code running on a local or remote system',
                'color': '#4ECDC4'
            },
            'TA0003': {
                'name': 'Persistence',
                'description': 'Techniques that adversaries use to keep access to systems across restarts',
                'color': '#45B7D1'
            },
            'TA0004': {
                'name': 'Privilege Escalation',
                'description': 'Techniques that adversaries use to gain higher-level permissions',
                'color': '#96CEB4'
            },
            'TA0005': {
                'name': 'Defense Evasion',
                'description': 'Techniques that adversaries use to avoid detection',
                'color': '#FFEAA7'
            },
            'TA0006': {
                'name': 'Credential Access',
                'description': 'Techniques for stealing credentials like account names and passwords',
                'color': '#DDA0DD'
            },
            'TA0007': {
                'name': 'Discovery',
                'description': 'Techniques an adversary may use to gain knowledge about the system',
                'color': '#98D8C8'
            },
            'TA0008': {
                'name': 'Lateral Movement',
                'description': 'Techniques that adversaries use to enter and control remote systems',
                'color': '#F7DC6F'
            },
            'TA0009': {
                'name': 'Collection',
                'description': 'Techniques adversaries may use to gather information',
                'color': '#BB8FCE'
            },
            'TA0010': {
                'name': 'Exfiltration',
                'description': 'Techniques that adversaries may use to steal data',
                'color': '#F1948A'
            },
            'TA0011': {
                'name': 'Command and Control',
                'description': 'Techniques that adversaries may use to communicate with compromised systems',
                'color': '#85C1E9'
            },
            'TA0040': {
                'name': 'Impact',
                'description': 'Techniques that adversaries use to disrupt availability or compromise integrity',
                'color': '#F8C471'
            }
        }
    
    def _initialize_techniques(self) -> Dict:
        """Initialize MITRE ATT&CK techniques relevant to our attacks"""
        return {
            'T1110': {
                'name': 'Brute Force',
                'description': 'Adversaries may use brute force techniques to gain access to accounts',
                'tactic': 'TA0006',
                'subtechniques': {
                    'T1110.001': 'Password Guessing',
                    'T1110.002': 'Password Cracking',
                    'T1110.003': 'Password Spraying',
                    'T1110.004': 'Credential Stuffing'
                }
            },
            'T1078': {
                'name': 'Valid Accounts',
                'description': 'Adversaries may obtain and abuse credentials of existing accounts',
                'tactic': 'TA0001',
                'subtechniques': {
                    'T1078.001': 'Default Accounts',
                    'T1078.002': 'Domain Accounts',
                    'T1078.003': 'Local Accounts'
                }
            },
            'T1190': {
                'name': 'Exploit Public-Facing Application',
                'description': 'Adversaries may attempt to take advantage of a weakness in an Internet-facing computer',
                'tactic': 'TA0001',
                'subtechniques': {}
            },
            'T1059': {
                'name': 'Command and Scripting Interpreter',
                'description': 'Adversaries may abuse command and script interpreters to execute commands',
                'tactic': 'TA0002',
                'subtechniques': {
                    'T1059.001': 'PowerShell',
                    'T1059.002': 'AppleScript',
                    'T1059.003': 'Windows Command Shell',
                    'T1059.004': 'Unix Shell'
                }
            },
            'T1021': {
                'name': 'Remote Services',
                'description': 'Adversaries may use valid accounts to log into a service specifically designed to accept remote connections',
                'tactic': 'TA0008',
                'subtechniques': {
                    'T1021.001': 'Remote Desktop Protocol',
                    'T1021.002': 'SMB/Windows Admin Shares',
                    'T1021.004': 'SSH'
                }
            },
            'T1071': {
                'name': 'Application Layer Protocol',
                'description': 'Adversaries may communicate using application layer protocols',
                'tactic': 'TA0011',
                'subtechniques': {
                    'T1071.001': 'Web Protocols',
                    'T1071.002': 'File Transfer Protocols',
                    'T1071.003': 'Mail Protocols',
                    'T1071.004': 'DNS'
                }
            },
            'T1055': {
                'name': 'Process Injection',
                'description': 'Adversaries may inject code into processes in order to evade process-based defenses',
                'tactic': 'TA0005',
                'subtechniques': {}
            },
            'T1053': {
                'name': 'Scheduled Task/Job',
                'description': 'Adversaries may abuse task scheduling functionality to facilitate initial or recurring execution',
                'tactic': 'TA0003',
                'subtechniques': {
                    'T1053.003': 'Cron',
                    'T1053.005': 'Scheduled Task'
                }
            },
            'T1560': {
                'name': 'Archive Collected Data',
                'description': 'An adversary may compress and/or encrypt data that is collected prior to exfiltration',
                'tactic': 'TA0009',
                'subtechniques': {}
            },
            'T1041': {
                'name': 'Exfiltration Over C2 Channel',
                'description': 'Adversaries may steal data by exfiltrating it over an existing command and control channel',
                'tactic': 'TA0010',
                'subtechniques': {}
            }
        }
    
    def _initialize_attack_mappings(self) -> Dict:
        """Map our attack types to MITRE ATT&CK techniques"""
        return {
            'SSH_BRUTE_FORCE': {
                'technique': 'T1110.001',
                'tactic': 'TA0006',
                'confidence': 'HIGH'
            },
            'SSH_USER_ENUMERATION': {
                'technique': 'T1078',
                'tactic': 'TA0001',
                'confidence': 'MEDIUM'
            },
            'SSH_USER_ENUM': {
                'technique': 'T1078',
                'tactic': 'TA0001',
                'confidence': 'MEDIUM'
            },
            'SQL_INJECTION': {
                'technique': 'T1190',
                'tactic': 'TA0001',
                'confidence': 'HIGH'
            },
            'XSS_ATTEMPT': {
                'technique': 'T1190',
                'tactic': 'TA0001',
                'confidence': 'HIGH'
            },
            'DIRECTORY_TRAVERSAL': {
                'technique': 'T1190',
                'tactic': 'TA0001',
                'confidence': 'HIGH'
            },
            'COMMAND_INJECTION': {
                'technique': 'T1059.004',
                'tactic': 'TA0002',
                'confidence': 'HIGH'
            },
            'LATERAL_MOVEMENT': {
                'technique': 'T1021.002',
                'tactic': 'TA0008',
                'confidence': 'HIGH'
            },
            'PRIVILEGE_ESCALATION': {
                'technique': 'T1078.003',
                'tactic': 'TA0004',
                'confidence': 'HIGH'
            },
            'DATA_EXFILTRATION': {
                'technique': 'T1041',
                'tactic': 'TA0010',
                'confidence': 'HIGH'
            },
            'C2_COMMUNICATION': {
                'technique': 'T1071.001',
                'tactic': 'TA0011',
                'confidence': 'HIGH'
            },
            'C2_BEACON': {
                'technique': 'T1071.001',
                'tactic': 'TA0011',
                'confidence': 'HIGH'
            },
            'AUTOMATED_ATTACK': {
                'technique': 'T1190',
                'tactic': 'TA0001',
                'confidence': 'MEDIUM'
            }
        }
    
    def map_attack_to_mitre(self, attack_type: str) -> Optional[Dict]:
        """Map an attack type to MITRE ATT&CK framework"""
        mapping = self.attack_mappings.get(attack_type)
        if not mapping:
            return None
        
        technique_id = mapping['technique']
        tactic_id = mapping['tactic']
        
        technique = self.techniques.get(technique_id)
        tactic = self.tactics.get(tactic_id)
        
        if not technique or not tactic:
            return None
        
        return {
            'attack_type': attack_type,
            'technique': {
                'id': technique_id,
                'name': technique['name'],
                'description': technique['description'],
                'subtechniques': technique.get('subtechniques', {})
            },
            'tactic': {
                'id': tactic_id,
                'name': tactic['name'],
                'description': tactic['description'],
                'color': tactic['color']
            },
            'confidence': mapping['confidence'],
            'mitre_url': f'https://attack.mitre.org/techniques/{technique_id}/'
        }
    
    def get_attack_campaign_analysis(self, attacks: List[Dict]) -> Dict:
        """Analyze attack patterns and map to MITRE ATT&CK campaign"""
        campaign_analysis = {
            'tactics_used': {},
            'techniques_used': {},
            'attack_progression': [],
            'campaign_sophistication': 'LOW',
            'likely_threat_actor_type': 'Opportunistic',
            'mitre_coverage': 0.0
        }
        
        tactic_sequence = []
        
        for attack in attacks:
            mitre_mapping = self.map_attack_to_mitre(attack.get('attack_type', ''))
            if mitre_mapping:
                tactic = mitre_mapping['tactic']
                technique = mitre_mapping['technique']
                
                # Track tactics
                tactic_id = tactic['id']
                if tactic_id not in campaign_analysis['tactics_used']:
                    campaign_analysis['tactics_used'][tactic_id] = {
                        'name': tactic['name'],
                        'color': tactic['color'],
                        'count': 0,
                        'techniques': []
                    }
                campaign_analysis['tactics_used'][tactic_id]['count'] += 1
                
                # Track techniques
                technique_id = technique['id']
                if technique_id not in campaign_analysis['techniques_used']:
                    campaign_analysis['techniques_used'][technique_id] = {
                        'name': technique['name'],
                        'tactic': tactic['name'],
                        'count': 0
                    }
                campaign_analysis['techniques_used'][technique_id]['count'] += 1
                
                # Track technique under tactic
                if technique_id not in campaign_analysis['tactics_used'][tactic_id]['techniques']:
                    campaign_analysis['tactics_used'][tactic_id]['techniques'].append(technique_id)
                
                tactic_sequence.append(tactic_id)
        
        # Analyze attack progression
        campaign_analysis['attack_progression'] = self._analyze_attack_progression(tactic_sequence)
        
        # Determine campaign sophistication
        campaign_analysis['campaign_sophistication'] = self._determine_sophistication(campaign_analysis)
        
        # Determine likely threat actor type
        campaign_analysis['likely_threat_actor_type'] = self._determine_threat_actor_type(campaign_analysis)
        
        # Calculate MITRE framework coverage
        total_tactics = len(self.tactics)
        tactics_used = len(campaign_analysis['tactics_used'])
        campaign_analysis['mitre_coverage'] = (tactics_used / total_tactics) * 100
        
        return campaign_analysis
    
    def _analyze_attack_progression(self, tactic_sequence: List[str]) -> List[Dict]:
        """Analyze the progression of attack tactics"""
        progression = []
        
        # Expected attack progression patterns
        typical_progression = [
            'TA0001',  # Initial Access
            'TA0002',  # Execution
            'TA0003',  # Persistence
            'TA0004',  # Privilege Escalation
            'TA0007',  # Discovery
            'TA0008',  # Lateral Movement
            'TA0009',  # Collection
            'TA0010',  # Exfiltration
            'TA0011'   # Command and Control
        ]
        
        unique_tactics = list(dict.fromkeys(tactic_sequence))  # Preserve order, remove duplicates
        
        for i, tactic_id in enumerate(unique_tactics):
            tactic = self.tactics.get(tactic_id)
            if tactic:
                progression.append({
                    'step': i + 1,
                    'tactic_id': tactic_id,
                    'tactic_name': tactic['name'],
                    'expected_order': tactic_id in typical_progression,
                    'order_position': typical_progression.index(tactic_id) if tactic_id in typical_progression else -1
                })
        
        return progression
    
    def _determine_sophistication(self, campaign_analysis: Dict) -> str:
        """Determine campaign sophistication level"""
        tactics_count = len(campaign_analysis['tactics_used'])
        techniques_count = len(campaign_analysis['techniques_used'])
        
        # Check for advanced tactics
        advanced_tactics = ['TA0005', 'TA0008', 'TA0010', 'TA0011']  # Defense Evasion, Lateral Movement, Exfiltration, C2
        advanced_count = sum(1 for tactic in advanced_tactics if tactic in campaign_analysis['tactics_used'])
        
        if tactics_count >= 6 and advanced_count >= 3:
            return 'HIGH'
        elif tactics_count >= 4 and advanced_count >= 2:
            return 'MEDIUM'
        else:
            return 'LOW'
    
    def _determine_threat_actor_type(self, campaign_analysis: Dict) -> str:
        """Determine likely threat actor type based on attack patterns"""
        tactics_used = campaign_analysis['tactics_used']
        sophistication = campaign_analysis['campaign_sophistication']
        
        # APT indicators
        if sophistication == 'HIGH' and 'TA0008' in tactics_used and 'TA0010' in tactics_used:
            return 'Advanced Persistent Threat (APT)'
        
        # Targeted attack indicators
        elif sophistication == 'MEDIUM' and len(tactics_used) >= 4:
            return 'Targeted Attack Group'
        
        # Ransomware indicators
        elif 'TA0040' in tactics_used:  # Impact
            return 'Ransomware Group'
        
        # Credential harvesting
        elif 'TA0006' in tactics_used and len(tactics_used) <= 3:
            return 'Credential Harvester'
        
        # Default
        else:
            return 'Opportunistic Attacker'
    
    def get_mitre_dashboard_data(self, attacks: List[Dict]) -> Dict:
        """Get MITRE ATT&CK data for dashboard visualization"""
        dashboard_data = {
            'tactics_heatmap': {},
            'techniques_list': [],
            'attack_timeline': [],
            'campaign_summary': {}
        }
        
        # Initialize tactics heatmap
        for tactic_id, tactic_info in self.tactics.items():
            dashboard_data['tactics_heatmap'][tactic_id] = {
                'name': tactic_info['name'],
                'color': tactic_info['color'],
                'attack_count': 0,
                'techniques': []
            }
        
        # Process attacks
        for attack in attacks:
            mitre_mapping = self.map_attack_to_mitre(attack.get('attack_type', ''))
            if mitre_mapping:
                tactic_id = mitre_mapping['tactic']['id']
                technique_id = mitre_mapping['technique']['id']
                
                # Update heatmap
                dashboard_data['tactics_heatmap'][tactic_id]['attack_count'] += 1
                if technique_id not in dashboard_data['tactics_heatmap'][tactic_id]['techniques']:
                    dashboard_data['tactics_heatmap'][tactic_id]['techniques'].append(technique_id)
                
                # Add to techniques list
                dashboard_data['techniques_list'].append({
                    'technique_id': technique_id,
                    'technique_name': mitre_mapping['technique']['name'],
                    'tactic_name': mitre_mapping['tactic']['name'],
                    'attack_type': attack.get('attack_type'),
                    'timestamp': attack.get('timestamp'),
                    'source_ip': attack.get('source_ip'),
                    'confidence': mitre_mapping['confidence']
                })
        
        # Get campaign analysis
        dashboard_data['campaign_summary'] = self.get_attack_campaign_analysis(attacks)
        
        return dashboard_data

# Initialize global MITRE mapper
mitre_mapper = MITREAttackMapper() 