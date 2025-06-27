#!/usr/bin/env python3
"""
NoSleep-Ops Security Reporting Module
Professional security analytics and report generation
"""

import json
import sqlite3
from datetime import datetime, timedelta
from collections import defaultdict, Counter
from typing import Dict, List, Optional, Tuple
import logging

logger = logging.getLogger(__name__)

class SecurityReporter:
    """Professional security reporting and analytics"""
    
    def __init__(self, db_path: str = 'attack_monitor.db'):
        self.db_path = db_path
    
    def get_attack_trends(self, days: int = 7) -> Dict:
        """Get attack trends over specified days"""
        end_date = datetime.now()
        start_date = end_date - timedelta(days=days)
        
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # Get attacks by day
        cursor.execute('''
            SELECT DATE(timestamp) as date, COUNT(*) as count, attack_type
            FROM attacks 
            WHERE timestamp >= ? AND timestamp <= ?
            GROUP BY DATE(timestamp), attack_type
            ORDER BY date DESC
        ''', (start_date.isoformat(), end_date.isoformat()))
        
        results = cursor.fetchall()
        conn.close()
        
        # Process results
        trends = {
            'period': f'{days} days',
            'start_date': start_date.isoformat(),
            'end_date': end_date.isoformat(),
            'daily_totals': defaultdict(int),
            'attack_types_by_day': defaultdict(lambda: defaultdict(int)),
            'total_attacks': 0
        }
        
        for date, count, attack_type in results:
            trends['daily_totals'][date] += count
            trends['attack_types_by_day'][date][attack_type] += count
            trends['total_attacks'] += count
        
        return dict(trends)
    
    def get_top_attackers(self, limit: int = 10, days: int = 7) -> List[Dict]:
        """Get top attacking IPs with detailed analysis"""
        end_date = datetime.now()
        start_date = end_date - timedelta(days=days)
        
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            SELECT source_ip, COUNT(*) as attack_count, 
                   GROUP_CONCAT(DISTINCT attack_type) as attack_types,
                   MIN(timestamp) as first_seen,
                   MAX(timestamp) as last_seen,
                   GROUP_CONCAT(DISTINCT severity) as severities
            FROM attacks 
            WHERE timestamp >= ? AND timestamp <= ?
            GROUP BY source_ip
            ORDER BY attack_count DESC
            LIMIT ?
        ''', (start_date.isoformat(), end_date.isoformat(), limit))
        
        results = cursor.fetchall()
        conn.close()
        
        attackers = []
        for row in results:
            ip, count, types, first, last, severities = row
            attackers.append({
                'ip': ip,
                'attack_count': count,
                'attack_types': types.split(',') if types else [],
                'first_seen': first,
                'last_seen': last,
                'severities': list(set(severities.split(',') if severities else [])),
                'duration_hours': self._calculate_duration_hours(first, last)
            })
        
        return attackers
    
    def get_attack_patterns(self, days: int = 7) -> Dict:
        """Analyze attack patterns and behaviors"""
        end_date = datetime.now()
        start_date = end_date - timedelta(days=days)
        
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # Get all attacks in the period
        cursor.execute('''
            SELECT source_ip, attack_type, timestamp, severity, details
            FROM attacks 
            WHERE timestamp >= ? AND timestamp <= ?
            ORDER BY timestamp
        ''', (start_date.isoformat(), end_date.isoformat()))
        
        attacks = cursor.fetchall()
        conn.close()
        
        patterns = {
            'analysis_period': f'{days} days',
            'total_attacks': len(attacks),
            'unique_ips': len(set(attack[0] for attack in attacks)),
            'attack_type_distribution': Counter(),
            'severity_distribution': Counter(),
            'hourly_distribution': defaultdict(int),
            'multi_vector_attackers': [],
            'persistent_attackers': [],
            'attack_sequences': []
        }
        
        # Analyze patterns
        ip_attacks = defaultdict(list)
        
        for ip, attack_type, timestamp, severity, details in attacks:
            patterns['attack_type_distribution'][attack_type] += 1
            patterns['severity_distribution'][severity] += 1
            
            # Hour of day analysis
            hour = datetime.fromisoformat(timestamp).hour
            patterns['hourly_distribution'][hour] += 1
            
            # Group by IP for sequence analysis
            ip_attacks[ip].append({
                'type': attack_type,
                'time': timestamp,
                'severity': severity,
                'details': details
            })
        
        # Find multi-vector attackers (using multiple attack types)
        for ip, attacks_list in ip_attacks.items():
            attack_types = set(attack['type'] for attack in attacks_list)
            if len(attack_types) > 2:
                patterns['multi_vector_attackers'].append({
                    'ip': ip,
                    'attack_types': list(attack_types),
                    'total_attacks': len(attacks_list),
                    'type_count': len(attack_types)
                })
        
        # Find persistent attackers (attacking over multiple days)
        for ip, attacks_list in ip_attacks.items():
            dates = set(datetime.fromisoformat(attack['time']).date() for attack in attacks_list)
            if len(dates) > 1 and len(attacks_list) > 10:
                patterns['persistent_attackers'].append({
                    'ip': ip,
                    'attack_days': len(dates),
                    'total_attacks': len(attacks_list),
                    'avg_attacks_per_day': len(attacks_list) / len(dates)
                })
        
        # Convert defaultdicts to regular dicts for JSON serialization
        patterns['attack_type_distribution'] = dict(patterns['attack_type_distribution'])
        patterns['severity_distribution'] = dict(patterns['severity_distribution'])
        patterns['hourly_distribution'] = dict(patterns['hourly_distribution'])
        
        return patterns
    
    def get_defense_effectiveness(self, days: int = 7) -> Dict:
        """Analyze defense action effectiveness"""
        end_date = datetime.now()
        start_date = end_date - timedelta(days=days)
        
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # Get defense actions
        cursor.execute('''
            SELECT action_type, COUNT(*) as count, effectiveness,
                   AVG(CASE WHEN effectiveness = 'SUCCESS' THEN 1 ELSE 0 END) as success_rate
            FROM defenses 
            WHERE timestamp >= ? AND timestamp <= ?
            GROUP BY action_type, effectiveness
        ''', (start_date.isoformat(), end_date.isoformat()))
        
        defense_data = cursor.fetchall()
        
        # Get attacks vs defenses timeline
        cursor.execute('''
            SELECT DATE(timestamp) as date, 'attack' as type, COUNT(*) as count
            FROM attacks 
            WHERE timestamp >= ? AND timestamp <= ?
            GROUP BY DATE(timestamp)
            UNION ALL
            SELECT DATE(timestamp) as date, 'defense' as type, COUNT(*) as count
            FROM defenses 
            WHERE timestamp >= ? AND timestamp <= ?
            GROUP BY DATE(timestamp)
            ORDER BY date
        ''', (start_date.isoformat(), end_date.isoformat(), 
              start_date.isoformat(), end_date.isoformat()))
        
        timeline_data = cursor.fetchall()
        conn.close()
        
        effectiveness = {
            'analysis_period': f'{days} days',
            'defense_actions': defaultdict(lambda: {'count': 0, 'success_rate': 0}),
            'timeline': defaultdict(lambda: {'attacks': 0, 'defenses': 0}),
            'overall_stats': {
                'total_defenses': 0,
                'successful_defenses': 0,
                'overall_success_rate': 0
            }
        }
        
        # Process defense effectiveness
        total_defenses = 0
        successful_defenses = 0
        
        for action_type, count, eff, success_rate in defense_data:
            effectiveness['defense_actions'][action_type]['count'] += count
            effectiveness['defense_actions'][action_type]['success_rate'] = success_rate
            total_defenses += count
            if eff == 'SUCCESS':
                successful_defenses += count
        
        # Process timeline
        for date, data_type, count in timeline_data:
            effectiveness['timeline'][date][f'{data_type}s'] = count
        
        effectiveness['overall_stats'] = {
            'total_defenses': total_defenses,
            'successful_defenses': successful_defenses,
            'overall_success_rate': (successful_defenses / total_defenses * 100) if total_defenses > 0 else 0
        }
        
        # Convert defaultdicts for JSON serialization
        effectiveness['defense_actions'] = dict(effectiveness['defense_actions'])
        effectiveness['timeline'] = dict(effectiveness['timeline'])
        
        return effectiveness
    
    def generate_executive_summary(self, days: int = 7) -> Dict:
        """Generate executive-level security summary"""
        end_date = datetime.now()
        start_date = end_date - timedelta(days=days)
        
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # Get basic stats
        cursor.execute('''
            SELECT COUNT(*) as total_attacks,
                   COUNT(DISTINCT source_ip) as unique_ips,
                   attack_type,
                   COUNT(*) as type_count
            FROM attacks 
            WHERE timestamp >= ? AND timestamp <= ?
            GROUP BY attack_type
            ORDER BY type_count DESC
        ''', (start_date.isoformat(), end_date.isoformat()))
        
        attack_data = cursor.fetchall()
        conn.close()
        
        total_attacks = sum(row[3] for row in attack_data) if attack_data else 0
        unique_ips = attack_data[0][1] if attack_data else 0
        
        risk_level = self._calculate_risk_level(total_attacks, unique_ips, 0)
        
        summary = {
            'report_generated': datetime.now().isoformat(),
            'analysis_period': f'{days} days',
            'key_metrics': {
                'total_attacks': total_attacks,
                'unique_attackers': unique_ips,
                'attacks_per_day': total_attacks / days if days > 0 else 0
            },
            'risk_assessment': {
                'overall_risk_level': risk_level,
                'recommendations': self._generate_recommendations(risk_level, attack_data)
            },
            'attack_summary': {
                'most_common_attack': attack_data[0][2] if attack_data else 'None',
                'attack_distribution': {row[2]: row[3] for row in attack_data}
            }
        }
        
        return summary
    
    def _calculate_duration_hours(self, first: str, last: str) -> float:
        """Calculate duration between first and last attack in hours"""
        try:
            first_dt = datetime.fromisoformat(first)
            last_dt = datetime.fromisoformat(last)
            return (last_dt - first_dt).total_seconds() / 3600
        except:
            return 0.0
    
    def _calculate_risk_level(self, total_attacks: int, unique_ips: int, multi_vector: int) -> str:
        """Calculate overall risk level"""
        score = 0
        
        if total_attacks > 100:
            score += 3
        elif total_attacks > 50:
            score += 2
        elif total_attacks > 20:
            score += 1
        
        if unique_ips > 20:
            score += 3
        elif unique_ips > 10:
            score += 2
        elif unique_ips > 5:
            score += 1
        
        if score >= 7:
            return 'CRITICAL'
        elif score >= 5:
            return 'HIGH'
        elif score >= 3:
            return 'MEDIUM'
        else:
            return 'LOW'
    
    def _generate_recommendations(self, risk_level: str, attack_data: List) -> List[str]:
        """Generate security recommendations"""
        recommendations = []
        
        if risk_level in ['CRITICAL', 'HIGH']:
            recommendations.append("Implement immediate IP blocking for top attackers")
            recommendations.append("Review and strengthen authentication mechanisms")
        
        # Check for specific attack types
        attack_types = {row[2]: row[3] for row in attack_data}
        
        if attack_types.get('SSH_BRUTE_FORCE', 0) > 10:
            recommendations.append("Implement SSH key-based authentication")
        
        if attack_types.get('SQL_INJECTION', 0) > 5:
            recommendations.append("Review web application security and input validation")
        
        return recommendations

# Example usage
if __name__ == "__main__":
    reporter = SecurityReporter()
    
    print("🔍 Generating Security Reports")
    print("=" * 50)
    
    # Generate executive summary
    summary = reporter.generate_executive_summary(7)
    
    print(f"\n📊 Executive Summary (7 days)")
    print(f"Risk Level: {summary['risk_assessment']['overall_risk_level']}")
    print(f"Total Attacks: {summary['key_metrics']['total_attacks']}")
    print(f"Unique Attackers: {summary['key_metrics']['unique_attackers']}")
    print(f"Defense Success Rate: {summary['defense_summary']['defense_success_rate']:.1f}%")
    
    if summary['risk_assessment']['recommendations']:
        print(f"\n🎯 Top Recommendations:")
        for rec in summary['risk_assessment']['recommendations'][:3]:
            print(f"  • {rec}") 