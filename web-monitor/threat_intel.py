#!/usr/bin/env python3
"""
NoSleep-Ops Threat Intelligence Module
Integrates with multiple threat intelligence sources for IP reputation and threat analysis
"""

import requests
import json
import time
import hashlib
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Tuple
import logging

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class ThreatIntelligence:
    """Comprehensive threat intelligence integration"""
    
    def __init__(self, config: Optional[Dict] = None):
        self.config = config or {}
        self.cache = {}
        self.cache_ttl = 3600  # 1 hour cache
        
        # API endpoints
        self.virustotal_url = "https://www.virustotal.com/vtapi/v2/ip-address/report"
        self.abuseipdb_url = "https://api.abuseipdb.com/api/v2/check"
        self.shodan_url = "https://api.shodan.io/shodan/host"
        self.greynoise_url = "https://api.greynoise.io/v3/community"
        
        # Threat intelligence feeds (public)
        self.malware_ips = set()
        self.tor_exit_nodes = set()
        self.known_scanners = set()
        
        # Initialize threat feeds
        self.load_threat_feeds()
    
    def load_threat_feeds(self):
        """Load public threat intelligence feeds"""
        try:
            # Load known malicious IPs from public feeds
            malicious_ips = [
                "185.220.100.240", "185.220.100.241", "185.220.100.242",
                "192.42.116.16", "192.42.116.17", "192.42.116.18",
                "199.87.154.255", "199.87.154.254", "199.87.154.253"
            ]
            self.malware_ips.update(malicious_ips)
            
            # Load Tor exit nodes (sample)
            tor_nodes = [
                "199.87.154.255", "185.220.100.240", "192.42.116.16",
                "109.70.100.23", "185.220.101.1", "185.220.101.2"
            ]
            self.tor_exit_nodes.update(tor_nodes)
            
            # Load known scanners
            scanner_ips = [
                "162.142.125.0/24", "71.6.135.0/24", "71.6.146.0/24",
                "82.221.105.0/24", "89.248.165.0/24", "93.120.27.0/24"
            ]
            self.known_scanners.update(scanner_ips)
            
            logger.info(f"Loaded {len(self.malware_ips)} malicious IPs, {len(self.tor_exit_nodes)} Tor nodes")
            
        except Exception as e:
            logger.error(f"Error loading threat feeds: {e}")
    
    def get_ip_reputation(self, ip: str) -> Dict:
        """Get comprehensive IP reputation from multiple sources"""
        
        # Check cache first
        cache_key = f"ip_rep_{ip}"
        if cache_key in self.cache:
            cached_data, timestamp = self.cache[cache_key]
            if time.time() - timestamp < self.cache_ttl:
                return cached_data
        
        reputation = {
            'ip': ip,
            'timestamp': datetime.now().isoformat(),
            'reputation_score': 0,  # 0-100, higher = more malicious
            'threat_types': [],
            'sources': {},
            'is_malicious': False,
            'is_tor': False,
            'is_scanner': False,
            'country': 'Unknown',
            'asn': 'Unknown',
            'last_seen': None
        }
        
        try:
            # Check local threat feeds first (fast)
            reputation.update(self._check_local_feeds(ip))
            
            # Check public APIs if enabled
            if self.config.get('ENABLE_THREAT_INTEL', False):
                reputation.update(self._check_virustotal(ip))
                reputation.update(self._check_abuseipdb(ip))
                reputation.update(self._check_greynoise(ip))
            
            # Calculate overall reputation score
            reputation['reputation_score'] = self._calculate_reputation_score(reputation)
            reputation['is_malicious'] = reputation['reputation_score'] > 70
            
            # Cache the result
            self.cache[cache_key] = (reputation, time.time())
            
        except Exception as e:
            logger.error(f"Error getting IP reputation for {ip}: {e}")
            reputation['error'] = str(e)
        
        return reputation
    
    def _check_local_feeds(self, ip: str) -> Dict:
        """Check IP against local threat feeds"""
        result = {
            'sources': {},
            'threat_types': [],
            'is_tor': False,
            'is_scanner': False
        }
        
        # Check malicious IPs
        if ip in self.malware_ips:
            result['sources']['local_malware'] = {'malicious': True, 'confidence': 'high'}
            result['threat_types'].append('malware')
        
        # Check Tor exit nodes
        if ip in self.tor_exit_nodes:
            result['sources']['local_tor'] = {'is_tor': True, 'confidence': 'high'}
            result['threat_types'].append('tor_exit')
            result['is_tor'] = True
        
        # Check known scanners
        if ip in self.known_scanners:
            result['sources']['local_scanners'] = {'is_scanner': True, 'confidence': 'high'}
            result['threat_types'].append('scanner')
            result['is_scanner'] = True
        
        return result
    
    def _check_virustotal(self, ip: str) -> Dict:
        """Check IP reputation with VirusTotal"""
        result = {'sources': {}}
        
        try:
            api_key = self.config.get('VIRUSTOTAL_API_KEY')
            if not api_key:
                return result
            
            params = {
                'apikey': api_key,
                'ip': ip
            }
            
            response = requests.get(self.virustotal_url, params=params, timeout=10)
            if response.status_code == 200:
                data = response.json()
                if data.get('response_code') == 1:
                    result['sources']['virustotal'] = {
                        'detected_urls': data.get('detected_urls', []),
                        'detected_samples': data.get('detected_samples', []),
                        'country': data.get('country', 'Unknown'),
                        'asn': data.get('asn', 'Unknown')
                    }
                    
                    if data.get('detected_urls'):
                        if 'threat_types' not in result:
                            result['threat_types'] = []
                        result['threat_types'].append('malicious_urls')
                    
                    if data.get('detected_samples'):
                        if 'threat_types' not in result:
                            result['threat_types'] = []
                        result['threat_types'].append('malware_samples')
            
            time.sleep(0.25)  # Rate limiting
            
        except Exception as e:
            logger.error(f"VirusTotal API error for {ip}: {e}")
        
        return result
    
    def _check_abuseipdb(self, ip: str) -> Dict:
        """Check IP reputation with AbuseIPDB"""
        result = {'sources': {}}
        
        try:
            api_key = self.config.get('ABUSEIPDB_API_KEY')
            if not api_key:
                return result
            
            headers = {
                'Key': api_key,
                'Accept': 'application/json'
            }
            
            params = {
                'ipAddress': ip,
                'maxAgeInDays': 90,
                'verbose': ''
            }
            
            response = requests.get(self.abuseipdb_url, headers=headers, params=params, timeout=10)
            if response.status_code == 200:
                data = response.json()
                if 'data' in data:
                    abuse_data = data['data']
                    result['sources']['abuseipdb'] = {
                        'abuse_confidence': abuse_data.get('abuseConfidencePercentage', 0),
                        'total_reports': abuse_data.get('totalReports', 0),
                        'country_code': abuse_data.get('countryCode', 'Unknown'),
                        'is_public': abuse_data.get('isPublic', False),
                        'last_reported': abuse_data.get('lastReportedAt')
                    }
                    
                    if abuse_data.get('abuseConfidencePercentage', 0) > 50:
                        result['threat_types'] = result.get('threat_types', [])
                        result['threat_types'].append('reported_abuse')
            
            time.sleep(0.5)  # Rate limiting
            
        except Exception as e:
            logger.error(f"AbuseIPDB API error for {ip}: {e}")
        
        return result
    
    def _check_greynoise(self, ip: str) -> Dict:
        """Check IP with GreyNoise Community API"""
        result = {'sources': {}}
        
        try:
            api_key = self.config.get('GREYNOISE_API_KEY')
            headers = {}
            if api_key:
                headers['key'] = api_key
            
            url = f"{self.greynoise_url}/{ip}"
            response = requests.get(url, headers=headers, timeout=10)
            
            if response.status_code == 200:
                data = response.json()
                result['sources']['greynoise'] = {
                    'noise': data.get('noise', False),
                    'riot': data.get('riot', False),
                    'classification': data.get('classification', 'unknown'),
                    'last_seen': data.get('last_seen'),
                    'message': data.get('message', '')
                }
                
                if data.get('noise'):
                    result['threat_types'] = result.get('threat_types', [])
                    result['threat_types'].append('internet_noise')
            
            time.sleep(0.5)  # Rate limiting
            
        except Exception as e:
            logger.error(f"GreyNoise API error for {ip}: {e}")
        
        return result
    
    def _calculate_reputation_score(self, reputation: Dict) -> int:
        """Calculate overall reputation score (0-100)"""
        score = 0
        
        # Local threat feeds (high confidence)
        if 'malware' in reputation.get('threat_types', []):
            score += 40
        if 'tor_exit' in reputation.get('threat_types', []):
            score += 20
        if 'scanner' in reputation.get('threat_types', []):
            score += 15
        
        # VirusTotal
        vt_data = reputation.get('sources', {}).get('virustotal', {})
        if vt_data.get('detected_urls'):
            score += 25
        if vt_data.get('detected_samples'):
            score += 30
        
        # AbuseIPDB
        abuse_data = reputation.get('sources', {}).get('abuseipdb', {})
        abuse_confidence = abuse_data.get('abuse_confidence', 0)
        score += min(abuse_confidence // 2, 30)  # Max 30 points from abuse reports
        
        # GreyNoise
        gn_data = reputation.get('sources', {}).get('greynoise', {})
        if gn_data.get('noise'):
            score += 10
        if gn_data.get('classification') == 'malicious':
            score += 20
        
        return min(score, 100)
    
    def bulk_check_ips(self, ips: List[str]) -> Dict[str, Dict]:
        """Check multiple IPs efficiently"""
        results = {}
        
        for ip in ips:
            try:
                results[ip] = self.get_ip_reputation(ip)
                time.sleep(0.1)  # Small delay to avoid overwhelming APIs
            except Exception as e:
                logger.error(f"Error checking IP {ip}: {e}")
                results[ip] = {'error': str(e)}
        
        return results
    
    def get_threat_summary(self, ips: List[str]) -> Dict:
        """Get summary of threats for a list of IPs"""
        results = self.bulk_check_ips(ips)
        
        summary = {
            'total_ips': len(ips),
            'malicious_ips': 0,
            'tor_ips': 0,
            'scanner_ips': 0,
            'clean_ips': 0,
            'threat_types': {},
            'top_threats': [],
            'countries': {},
            'analysis_timestamp': datetime.now().isoformat()
        }
        
        for ip, data in results.items():
            if data.get('is_malicious'):
                summary['malicious_ips'] += 1
            elif data.get('reputation_score', 0) < 20:
                summary['clean_ips'] += 1
            
            if data.get('is_tor'):
                summary['tor_ips'] += 1
            
            if data.get('is_scanner'):
                summary['scanner_ips'] += 1
            
            # Count threat types
            for threat_type in data.get('threat_types', []):
                summary['threat_types'][threat_type] = summary['threat_types'].get(threat_type, 0) + 1
            
            # Count countries
            country = data.get('country', 'Unknown')
            summary['countries'][country] = summary['countries'].get(country, 0) + 1
            
            # Track top threats
            if data.get('reputation_score', 0) > 50:
                summary['top_threats'].append({
                    'ip': ip,
                    'score': data.get('reputation_score', 0),
                    'threats': data.get('threat_types', [])
                })
        
        # Sort top threats by score
        summary['top_threats'].sort(key=lambda x: x['score'], reverse=True)
        summary['top_threats'] = summary['top_threats'][:10]  # Top 10
        
        return summary

# Example usage and testing
if __name__ == "__main__":
    # Test with sample IPs
    config = {
        'ENABLE_THREAT_INTEL': True,
        'VIRUSTOTAL_API_KEY': 'your-api-key-here',
        'ABUSEIPDB_API_KEY': 'your-api-key-here'
    }
    
    ti = ThreatIntelligence(config)
    
    # Test IPs
    test_ips = [
        "8.8.8.8",  # Google DNS (clean)
        "185.220.100.240",  # Known malicious
        "192.42.116.16",  # Tor exit node
        "1.1.1.1"  # Cloudflare DNS (clean)
    ]
    
    print("🔍 Testing Threat Intelligence Module")
    print("=" * 50)
    
    for ip in test_ips:
        result = ti.get_ip_reputation(ip)
        print(f"\n📊 IP: {ip}")
        print(f"   Reputation Score: {result['reputation_score']}/100")
        print(f"   Malicious: {result['is_malicious']}")
        print(f"   Threat Types: {result['threat_types']}")
        print(f"   Sources: {list(result['sources'].keys())}")
    
    print(f"\n📈 Threat Summary:")
    summary = ti.get_threat_summary(test_ips)
    print(f"   Total IPs: {summary['total_ips']}")
    print(f"   Malicious: {summary['malicious_ips']}")
    print(f"   Clean: {summary['clean_ips']}")
    print(f"   Threat Types: {summary['threat_types']}") 