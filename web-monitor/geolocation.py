#!/usr/bin/env python3
"""
NoSleep-Ops Geolocation Attack Mapping Module
Real-time IP geolocation for attack visualization
"""

import requests
import json
import time
from typing import Dict, List, Optional, Tuple
import sqlite3
from datetime import datetime, timedelta
import logging

class GeolocationMapper:
    """Real-time IP geolocation for attack mapping"""
    
    def __init__(self, db_path='data/attacks.db'):
        self.db_path = db_path
        self.cache = {}  # IP geolocation cache
        self.cache_expiry = 24 * 3600  # 24 hours
        self.api_calls_today = 0
        self.max_api_calls = 1000  # Daily limit
        
        # Free geolocation APIs (no key required)
        self.geo_apis = [
            'http://ip-api.com/json/',  # 1000 requests/month free
            'https://ipapi.co/',         # 1000 requests/day free
            'https://freegeoip.app/json/', # 15000 requests/hour free
        ]
        
        # Don't setup separate database - use existing one
        # self.setup_database()
        
    def setup_database(self):
        """Initialize geolocation cache database"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS ip_geolocation (
                    ip TEXT PRIMARY KEY,
                    country TEXT,
                    country_code TEXT,
                    region TEXT,
                    city TEXT,
                    latitude REAL,
                    longitude REAL,
                    isp TEXT,
                    org TEXT,
                    timezone TEXT,
                    cached_at TIMESTAMP,
                    threat_level TEXT DEFAULT 'UNKNOWN'
                )
            ''')
            
            conn.commit()
            conn.close()
            
        except Exception as e:
            logging.error(f"Error setting up geolocation database: {e}")
    
    def get_ip_location(self, ip: str) -> Optional[Dict]:
        """Get geolocation data for an IP address"""
        try:
            # Skip private/local IPs
            if self._is_private_ip(ip):
                return self._get_private_ip_location(ip)
            
            # Check cache first
            cached_location = self._get_cached_location(ip)
            if cached_location:
                return cached_location
            
            # Query external APIs
            location_data = self._query_geolocation_apis(ip)
            if location_data:
                self._cache_location(ip, location_data)
                return location_data
                
        except Exception as e:
            logging.error(f"Error getting location for IP {ip}: {e}")
        
        return None
    
    def _is_private_ip(self, ip: str) -> bool:
        """Check if IP is private/local"""
        private_ranges = [
            '127.', '10.', '172.16.', '172.17.', '172.18.', '172.19.',
            '172.20.', '172.21.', '172.22.', '172.23.', '172.24.',
            '172.25.', '172.26.', '172.27.', '172.28.', '172.29.',
            '172.30.', '172.31.', '192.168.'
        ]
        return any(ip.startswith(prefix) for prefix in private_ranges)
    
    def _get_private_ip_location(self, ip: str) -> Dict:
        """Get location data for private/local IPs"""
        if ip.startswith('127.'):
            return {
                'ip': ip,
                'country': 'Local',
                'country_code': 'LOCAL',
                'region': 'Localhost',
                'city': 'Local Machine',
                'latitude': 0.0,
                'longitude': 0.0,
                'isp': 'Local Network',
                'org': 'Internal',
                'timezone': 'Local',
                'threat_level': 'INTERNAL'
            }
        else:
            return {
                'ip': ip,
                'country': 'Private Network',
                'country_code': 'PRIV',
                'region': 'RFC1918',
                'city': 'Private Range',
                'latitude': 0.0,
                'longitude': 0.0,
                'isp': 'Private Network',
                'org': 'Internal Network',
                'timezone': 'Local',
                'threat_level': 'INTERNAL'
            }
    
    def _get_cached_location(self, ip: str) -> Optional[Dict]:
        """Get cached geolocation data"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute('''
                SELECT * FROM ip_geolocation 
                WHERE ip = ? AND cached_at > ?
            ''', (ip, datetime.now() - timedelta(seconds=self.cache_expiry)))
            
            row = cursor.fetchone()
            conn.close()
            
            if row:
                return {
                    'ip': row[0],
                    'country': row[1],
                    'country_code': row[2],
                    'region': row[3],
                    'city': row[4],
                    'latitude': row[5],
                    'longitude': row[6],
                    'isp': row[7],
                    'org': row[8],
                    'timezone': row[9],
                    'threat_level': row[11] or 'UNKNOWN'
                }
                
        except Exception as e:
            logging.error(f"Error getting cached location: {e}")
        
        return None
    
    def _query_geolocation_apis(self, ip: str) -> Optional[Dict]:
        """Query external geolocation APIs"""
        if self.api_calls_today >= self.max_api_calls:
            return None
        
        for api_url in self.geo_apis:
            try:
                if 'ip-api.com' in api_url:
                    response = requests.get(f"{api_url}{ip}", timeout=5)
                    if response.status_code == 200:
                        data = response.json()
                        if data.get('status') == 'success':
                            self.api_calls_today += 1
                            return {
                                'ip': ip,
                                'country': data.get('country', 'Unknown'),
                                'country_code': data.get('countryCode', 'XX'),
                                'region': data.get('regionName', 'Unknown'),
                                'city': data.get('city', 'Unknown'),
                                'latitude': float(data.get('lat', 0.0)),
                                'longitude': float(data.get('lon', 0.0)),
                                'isp': data.get('isp', 'Unknown'),
                                'org': data.get('org', 'Unknown'),
                                'timezone': data.get('timezone', 'Unknown'),
                                'threat_level': 'UNKNOWN'
                            }
                
                elif 'ipapi.co' in api_url:
                    response = requests.get(f"{api_url}{ip}/json/", timeout=5)
                    if response.status_code == 200:
                        data = response.json()
                        self.api_calls_today += 1
                        return {
                            'ip': ip,
                            'country': data.get('country_name', 'Unknown'),
                            'country_code': data.get('country', 'XX'),
                            'region': data.get('region', 'Unknown'),
                            'city': data.get('city', 'Unknown'),
                            'latitude': float(data.get('latitude', 0.0)),
                            'longitude': float(data.get('longitude', 0.0)),
                            'isp': data.get('org', 'Unknown'),
                            'org': data.get('org', 'Unknown'),
                            'timezone': data.get('timezone', 'Unknown'),
                            'threat_level': 'UNKNOWN'
                        }
                
            except Exception as e:
                logging.warning(f"Error querying {api_url}: {e}")
                continue
        
        return None
    
    def _cache_location(self, ip: str, location_data: Dict):
        """Cache geolocation data"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute('''
                INSERT OR REPLACE INTO ip_geolocation 
                (ip, country, country_code, region, city, latitude, longitude, 
                 isp, org, timezone, cached_at, threat_level)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                location_data['ip'],
                location_data['country'],
                location_data['country_code'],
                location_data['region'],
                location_data['city'],
                location_data['latitude'],
                location_data['longitude'],
                location_data['isp'],
                location_data['org'],
                location_data['timezone'],
                datetime.now(),
                location_data.get('threat_level', 'UNKNOWN')
            ))
            
            conn.commit()
            conn.close()
            
        except Exception as e:
            logging.error(f"Error caching location: {e}")
    
    def get_attack_map_data(self, hours_back: int = 24) -> List[Dict]:
        """Get attack data for map visualization"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            # Get recent attacks using the correct table schema
            cursor.execute('''
                SELECT source_ip, attack_type, target, severity, timestamp
                FROM attacks 
                WHERE timestamp > datetime('now', '-{} hours')
                ORDER BY timestamp DESC
            '''.format(hours_back))
            
            attacks = cursor.fetchall()
            conn.close()
            
            map_data = []
            ip_attack_counts = {}
            
            for attack in attacks:
                ip, attack_type, target, severity, timestamp = attack
                
                # Count attacks per IP
                if ip not in ip_attack_counts:
                    ip_attack_counts[ip] = {
                        'count': 0,
                        'types': set(),
                        'severity_levels': set(),
                        'latest_timestamp': timestamp
                    }
                
                ip_attack_counts[ip]['count'] += 1
                ip_attack_counts[ip]['types'].add(attack_type)
                ip_attack_counts[ip]['severity_levels'].add(severity)
                
                if timestamp > ip_attack_counts[ip]['latest_timestamp']:
                    ip_attack_counts[ip]['latest_timestamp'] = timestamp
            
            # Get geolocation for each attacking IP
            for ip, attack_info in ip_attack_counts.items():
                location = self.get_ip_location(ip)
                if location:
                    map_data.append({
                        'ip': ip,
                        'latitude': location['latitude'],
                        'longitude': location['longitude'],
                        'country': location['country'],
                        'city': location['city'],
                        'isp': location['isp'],
                        'attack_count': attack_info['count'],
                        'attack_types': list(attack_info['types']),
                        'severity_levels': list(attack_info['severity_levels']),
                        'latest_attack': attack_info['latest_timestamp'],
                        'threat_level': self._calculate_threat_level(attack_info)
                    })
            
            return map_data
            
        except Exception as e:
            logging.error(f"Error getting attack map data: {e}")
            return []
    
    def _calculate_threat_level(self, attack_info: Dict) -> str:
        """Calculate threat level based on attack patterns"""
        count = attack_info['count']
        severity_levels = attack_info['severity_levels']
        attack_types = attack_info['types']
        
        # High threat indicators
        if 'CRITICAL' in severity_levels or count > 10:
            return 'CRITICAL'
        elif 'HIGH' in severity_levels or count > 5:
            return 'HIGH'
        elif len(attack_types) > 3 or count > 2:
            return 'MEDIUM'
        else:
            return 'LOW'
    
    def get_global_attack_stats(self) -> Dict:
        """Get global attack statistics for dashboard"""
        try:
            map_data = self.get_attack_map_data(24)
            
            countries = {}
            total_attacks = 0
            threat_levels = {'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0}
            
            for attack in map_data:
                country = attack['country']
                if country not in countries:
                    countries[country] = {
                        'attack_count': 0,
                        'unique_ips': 0,
                        'cities': set()
                    }
                
                countries[country]['attack_count'] += attack['attack_count']
                countries[country]['unique_ips'] += 1
                countries[country]['cities'].add(attack['city'])
                
                total_attacks += attack['attack_count']
                threat_levels[attack['threat_level']] += 1
            
            # Convert sets to counts
            for country_data in countries.values():
                country_data['cities'] = len(country_data['cities'])
            
            return {
                'total_attacks': total_attacks,
                'countries_affected': len(countries),
                'unique_ips': len(map_data),
                'threat_distribution': threat_levels,
                'top_countries': dict(sorted(countries.items(), 
                                           key=lambda x: x[1]['attack_count'], 
                                           reverse=True)[:10])
            }
            
        except Exception as e:
            logging.error(f"Error getting global attack stats: {e}")
            return {}

# Initialize global geolocation mapper
geo_mapper = GeolocationMapper() 