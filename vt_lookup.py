"""
PhishIris - VirusTotal Integration
Threat intelligence lookup for IPs, domains, and URLs
"""

import requests
import hashlib
from typing import Dict, List, Optional
import logging
import time

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class VirusTotalLookup:
    """VirusTotal API integration for threat intelligence"""
    
    BASE_URL = "https://www.virustotal.com/api/v3"
    
    def __init__(self, api_key: str = None):
        self.api_key = api_key
        self.session = requests.Session()
        if api_key:
            self.session.headers.update({"x-apikey": api_key})
    
    def lookup_ip(self, ip: str) -> Dict:
        """Lookup IP address reputation"""
        if not self.api_key:
            return self._mock_ip_result(ip)
        
        try:
            url = f"{self.BASE_URL}/ip_addresses/{ip}"
            response = self.session.get(url)
            
            if response.status_code == 200:
                data = response.json()
                return self._parse_ip_response(data)
            else:
                logger.error(f"VT API error for IP {ip}: {response.status_code}")
                return {'error': 'API error', 'reputation': 'unknown'}
        except Exception as e:
            logger.error(f"Error looking up IP {ip}: {e}")
            return {'error': str(e), 'reputation': 'unknown'}
    
    def lookup_domain(self, domain: str) -> Dict:
        """Lookup domain reputation"""
        if not self.api_key:
            return self._mock_domain_result(domain)
        
        try:
            url = f"{self.BASE_URL}/domains/{domain}"
            response = self.session.get(url)
            
            if response.status_code == 200:
                data = response.json()
                return self._parse_domain_response(data)
            else:
                logger.error(f"VT API error for domain {domain}: {response.status_code}")
                return {'error': 'API error', 'reputation': 'unknown'}
        except Exception as e:
            logger.error(f"Error looking up domain {domain}: {e}")
            return {'error': str(e), 'reputation': 'unknown'}
    
    def lookup_url(self, url: str) -> Dict:
        """Lookup URL reputation"""
        if not self.api_key:
            return self._mock_url_result(url)
        
        try:
            # VT requires URL identifier (SHA-256 of URL)
            url_id = hashlib.sha256(url.encode()).hexdigest()
            api_url = f"{self.BASE_URL}/urls/{url_id}"
            response = self.session.get(api_url)
            
            if response.status_code == 200:
                data = response.json()
                return self._parse_url_response(data)
            else:
                logger.error(f"VT API error for URL: {response.status_code}")
                return {'error': 'API error', 'reputation': 'unknown'}
        except Exception as e:
            logger.error(f"Error looking up URL: {e}")
            return {'error': str(e), 'reputation': 'unknown'}
    
    def _parse_ip_response(self, data: Dict) -> Dict:
        """Parse IP lookup response"""
        try:
            attributes = data.get('data', {}).get('attributes', {})
            stats = attributes.get('last_analysis_stats', {})
            
            malicious = stats.get('malicious', 0)
            suspicious = stats.get('suspicious', 0)
            total = sum(stats.values()) if stats else 0
            
            if malicious >= 3:
                reputation = 'malicious'
            elif malicious >= 1 or suspicious >= 3:
                reputation = 'suspicious'
            else:
                reputation = 'clean'
            
            return {
                'reputation': reputation,
                'malicious_count': malicious,
                'suspicious_count': suspicious,
                'total_engines': total,
                'country': attributes.get('country', 'Unknown'),
                'asn': attributes.get('asn', 'Unknown'),
                'as_owner': attributes.get('as_owner', 'Unknown'),
                'threat_names': attributes.get('threat_names', [])[:5]
            }
        except Exception as e:
            logger.error(f"Error parsing IP response: {e}")
            return {'reputation': 'unknown'}
    
    def _parse_domain_response(self, data: Dict) -> Dict:
        """Parse domain lookup response"""
        try:
            attributes = data.get('data', {}).get('attributes', {})
            stats = attributes.get('last_analysis_stats', {})
            
            malicious = stats.get('malicious', 0)
            suspicious = stats.get('suspicious', 0)
            total = sum(stats.values()) if stats else 0
            
            if malicious >= 3:
                reputation = 'malicious'
            elif malicious >= 1 or suspicious >= 3:
                reputation = 'suspicious'
            else:
                reputation = 'clean'
            
            return {
                'reputation': reputation,
                'malicious_count': malicious,
                'suspicious_count': suspicious,
                'total_engines': total,
                'creation_date': attributes.get('creation_date'),
                'whois': attributes.get('whois', '')[:500],
                'threat_names': attributes.get('threat_names', [])[:5],
                'categories': attributes.get('categories', [])
            }
        except Exception as e:
            logger.error(f"Error parsing domain response: {e}")
            return {'reputation': 'unknown'}
    
    def _parse_url_response(self, data: Dict) -> Dict:
        """Parse URL lookup response"""
        try:
            attributes = data.get('data', {}).get('attributes', {})
            stats = attributes.get('last_analysis_stats', {})
            
            malicious = stats.get('malicious', 0)
            suspicious = stats.get('suspicious', 0)
            total = sum(stats.values()) if stats else 0
            
            if malicious >= 3:
                reputation = 'malicious'
            elif malicious >= 1 or suspicious >= 3:
                reputation = 'suspicious'
            else:
                reputation = 'clean'
            
            return {
                'reputation': reputation,
                'malicious_count': malicious,
                'suspicious_count': suspicious,
                'total_engines': total,
                'threat_names': attributes.get('threat_names', [])[:5]
            }
        except Exception as e:
            logger.error(f"Error parsing URL response: {e}")
            return {'reputation': 'unknown'}
    
    def enrich_iocs(self, iocs: Dict) -> Dict:
        """Enrich IOCs with threat intelligence"""
        enriched = iocs.copy()
        
        # Enrich IPs
        for ip in enriched.get('ip_addresses', []):
            result = self.lookup_ip(ip['value'])
            ip['reputation'] = result.get('reputation', 'unknown')
            ip['vt_data'] = result
            time.sleep(0.5)  # Rate limiting
        
        # Enrich domains
        for domain in enriched.get('domains', []):
            result = self.lookup_domain(domain['value'])
            domain['reputation'] = result.get('reputation', 'unknown')
            domain['vt_data'] = result
            time.sleep(0.5)
        
        # Enrich URLs
        for url in enriched.get('urls', []):
            result = self.lookup_url(url.get('value') or url.get('url', ''))
            url['reputation'] = result.get('reputation', 'unknown')
            url['vt_data'] = result
            time.sleep(0.5)
        
        return enriched
    
    # Mock methods for demo without API key
    def _mock_ip_result(self, ip: str) -> Dict:
        """Generate mock result for demo"""
        import random
        
        # Some IPs are more likely to be malicious
        suspicious_prefixes = ['185', '45', '91', '178']
        is_suspicious = any(ip.startswith(prefix) for prefix in suspicious_prefixes)
        
        if is_suspicious:
            malicious = random.randint(3, 15)
            suspicious = random.randint(2, 8)
            reputation = 'malicious' if malicious > 5 else 'suspicious'
        else:
            malicious = 0
            suspicious = random.randint(0, 2)
            reputation = 'clean'
        
        return {
            'reputation': reputation,
            'malicious_count': malicious,
            'suspicious_count': suspicious,
            'total_engines': 70,
            'country': 'Unknown',
            'asn': 'AS12345',
            'as_owner': 'Mock ISP',
            'threat_names': ['phishing', 'malware'] if reputation == 'malicious' else []
        }
    
    def _mock_domain_result(self, domain: str) -> Dict:
        """Generate mock domain result for demo"""
        import random
        
        # Check for suspicious TLDs
        suspicious_tlds = ['.tk', '.ml', '.ga', '.ru', '.cn']
        is_suspicious = any(domain.endswith(tld) for tld in suspicious_tlds)
        
        # Check for suspicious keywords
        suspicious_keywords = ['login', 'verify', 'secure', 'account', 'bank']
        has_suspicious_keyword = any(kw in domain.lower() for kw in suspicious_keywords)
        
        if is_suspicious or has_suspicious_keyword:
            malicious = random.randint(5, 20)
            suspicious = random.randint(3, 10)
            reputation = 'malicious' if malicious > 8 else 'suspicious'
        else:
            malicious = 0
            suspicious = random.randint(0, 2)
            reputation = 'clean'
        
        return {
            'reputation': reputation,
            'malicious_count': malicious,
            'suspicious_count': suspicious,
            'total_engines': 70,
            'threat_names': ['phishing'] if reputation in ['malicious', 'suspicious'] else [],
            'categories': ['phishing'] if reputation == 'malicious' else []
        }
    
    def _mock_url_result(self, url: str) -> Dict:
        """Generate mock URL result for demo"""
        import random
        
        suspicious_indicators = ['login', 'verify', 'account', 'secure', 'update']
        is_suspicious = any(ind in url.lower() for ind in suspicious_indicators)
        
        if is_suspicious:
            malicious = random.randint(5, 18)
            suspicious = random.randint(3, 10)
            reputation = 'malicious' if malicious > 6 else 'suspicious'
        else:
            malicious = 0
            suspicious = random.randint(0, 2)
            reputation = 'clean'
        
        return {
            'reputation': reputation,
            'malicious_count': malicious,
            'suspicious_count': suspicious,
            'total_engines': 70,
            'threat_names': ['phishing', 'malware'] if reputation == 'malicious' else []
        }
