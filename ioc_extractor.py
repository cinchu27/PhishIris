"""
PhishIris - IOC (Indicator of Compromise) Extractor
Extracts IPs, domains, emails, and hashes from email content
"""

import re
from typing import Dict, List, Set
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class IOCExtractor:
    """Extract Indicators of Compromise from email content"""
    
    def __init__(self):
        # Known safe domains to exclude
        self.safe_domains = {
            'google.com', 'microsoft.com', 'apple.com', 'amazon.com',
            'facebook.com', 'twitter.com', 'linkedin.com', 'github.com',
            'outlook.com', 'hotmail.com', 'gmail.com', 'yahoo.com',
            'live.com', 'office.com', 'office365.com', 'microsoftonline.com'
        }
        
        # Known safe TLDs for internal networks
        self.internal_tlds = {'.local', '.internal', '.lan', '.corp'}
    
    def extract_all(self, text: str, urls: List[Dict] = None) -> Dict[str, List[Dict]]:
        """Extract all IOCs from text"""
        iocs = {
            'ip_addresses': self._extract_ips(text),
            'domains': self._extract_domains(text),
            'urls': urls if urls else self._extract_urls(text),
            'email_addresses': self._extract_emails(text),
            'hashes': self._extract_hashes(text),
            'suspicious_keywords': self._extract_suspicious_keywords(text)
        }
        
        # Deduplicate and filter
        iocs['domains'] = self._filter_domains(iocs['domains'])
        
        return iocs
    
    def _extract_ips(self, text: str) -> List[Dict]:
        """Extract IPv4 and IPv6 addresses"""
        ips = []
        seen = set()
        
        # IPv4 pattern (excluding private/common false positives)
        ipv4_pattern = r'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b'
        
        matches = re.findall(ipv4_pattern, text)
        for ip in matches:
            if ip not in seen and not self._is_private_ip(ip):
                seen.add(ip)
                ips.append({
                    'value': ip,
                    'type': 'IPv4',
                    'reputation': None
                })
        
        return ips
    
    def _extract_domains(self, text: str) -> List[Dict]:
        """Extract domain names"""
        domains = []
        seen = set()
        
        # Domain pattern
        domain_pattern = r'\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}\b'
        
        matches = re.findall(domain_pattern, text)
        for domain in matches:
            domain_lower = domain.lower()
            if domain_lower not in seen:
                seen.add(domain_lower)
                domains.append({
                    'value': domain_lower,
                    'type': 'Domain',
                    'reputation': None,
                    'is_suspicious': self._is_domain_suspicious(domain_lower)
                })
        
        return domains
    
    def _extract_urls(self, text: str) -> List[Dict]:
        """Extract URLs"""
        urls = []
        seen = set()
        
        url_pattern = r'https?://[^\s<>"{}|\\^`\[\]]+'
        
        matches = re.findall(url_pattern, text, re.IGNORECASE)
        for url in matches:
            url = url.strip('.,;:\'"<>)]}')
            if url not in seen:
                seen.add(url)
                domain = self._extract_domain_from_url(url)
                urls.append({
                    'value': url,
                    'type': 'URL',
                    'domain': domain,
                    'reputation': None,
                    'is_suspicious': self._is_url_suspicious(url)
                })
        
        return urls
    
    def _extract_emails(self, text: str) -> List[Dict]:
        """Extract email addresses"""
        emails = []
        seen = set()
        
        email_pattern = r'\b[\w\.-]+@[\w\.-]+\.\w{2,}\b'
        
        matches = re.findall(email_pattern, text)
        for email in matches:
            email_lower = email.lower()
            if email_lower not in seen:
                seen.add(email_lower)
                emails.append({
                    'value': email_lower,
                    'type': 'Email',
                    'domain': email_lower.split('@')[1] if '@' in email_lower else None
                })
        
        return emails
    
    def _extract_hashes(self, text: str) -> List[Dict]:
        """Extract file hashes (MD5, SHA1, SHA256)"""
        hashes = []
        seen = set()
        
        hash_patterns = {
            'MD5': r'\b[a-fA-F0-9]{32}\b',
            'SHA1': r'\b[a-fA-F0-9]{40}\b',
            'SHA256': r'\b[a-fA-F0-9]{64}\b'
        }
        
        for hash_type, pattern in hash_patterns.items():
            matches = re.findall(pattern, text)
            for hash_val in matches:
                if hash_val.lower() not in seen:
                    seen.add(hash_val.lower())
                    hashes.append({
                        'value': hash_val.lower(),
                        'type': hash_type,
                        'reputation': None
                    })
        
        return hashes
    
    def _extract_suspicious_keywords(self, text: str) -> List[Dict]:
        """Extract suspicious keywords/phrases"""
        keywords = []
        
        suspicious_patterns = {
            'Urgency': [
                r'\burgent\b', r'\bimmediate\b', r'\bimmediately\b',
                r'\baction required\b', r'\bact now\b', r'\bexpires\b',
                r'\blimited time\b', r'\bdeadline\b'
            ],
            'Credential Harvesting': [
                r'\bverify\b', r'\bverification\b', r'\bconfirm\b',
                r'\bpassword\b', r'\bcredential\b', r'\blogin\b',
                r'\baccount\b', r'\bsecurity\b', r'\bupdate\b',
                r'\bvalidate\b', r'\bauthentication\b'
            ],
            'Threat': [
                r'\bsuspended\b', r'\bdisabled\b', r'\blocked\b',
                r'\bunauthorized\b', r'\bfraudulent\b', r'\bbreach\b',
                r'\bcompromised\b', r'\bunusual activity\b'
            ],
            'Financial': [
                r'\bwire transfer\b', r'\bpayment\b', r'\binvoice\b',
                r'\bbank\b', r'\bfinancial\b', r'\btransaction\b'
            ],
            'Action Required': [
                r'\bclick here\b', r'\bclick below\b', r'\bfollow this link\b',
                r'\bopen attachment\b', r'\bdownload\b', r'\benable macros\b'
            ]
        }
        
        text_lower = text.lower()
        
        for category, patterns in suspicious_patterns.items():
            for pattern in patterns:
                matches = re.finditer(pattern, text_lower)
                for match in matches:
                    keywords.append({
                        'keyword': match.group(),
                        'category': category,
                        'position': match.start()
                    })
        
        return keywords
    
    def _is_private_ip(self, ip: str) -> bool:
        """Check if IP is private/internal"""
        parts = [int(x) for x in ip.split('.')]
        
        # 10.0.0.0/8
        if parts[0] == 10:
            return True
        # 172.16.0.0/12
        if parts[0] == 172 and 16 <= parts[1] <= 31:
            return True
        # 192.168.0.0/16
        if parts[0] == 192 and parts[1] == 168:
            return True
        # 127.0.0.0/8 (localhost)
        if parts[0] == 127:
            return True
        # 169.254.0.0/16 (link-local)
        if parts[0] == 169 and parts[1] == 254:
            return True
        
        return False
    
    def _filter_domains(self, domains: List[Dict]) -> List[Dict]:
        """Filter out known safe domains"""
        filtered = []
        for domain in domains:
            domain_val = domain['value']
            # Check if it's a subdomain of a safe domain
            is_safe = any(
                domain_val == safe or domain_val.endswith('.' + safe)
                for safe in self.safe_domains
            )
            if not is_safe:
                filtered.append(domain)
        return filtered
    
    def _extract_domain_from_url(self, url: str) -> str:
        """Extract domain from URL"""
        match = re.search(r'https?://([^/:\s]+)', url)
        if match:
            return match.group(1).lower()
        return ''
    
    def _is_domain_suspicious(self, domain: str) -> bool:
        """Check if domain has suspicious characteristics"""
        suspicious_indicators = [
            r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$',  # IP as domain
            r'[0o][0o][0o]',  # Character substitution
            r'[1l][1l][1l]',
            r'login', r'verify', r'account', r'secure',
            r'-',  # Hyphenated (often typosquatting)
            r'\.tk$', r'\.ml$', r'\.ga$', r'\.cf$',  # Free TLDs
            r'\.ru$', r'\.cn$'  # High-risk TLDs
        ]
        
        for pattern in suspicious_indicators:
            if re.search(pattern, domain, re.IGNORECASE):
                # Check for false positives
                if domain in self.safe_domains:
                    return False
                return True
        return False
    
    def _is_url_suspicious(self, url: str) -> bool:
        """Check if URL is suspicious"""
        suspicious_indicators = [
            r'@\w+',  # Credentials in URL
            r'//[^/]*@',  # User:pass in URL
            r'\.\./',  # Directory traversal
            r'%[0-9a-fA-F]{2}',  # Excessive encoding
            r'javascript:',  # JavaScript protocol
            r'data:',  # Data URI
            r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}',  # IP address
            r'(login|verify|account|secure|update|confirm)',
            r'\.(tk|ml|ga|cf|ru|cn)/'
        ]
        
        url_lower = url.lower()
        for pattern in suspicious_indicators:
            if re.search(pattern, url_lower):
                return True
        return False
