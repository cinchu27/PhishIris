"""
PhishIris - Email Parser Module
Extracts headers, body, and URLs from raw email content
"""

import re
import email
from email import policy
from email.parser import BytesParser
from typing import Dict, List, Optional, Tuple
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class EmailParser:
    """Advanced email parser for phishing analysis"""
    
    def __init__(self):
        self.headers_of_interest = [
            'From', 'Reply-To', 'To', 'Cc', 'Bcc',
            'Subject', 'Date', 'Message-ID',
            'Received', 'Return-Path',
            'X-Spam-Status', 'X-Spam-Score',
            'Authentication-Results'
        ]
    
    def parse_raw_email(self, raw_content: bytes) -> Dict:
        """Parse raw email content (bytes)"""
        try:
            if isinstance(raw_content, str):
                raw_content = raw_content.encode('utf-8', errors='ignore')
            
            msg = BytesParser(policy=policy.default).parsebytes(raw_content)
            return self._extract_email_data(msg)
        except Exception as e:
            logger.error(f"Error parsing email: {e}")
            # Fallback to text parsing
            return self._parse_text_email(raw_content.decode('utf-8', errors='ignore'))
    
    def parse_text_email(self, text_content: str) -> Dict:
        """Parse email from text format"""
        try:
            if isinstance(text_content, bytes):
                text_content = text_content.decode('utf-8', errors='ignore')
            msg = email.message_from_string(text_content)
            return self._extract_email_data(msg)
        except Exception as e:
            logger.error(f"Error parsing text email: {e}")
            return self._parse_text_email(text_content)
    
    def _extract_email_data(self, msg) -> Dict:
        """Extract all relevant data from parsed message"""
        email_data = {
            'headers': {},
            'body': '',
            'html_body': '',
            'urls': [],
            'attachments': [],
            'spf': None,
            'dkim': None,
            'dmarc': None
        }
        
        # Extract headers
        for header in self.headers_of_interest:
            value = msg.get(header, '')
            if value:
                email_data['headers'][header] = str(value)
        
        # Parse authentication results
        auth_results = msg.get('Authentication-Results', '')
        if auth_results:
            email_data['spf'] = self._parse_spf(auth_results)
            email_data['dkim'] = self._parse_dkim(auth_results)
            email_data['dmarc'] = self._parse_dmarc(auth_results)
        
        # Extract body
        email_data['body'], email_data['html_body'] = self._extract_body(msg)
        
        # Extract URLs from body
        email_data['urls'] = self._extract_urls(email_data['body'] + ' ' + email_data['html_body'])
        
        # Extract sender info
        email_data['sender'] = self._extract_email_address(email_data['headers'].get('From', ''))
        email_data['reply_to'] = self._extract_email_address(email_data['headers'].get('Reply-To', ''))
        
        # Check for sender mismatch
        if email_data['reply_to'] and email_data['sender']:
            email_data['sender_mismatch'] = email_data['sender'] != email_data['reply_to']
        else:
            email_data['sender_mismatch'] = False
        
        return email_data
    
    def _parse_text_email(self, text: str) -> Dict:
        """Fallback parser for non-standard email formats"""
        email_data = {
            'headers': {},
            'body': text,
            'html_body': '',
            'urls': [],
            'attachments': [],
            'spf': None,
            'dkim': None,
            'dmarc': None,
            'sender': None,
            'reply_to': None,
            'sender_mismatch': False
        }
        
        # Try to extract basic headers
        header_patterns = {
            'From': r'From:\s*(.+)',
            'To': r'To:\s*(.+)',
            'Subject': r'Subject:\s*(.+)',
            'Reply-To': r'Reply-To:\s*(.+)',
            'Date': r'Date:\s*(.+)'
        }
        
        for header, pattern in header_patterns.items():
            match = re.search(pattern, text, re.IGNORECASE | re.MULTILINE)
            if match:
                email_data['headers'][header] = match.group(1).strip()
        
        # Extract sender info
        email_data['sender'] = self._extract_email_address(email_data['headers'].get('From', ''))
        email_data['reply_to'] = self._extract_email_address(email_data['headers'].get('Reply-To', ''))
        
        if email_data['reply_to'] and email_data['sender']:
            email_data['sender_mismatch'] = email_data['sender'] != email_data['reply_to']
        
        # Extract URLs
        email_data['urls'] = self._extract_urls(text)
        
        return email_data
    
    def _extract_body(self, msg) -> Tuple[str, str]:
        """Extract plain text and HTML body"""
        plain_body = ''
        html_body = ''
        
        if msg.is_multipart():
            for part in msg.walk():
                content_type = part.get_content_type()
                content_disposition = str(part.get('Content-Disposition', ''))
                
                if 'attachment' in content_disposition:
                    continue
                
                try:
                    payload = part.get_payload(decode=True)
                    if payload:
                        text = payload.decode('utf-8', errors='ignore')
                        if content_type == 'text/plain':
                            plain_body += text
                        elif content_type == 'text/html':
                            html_body += text
                except Exception:
                    continue
        else:
            try:
                payload = msg.get_payload(decode=True)
                if payload:
                    plain_body = payload.decode('utf-8', errors='ignore')
            except Exception:
                plain_body = str(msg.get_payload())
        
        return plain_body, html_body
    
    def _extract_urls(self, text: str) -> List[Dict]:
        """Extract URLs from text"""
        urls = []
        
        # URL patterns
        url_patterns = [
            r'https?://[^\s<>"{}|\\^`\[\]]+',
            r'www\.[^\s<>"{}|\\^`\[\]]+',
            r'\b(?:click|here|link)\s*[:=]?\s*(https?://[^\s]+)'
        ]
        
        seen = set()
        for pattern in url_patterns:
            matches = re.findall(pattern, text, re.IGNORECASE)
            for match in matches:
                url = match if isinstance(match, str) else match[0]
                url = url.strip('.,;:\'"<>)]}')
                if url and url not in seen:
                    seen.add(url)
                    urls.append({
                        'url': url,
                        'domain': self._extract_domain(url),
                        'suspicious': self._is_suspicious_url(url)
                    })
        
        return urls
    
    def _extract_domain(self, url: str) -> str:
        """Extract domain from URL"""
        try:
            domain_match = re.search(r'https?://([^/:\s]+)', url)
            if domain_match:
                return domain_match.group(1).lower()
            domain_match = re.search(r'www\.([^/:\s]+)', url)
            if domain_match:
                return domain_match.group(1).lower()
        except Exception:
            pass
        return ''
    
    def _is_suspicious_url(self, url: str) -> bool:
        """Check if URL has suspicious characteristics"""
        suspicious_indicators = [
            r'\.ru/', r'\.cn/', r'\.tk/', r'\.ml/', r'\.ga/',
            r'login', r'verify', r'account', r'secure', r'update',
            r'confirm', r'password', r'banking', r'paypal',
            r'amazon', r'apple', r'microsoft', r'google',
            r'[^\w]bit\.ly', r'[^\w]tinyurl', r'[^\w]goo\.gl',
            r'@\w+',  # URL with @
            r'//[^/]*@',  # Credentials in URL
            r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}'  # IP address
        ]
        
        url_lower = url.lower()
        for pattern in suspicious_indicators:
            if re.search(pattern, url_lower):
                return True
        return False
    
    def _extract_email_address(self, header_value: str) -> Optional[str]:
        """Extract email address from header value"""
        if not header_value:
            return None
        
        # Try to extract email from "Name <email>" format
        match = re.search(r'<([^>]+)>', header_value)
        if match:
            return match.group(1).lower()
        
        # Try direct email format
        match = re.search(r'[\w\.-]+@[\w\.-]+\.\w+', header_value)
        if match:
            return match.group(0).lower()
        
        return None
    
    def _parse_spf(self, auth_results: str) -> Optional[str]:
        """Parse SPF result from authentication results"""
        match = re.search(r'spf=(\w+)', auth_results, re.IGNORECASE)
        if match:
            return match.group(1).lower()
        return None
    
    def _parse_dkim(self, auth_results: str) -> Optional[str]:
        """Parse DKIM result from authentication results"""
        match = re.search(r'dkim=(\w+)', auth_results, re.IGNORECASE)
        if match:
            return match.group(1).lower()
        return None
    
    def _parse_dmarc(self, auth_results: str) -> Optional[str]:
        """Parse DMARC result from authentication results"""
        match = re.search(r'dmarc=(\w+)', auth_results, re.IGNORECASE)
        if match:
            return match.group(1).lower()
        return None
