"""
PhishIris - Phishing Detection Engine
Rule-based detection with risk scoring
"""

import re
from typing import Dict, List, Tuple
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class PhishingDetector:
    """Advanced phishing detection engine"""
    
    # Risk score weights
    SCORE_WEIGHTS = {
        'spf_fail': 30,
        'dkim_fail': 30,
        'dmarc_fail': 30,
        'sender_mismatch': 25,
        'urgency_keywords': 20,
        'suspicious_link': 20,
        'suspicious_domain': 20,
        'credential_harvesting': 25,
        'bec_indicator': 30,
        'attachment_risk': 15,
        'reply_to_mismatch': 20
    }
    
    # Urgency keywords
    URGENCY_KEYWORDS = [
        'urgent', 'immediate', 'immediately', 'action required',
        'act now', 'expires', 'limited time', 'deadline',
        'within 24 hours', 'within 48 hours', 'last chance',
        'final notice', 'important', 'critical', 'asap'
    ]
    
    # Credential harvesting keywords
    CREDENTIAL_KEYWORDS = [
        'verify', 'verification', 'confirm', 'password',
        'credential', 'login', 'account', 'security',
        'update', 'validate', 'authentication', 'reset',
        'unlock', 'suspended', 'locked', 'disabled'
    ]
    
    # BEC indicators
    BEC_KEYWORDS = [
        'wire transfer', 'payment', 'invoice', 'urgent payment',
        'ceo', 'executive', 'confidential', 'transaction',
        'bank details', 'account number', 'swift code'
    ]
    
    # Suspicious TLDs
    SUSPICIOUS_TLDS = [
        '.tk', '.ml', '.ga', '.cf', '.gq',  # Free TLDs
        '.ru', '.cn', '.pk', '.ir'  # High-risk TLDs
    ]
    
    def __init__(self):
        self.total_score = 0
        self.detections = []
        self.indicators = {
            'spf': None,
            'dkim': None,
            'dmarc': None,
            'sender_mismatch': False,
            'urgency_detected': False,
            'suspicious_links': False,
            'suspicious_domains': False,
            'credential_harvesting': False,
            'bec_indicators': False
        }
    
    def analyze(self, email_data: Dict, iocs: Dict) -> Dict:
        """Perform comprehensive phishing analysis"""
        self.total_score = 0
        self.detections = []
        
        # Check authentication
        self._check_authentication(email_data)
        
        # Check sender mismatch
        self._check_sender_mismatch(email_data)
        
        # Check content for urgency
        self._check_urgency(email_data.get('body', ''))
        
        # Check for credential harvesting
        self._check_credential_harvesting(email_data.get('body', ''))
        
        # Check for BEC indicators
        self._check_bec_indicators(email_data)
        
        # Check URLs and domains
        self._check_urls_domains(iocs)
        
        # Determine risk level and classification
        risk_level = self._calculate_risk_level()
        attack_type = self._classify_attack()
        confidence = self._calculate_confidence()
        
        return {
            'score': self.total_score,
            'risk_level': risk_level,
            'attack_type': attack_type,
            'confidence': confidence,
            'detections': self.detections,
            'indicators': self.indicators,
            'recommendations': self._generate_recommendations()
        }
    
    def _check_authentication(self, email_data: Dict):
        """Check SPF, DKIM, DMARC authentication"""
        # SPF Check
        spf = email_data.get('spf')
        if spf is None:
            self.indicators['spf'] = 'unknown'
            self.detections.append({
                'type': 'SPF',
                'status': 'unknown',
                'message': 'SPF record not found',
                'score': 10
            })
            self.total_score += 10
        elif spf in ['fail', 'softfail', 'neutral']:
            self.indicators['spf'] = 'fail'
            self.detections.append({
                'type': 'SPF',
                'status': 'fail',
                'message': f'SPF {spf} - Email sender not authorized',
                'score': self.SCORE_WEIGHTS['spf_fail']
            })
            self.total_score += self.SCORE_WEIGHTS['spf_fail']
        else:
            self.indicators['spf'] = 'pass'
            self.detections.append({
                'type': 'SPF',
                'status': 'pass',
                'message': 'SPF validation passed',
                'score': 0
            })
        
        # DKIM Check
        dkim = email_data.get('dkim')
        if dkim is None:
            self.indicators['dkim'] = 'unknown'
            self.detections.append({
                'type': 'DKIM',
                'status': 'unknown',
                'message': 'DKIM signature not found',
                'score': 10
            })
            self.total_score += 10
        elif dkim in ['fail', 'neutral', 'none', 'temperror', 'permerror']:
            self.indicators['dkim'] = 'fail'
            self.detections.append({
                'type': 'DKIM',
                'status': 'fail',
                'message': f'DKIM {dkim} - Signature verification failed',
                'score': self.SCORE_WEIGHTS['dkim_fail']
            })
            self.total_score += self.SCORE_WEIGHTS['dkim_fail']
        else:
            self.indicators['dkim'] = 'pass'
            self.detections.append({
                'type': 'DKIM',
                'status': 'pass',
                'message': 'DKIM signature verified',
                'score': 0
            })
        
        # DMARC Check
        dmarc = email_data.get('dmarc')
        if dmarc is None:
            self.indicators['dmarc'] = 'unknown'
            self.detections.append({
                'type': 'DMARC',
                'status': 'unknown',
                'message': 'DMARC policy not found',
                'score': 10
            })
            self.total_score += 10
        elif dmarc in ['fail', 'none']:
            self.indicators['dmarc'] = 'fail'
            self.detections.append({
                'type': 'DMARC',
                'status': 'fail',
                'message': f'DMARC {dmarc} - Email policy not satisfied',
                'score': self.SCORE_WEIGHTS['dmarc_fail']
            })
            self.total_score += self.SCORE_WEIGHTS['dmarc_fail']
        else:
            self.indicators['dmarc'] = 'pass'
            self.detections.append({
                'type': 'DMARC',
                'status': 'pass',
                'message': 'DMARC policy passed',
                'score': 0
            })
    
    def _check_sender_mismatch(self, email_data: Dict):
        """Check for sender/reply-to mismatch"""
        sender = email_data.get('sender', '')
        reply_to = email_data.get('reply_to', '')
        
        if reply_to and sender:
            if sender != reply_to:
                self.indicators['sender_mismatch'] = True
                self.detections.append({
                    'type': 'Sender Mismatch',
                    'status': 'warning',
                    'message': f'Reply-To ({reply_to}) differs from From ({sender})',
                    'score': self.SCORE_WEIGHTS['sender_mismatch']
                })
                self.total_score += self.SCORE_WEIGHTS['sender_mismatch']
    
    def _check_urgency(self, body: str):
        """Check for urgency keywords"""
        if not body:
            return
        
        body_lower = body.lower()
        found_keywords = []
        
        for keyword in self.URGENCY_KEYWORDS:
            if keyword in body_lower:
                found_keywords.append(keyword)
        
        if found_keywords:
            self.indicators['urgency_detected'] = True
            self.detections.append({
                'type': 'Urgency',
                'status': 'warning',
                'message': f'Urgency keywords detected: {", ".join(found_keywords[:5])}',
                'keywords': found_keywords,
                'score': self.SCORE_WEIGHTS['urgency_keywords']
            })
            self.total_score += self.SCORE_WEIGHTS['urgency_keywords']
    
    def _check_credential_harvesting(self, body: str):
        """Check for credential harvesting indicators"""
        if not body:
            return
        
        body_lower = body.lower()
        found_keywords = []
        
        for keyword in self.CREDENTIAL_KEYWORDS:
            if keyword in body_lower:
                found_keywords.append(keyword)
        
        # Check for credential harvesting patterns
        credential_patterns = [
            r'click.{0,20}(here|below|link)',
            r'verify.{0,20}(your|account)',
            r'(update|confirm).{0,20}(your|account|information)',
            r'(password|credential).{0,20}(expired|reset|update)',
            r'(account|access).{0,20}(suspended|locked|disabled)'
        ]
        
        pattern_matches = []
        for pattern in credential_patterns:
            if re.search(pattern, body_lower):
                pattern_matches.append(pattern)
        
        if found_keywords or pattern_matches:
            self.indicators['credential_harvesting'] = True
            self.detections.append({
                'type': 'Credential Harvesting',
                'status': 'warning',
                'message': 'Potential credential harvesting attempt detected',
                'keywords': found_keywords[:5],
                'score': self.SCORE_WEIGHTS['credential_harvesting']
            })
            self.total_score += self.SCORE_WEIGHTS['credential_harvesting']
    
    def _check_bec_indicators(self, email_data: Dict):
        """Check for Business Email Compromise indicators"""
        body = email_data.get('body', '').lower()
        headers = email_data.get('headers', {})
        
        found_indicators = []
        
        for keyword in self.BEC_KEYWORDS:
            if keyword in body:
                found_indicators.append(keyword)
        
        # Check for executive impersonation patterns
        subject = headers.get('Subject', '').lower()
        if any(word in subject for word in ['urgent', 'confidential', 'wire', 'transfer']):
            found_indicators.append('urgent_subject')
        
        if found_indicators:
            self.indicators['bec_indicators'] = True
            self.detections.append({
                'type': 'BEC',
                'status': 'warning',
                'message': 'Potential Business Email Compromise indicators detected',
                'indicators': found_indicators,
                'score': self.SCORE_WEIGHTS['bec_indicator']
            })
            self.total_score += self.SCORE_WEIGHTS['bec_indicator']
    
    def _check_urls_domains(self, iocs: Dict):
        """Check URLs and domains for suspicious characteristics"""
        urls = iocs.get('urls', [])
        domains = iocs.get('domains', [])
        
        suspicious_urls = []
        suspicious_domains = []
        
        # Check URLs
        for url in urls:
            if url.get('is_suspicious'):
                suspicious_urls.append(url.get('value') or url.get('url', ''))
        
        # Check domains
        for domain in domains:
            if domain.get('is_suspicious'):
                suspicious_domains.append(domain.get('value', ''))
        
        if suspicious_urls:
            self.indicators['suspicious_links'] = True
            self.detections.append({
                'type': 'Suspicious URLs',
                'status': 'warning',
                'message': f'{len(suspicious_urls)} suspicious URL(s) detected',
                'items': suspicious_urls[:5],
                'score': min(self.SCORE_WEIGHTS['suspicious_link'] * len(suspicious_urls), 40)
            })
            self.total_score += min(self.SCORE_WEIGHTS['suspicious_link'] * len(suspicious_urls), 40)
        
        if suspicious_domains:
            self.indicators['suspicious_domains'] = True
            self.detections.append({
                'type': 'Suspicious Domains',
                'status': 'warning',
                'message': f'{len(suspicious_domains)} suspicious domain(s) detected',
                'items': suspicious_domains[:5],
                'score': min(self.SCORE_WEIGHTS['suspicious_domain'] * len(suspicious_domains), 40)
            })
            self.total_score += min(self.SCORE_WEIGHTS['suspicious_domain'] * len(suspicious_domains), 40)
    
    def _calculate_risk_level(self) -> Dict:
        """Calculate risk level based on score"""
        if self.total_score >= 90:
            return {'level': 'Critical', 'color': '#ef4444', 'glow': '0 0 30px rgba(239, 68, 68, 0.6)'}
        elif self.total_score >= 60:
            return {'level': 'High', 'color': '#f97316', 'glow': '0 0 30px rgba(249, 115, 22, 0.6)'}
        elif self.total_score >= 30:
            return {'level': 'Medium', 'color': '#eab308', 'glow': '0 0 30px rgba(234, 179, 8, 0.6)'}
        else:
            return {'level': 'Low', 'color': '#22c55e', 'glow': '0 0 30px rgba(34, 197, 94, 0.6)'}
    
    def _classify_attack(self) -> str:
        """Classify the type of attack"""
        if self.indicators['bec_indicators']:
            return 'Business Email Compromise (BEC)'
        elif self.indicators['credential_harvesting']:
            return 'Credential Harvesting'
        elif self.indicators['suspicious_links']:
            return 'Malicious Link'
        elif self.indicators['sender_mismatch']:
            return 'Spoofing Attempt'
        elif self.total_score >= 30:
            return 'Suspicious Email'
        else:
            return 'No Threat Detected'
    
    def _calculate_confidence(self) -> int:
        """Calculate confidence score for the detection"""
        total_indicators = sum(1 for v in self.indicators.values() if v in [True, 'fail', 'unknown'])
        positive_indicators = sum(1 for v in self.indicators.values() if v in [True, 'fail'])
        
        if total_indicators == 0:
            return 50  # Neutral confidence
        
        # Base confidence on number of detections
        base_confidence = min(len(self.detections) * 10 + 40, 95)
        
        return base_confidence
    
    def _generate_recommendations(self) -> List[Dict]:
        """Generate actionable recommendations"""
        recommendations = []
        
        if self.total_score >= 60:
            recommendations.append({
                'priority': 'high',
                'action': 'Quarantine Email',
                'description': 'Move email to quarantine and do not deliver to user',
                'icon': 'fa-shield-alt'
            })
            recommendations.append({
                'priority': 'high',
                'action': 'Block Sender Domain',
                'description': 'Add sender domain to email gateway blocklist',
                'icon': 'fa-ban'
            })
        
        if self.indicators['suspicious_links'] or self.indicators['suspicious_domains']:
            recommendations.append({
                'priority': 'high',
                'action': 'Block Malicious URLs/Domains',
                'description': 'Add detected URLs/domains to proxy blocklist',
                'icon': 'fa-link-slash'
            })
        
        if self.indicators['credential_harvesting']:
            recommendations.append({
                'priority': 'medium',
                'action': 'Alert Users',
                'description': 'Send security awareness notification to targeted users',
                'icon': 'fa-bell'
            })
            recommendations.append({
                'priority': 'medium',
                'action': 'Monitor Credentials',
                'description': 'Monitor for credential reuse attempts',
                'icon': 'fa-eye'
            })
        
        if self.indicators['bec_indicators']:
            recommendations.append({
                'priority': 'critical',
                'action': 'Escalate to SOC',
                'description': 'Potential BEC attack - escalate immediately',
                'icon': 'fa-exclamation-triangle'
            })
            recommendations.append({
                'priority': 'high',
                'action': 'Verify with Sender',
                'description': 'Contact alleged sender through alternate channel',
                'icon': 'fa-phone'
            })
        
        if self.total_score >= 30:
            recommendations.append({
                'priority': 'low',
                'action': 'Report to SOC',
                'description': 'Submit email to security team for further analysis',
                'icon': 'fa-flag'
            })
        
        if not recommendations:
            recommendations.append({
                'priority': 'low',
                'action': 'Monitor',
                'description': 'No immediate action required - continue monitoring',
                'icon': 'fa-check-circle'
            })
        
        return recommendations
