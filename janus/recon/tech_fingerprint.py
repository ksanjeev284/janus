# janus/recon/tech_fingerprint.py
"""
Technology Fingerprinting Module.

Identifies web technologies, frameworks, and servers used by target.
Useful for vulnerability research and attack surface mapping.
"""

import requests
import re
from dataclasses import dataclass, field, asdict
from typing import Dict, List, Any, Optional, Set
from datetime import datetime


@dataclass
class TechFinding:
    """A detected technology."""
    name: str
    category: str  # server, framework, language, cms, cdn, analytics
    version: Optional[str]
    confidence: str  # high, medium, low
    evidence: str
    
    def to_dict(self) -> Dict:
        return asdict(self)


@dataclass
class TechFingerprintReport:
    """Technology fingerprint report."""
    target_url: str
    scan_time: str
    technologies: List[TechFinding] = field(default_factory=list)
    
    def to_dict(self) -> Dict:
        return {
            **asdict(self),
            'technologies': [t.to_dict() for t in self.technologies]
        }


class TechFingerprinter:
    """
    Technology Fingerprinter.
    
    Detects:
    - Web servers (Apache, Nginx, IIS)
    - Languages (PHP, Python, Ruby, Node.js)
    - Frameworks (Django, Flask, Express, Laravel, Rails)
    - CMS (WordPress, Drupal, Joomla)
    - CDN/WAF (Cloudflare, Akamai, AWS)
    - JavaScript libraries
    """
    
    # Header-based detection
    HEADER_SIGNATURES = {
        # Servers
        'server': {
            'apache': {'name': 'Apache', 'category': 'server'},
            'nginx': {'name': 'Nginx', 'category': 'server'},
            'microsoft-iis': {'name': 'IIS', 'category': 'server'},
            'cloudflare': {'name': 'Cloudflare', 'category': 'cdn'},
            'gunicorn': {'name': 'Gunicorn', 'category': 'server'},
            'uvicorn': {'name': 'Uvicorn', 'category': 'server'},
            'werkzeug': {'name': 'Werkzeug (Flask)', 'category': 'framework'},
        },
        'x-powered-by': {
            'php': {'name': 'PHP', 'category': 'language'},
            'asp.net': {'name': 'ASP.NET', 'category': 'framework'},
            'express': {'name': 'Express.js', 'category': 'framework'},
            'next.js': {'name': 'Next.js', 'category': 'framework'},
            'nuxt': {'name': 'Nuxt.js', 'category': 'framework'},
        },
        'x-aspnet-version': {
            '': {'name': 'ASP.NET', 'category': 'framework'},
        },
        'x-drupal-cache': {
            '': {'name': 'Drupal', 'category': 'cms'},
        },
        'x-generator': {
            'drupal': {'name': 'Drupal', 'category': 'cms'},
            'wordpress': {'name': 'WordPress', 'category': 'cms'},
            'joomla': {'name': 'Joomla', 'category': 'cms'},
        },
        'cf-ray': {
            '': {'name': 'Cloudflare', 'category': 'cdn'},
        },
        'x-amz-cf-id': {
            '': {'name': 'AWS CloudFront', 'category': 'cdn'},
        },
        'x-cache': {
            'cloudfront': {'name': 'AWS CloudFront', 'category': 'cdn'},
            'varnish': {'name': 'Varnish', 'category': 'cache'},
        },
    }
    
    # HTML/content-based detection
    CONTENT_SIGNATURES = [
        # CMS
        {'pattern': r'wp-content|wp-includes', 'name': 'WordPress', 'category': 'cms', 'confidence': 'high'},
        {'pattern': r'/sites/default/files|drupal', 'name': 'Drupal', 'category': 'cms', 'confidence': 'high'},
        {'pattern': r'joomla', 'name': 'Joomla', 'category': 'cms', 'confidence': 'medium'},
        {'pattern': r'magento|mage/', 'name': 'Magento', 'category': 'cms', 'confidence': 'high'},
        {'pattern': r'shopify', 'name': 'Shopify', 'category': 'cms', 'confidence': 'high'},
        
        # Frameworks
        {'pattern': r'__next|_next/static', 'name': 'Next.js', 'category': 'framework', 'confidence': 'high'},
        {'pattern': r'_nuxt/', 'name': 'Nuxt.js', 'category': 'framework', 'confidence': 'high'},
        {'pattern': r'ng-version|angular', 'name': 'Angular', 'category': 'framework', 'confidence': 'high'},
        {'pattern': r'react|__react', 'name': 'React', 'category': 'library', 'confidence': 'medium'},
        {'pattern': r'vue\.js|__vue', 'name': 'Vue.js', 'category': 'framework', 'confidence': 'medium'},
        {'pattern': r'laravel|csrf_token', 'name': 'Laravel', 'category': 'framework', 'confidence': 'medium'},
        {'pattern': r'rails|csrf-token.*authenticity', 'name': 'Ruby on Rails', 'category': 'framework', 'confidence': 'medium'},
        {'pattern': r'django|csrfmiddlewaretoken', 'name': 'Django', 'category': 'framework', 'confidence': 'medium'},
        
        # JavaScript libraries
        {'pattern': r'jquery[-.\/]', 'name': 'jQuery', 'category': 'library', 'confidence': 'high'},
        {'pattern': r'bootstrap[-.\/]', 'name': 'Bootstrap', 'category': 'library', 'confidence': 'high'},
        {'pattern': r'tailwindcss|tailwind', 'name': 'Tailwind CSS', 'category': 'library', 'confidence': 'high'},
        
        # Analytics
        {'pattern': r'google-analytics|gtag|ga\.js', 'name': 'Google Analytics', 'category': 'analytics', 'confidence': 'high'},
        {'pattern': r'googletagmanager', 'name': 'Google Tag Manager', 'category': 'analytics', 'confidence': 'high'},
        {'pattern': r'facebook\.net|fbq\(', 'name': 'Facebook Pixel', 'category': 'analytics', 'confidence': 'high'},
        
        # Security
        {'pattern': r'recaptcha', 'name': 'reCAPTCHA', 'category': 'security', 'confidence': 'high'},
        {'pattern': r'cloudflare', 'name': 'Cloudflare', 'category': 'cdn', 'confidence': 'medium'},
    ]
    
    # Cookie-based detection
    COOKIE_SIGNATURES = {
        'PHPSESSID': {'name': 'PHP', 'category': 'language'},
        'JSESSIONID': {'name': 'Java', 'category': 'language'},
        'ASP.NET_SessionId': {'name': 'ASP.NET', 'category': 'framework'},
        'rack.session': {'name': 'Ruby/Rack', 'category': 'framework'},
        'laravel_session': {'name': 'Laravel', 'category': 'framework'},
        'django': {'name': 'Django', 'category': 'framework'},
        'express': {'name': 'Express.js', 'category': 'framework'},
        '__cf_bm': {'name': 'Cloudflare', 'category': 'cdn'},
        'wp-settings': {'name': 'WordPress', 'category': 'cms'},
    }
    
    def __init__(self, timeout: int = 10):
        self.timeout = timeout
    
    def fingerprint(
        self,
        url: str,
        token: Optional[str] = None
    ) -> TechFingerprintReport:
        """
        Fingerprint technologies used by target.
        
        Args:
            url: Target URL
            token: Authorization token
        
        Returns:
            TechFingerprintReport
        """
        technologies: List[TechFinding] = []
        seen: Set[str] = set()
        
        headers = {'Authorization': token} if token else {}
        
        try:
            response = requests.get(url, headers=headers, timeout=self.timeout)
            
            # Check response headers
            for header_name, signatures in self.HEADER_SIGNATURES.items():
                header_value = response.headers.get(header_name, '').lower()
                if header_value:
                    for sig_key, tech_info in signatures.items():
                        if sig_key == '' or sig_key in header_value:
                            if tech_info['name'] not in seen:
                                # Try to extract version
                                version = self._extract_version(header_value)
                                technologies.append(TechFinding(
                                    name=tech_info['name'],
                                    category=tech_info['category'],
                                    version=version,
                                    confidence='high',
                                    evidence=f"Header {header_name}: {header_value[:50]}"
                                ))
                                seen.add(tech_info['name'])
            
            # Check cookies
            for cookie_name in response.cookies.keys():
                for sig_name, tech_info in self.COOKIE_SIGNATURES.items():
                    if sig_name.lower() in cookie_name.lower():
                        if tech_info['name'] not in seen:
                            technologies.append(TechFinding(
                                name=tech_info['name'],
                                category=tech_info['category'],
                                version=None,
                                confidence='high',
                                evidence=f"Cookie: {cookie_name}"
                            ))
                            seen.add(tech_info['name'])
            
            # Check response content
            content = response.text.lower()
            for sig in self.CONTENT_SIGNATURES:
                if re.search(sig['pattern'], content, re.IGNORECASE):
                    if sig['name'] not in seen:
                        technologies.append(TechFinding(
                            name=sig['name'],
                            category=sig['category'],
                            version=None,
                            confidence=sig['confidence'],
                            evidence=f"Content pattern: {sig['pattern'][:30]}"
                        ))
                        seen.add(sig['name'])
                        
        except Exception as e:
            pass
        
        return TechFingerprintReport(
            target_url=url,
            scan_time=datetime.now().isoformat(),
            technologies=technologies
        )
    
    def _extract_version(self, header_value: str) -> Optional[str]:
        """Extract version number from header value."""
        # Common version patterns
        patterns = [
            r'(\d+\.\d+(?:\.\d+)?)',
            r'v(\d+(?:\.\d+)*)',
        ]
        
        for pattern in patterns:
            match = re.search(pattern, header_value)
            if match:
                return match.group(1)
        
        return None
    
    def quick_fingerprint(
        self,
        url: str,
        token: Optional[str] = None
    ) -> Dict[str, Any]:
        """Quick fingerprint with simplified output."""
        report = self.fingerprint(url, token)
        
        # Group by category
        by_category = {}
        for tech in report.technologies:
            if tech.category not in by_category:
                by_category[tech.category] = []
            version_str = f" ({tech.version})" if tech.version else ""
            by_category[tech.category].append(f"{tech.name}{version_str}")
        
        return {
            "url": url,
            "technologies_found": len(report.technologies),
            "by_category": by_category,
            "details": [t.to_dict() for t in report.technologies]
        }
