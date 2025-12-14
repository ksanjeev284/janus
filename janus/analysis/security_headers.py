# janus/analysis/security_headers.py
"""
Security Headers Scanner Module.

Analyzes HTTP response headers for security best practices.
Checks for presence and proper configuration of:
- Content-Security-Policy (CSP)
- X-Content-Type-Options
- X-Frame-Options
- Strict-Transport-Security (HSTS)
- X-XSS-Protection
- Referrer-Policy
- Permissions-Policy
- And more...
"""

import requests
from dataclasses import dataclass, field, asdict
from typing import Dict, List, Any, Optional, Tuple
from datetime import datetime


@dataclass
class HeaderFinding:
    """A single security header finding."""
    header_name: str
    status: str  # MISSING, MISCONFIGURED, WARNING, SECURE
    severity: str  # CRITICAL, HIGH, MEDIUM, LOW, INFO
    current_value: Optional[str]
    recommendation: str
    description: str
    
    def to_dict(self) -> Dict:
        return asdict(self)


@dataclass
class SecurityHeadersReport:
    """Complete security headers analysis report."""
    url: str
    scan_time: str
    overall_grade: str  # A, B, C, D, F
    total_headers_checked: int
    secure_headers: int
    missing_headers: int
    misconfigured_headers: int
    findings: List[HeaderFinding] = field(default_factory=list)
    
    def to_dict(self) -> Dict:
        return {
            **asdict(self),
            'findings': [f.to_dict() for f in self.findings]
        }


class SecurityHeadersScanner:
    """
    Security Headers Scanner.
    
    Analyzes HTTP response headers for security best practices
    and provides recommendations for improvements.
    """
    
    # Required security headers with their importance
    SECURITY_HEADERS = {
        'Strict-Transport-Security': {
            'severity': 'HIGH',
            'description': 'Enforces HTTPS connections to prevent MITM attacks',
            'recommended': 'max-age=31536000; includeSubDomains; preload',
            'check': '_check_hsts'
        },
        'Content-Security-Policy': {
            'severity': 'HIGH', 
            'description': 'Prevents XSS, clickjacking, and code injection attacks',
            'recommended': "default-src 'self'; script-src 'self'; style-src 'self'",
            'check': '_check_csp'
        },
        'X-Content-Type-Options': {
            'severity': 'MEDIUM',
            'description': 'Prevents MIME-type sniffing attacks',
            'recommended': 'nosniff',
            'check': '_check_xcto'
        },
        'X-Frame-Options': {
            'severity': 'MEDIUM',
            'description': 'Prevents clickjacking attacks by controlling framing',
            'recommended': 'DENY or SAMEORIGIN',
            'check': '_check_xfo'
        },
        'X-XSS-Protection': {
            'severity': 'LOW',
            'description': 'Legacy XSS filter (deprecated but still useful)',
            'recommended': '1; mode=block',
            'check': '_check_xxss'
        },
        'Referrer-Policy': {
            'severity': 'MEDIUM',
            'description': 'Controls information sent in Referer header',
            'recommended': 'strict-origin-when-cross-origin',
            'check': '_check_referrer'
        },
        'Permissions-Policy': {
            'severity': 'MEDIUM',
            'description': 'Controls browser features like camera, geolocation',
            'recommended': 'geolocation=(), camera=(), microphone=()',
            'check': '_check_permissions'
        },
        'Cache-Control': {
            'severity': 'LOW',
            'description': 'Controls caching of sensitive data',
            'recommended': 'no-store, no-cache, must-revalidate',
            'check': '_check_cache'
        },
        'X-Permitted-Cross-Domain-Policies': {
            'severity': 'LOW',
            'description': 'Restricts Adobe Flash/PDF cross-domain access',
            'recommended': 'none',
            'check': '_check_cross_domain'
        },
    }
    
    # Dangerous headers that should not be present
    DANGEROUS_HEADERS = {
        'Server': {
            'severity': 'LOW',
            'description': 'Reveals server software version (information disclosure)'
        },
        'X-Powered-By': {
            'severity': 'LOW',
            'description': 'Reveals framework/technology stack'
        },
        'X-AspNet-Version': {
            'severity': 'MEDIUM',
            'description': 'Reveals ASP.NET version'
        },
        'X-AspNetMvc-Version': {
            'severity': 'MEDIUM',
            'description': 'Reveals ASP.NET MVC version'
        },
    }
    
    def __init__(self, timeout: int = 10):
        self.timeout = timeout
    
    def scan(self, url: str, token: Optional[str] = None) -> SecurityHeadersReport:
        """
        Scan a URL for security headers.
        
        Args:
            url: Target URL to scan
            token: Optional authorization token
        
        Returns:
            SecurityHeadersReport with all findings
        """
        headers = {'Authorization': token} if token else {}
        
        try:
            response = requests.get(url, headers=headers, timeout=self.timeout, allow_redirects=True)
            response_headers = dict(response.headers)
        except Exception as e:
            return SecurityHeadersReport(
                url=url,
                scan_time=datetime.now().isoformat(),
                overall_grade='F',
                total_headers_checked=0,
                secure_headers=0,
                missing_headers=0,
                misconfigured_headers=0,
                findings=[HeaderFinding(
                    header_name='Connection',
                    status='ERROR',
                    severity='CRITICAL',
                    current_value=None,
                    recommendation='Fix connection issues',
                    description=f'Could not connect: {str(e)}'
                )]
            )
        
        findings = []
        secure_count = 0
        missing_count = 0
        misconfigured_count = 0
        
        # Check required security headers
        for header_name, config in self.SECURITY_HEADERS.items():
            header_value = self._get_header_case_insensitive(response_headers, header_name)
            
            if header_value is None:
                findings.append(HeaderFinding(
                    header_name=header_name,
                    status='MISSING',
                    severity=config['severity'],
                    current_value=None,
                    recommendation=f"Add header: {header_name}: {config['recommended']}",
                    description=config['description']
                ))
                missing_count += 1
            else:
                # Run specific check for this header
                check_method = getattr(self, config['check'], None)
                if check_method:
                    is_secure, message = check_method(header_value)
                    if is_secure:
                        findings.append(HeaderFinding(
                            header_name=header_name,
                            status='SECURE',
                            severity='INFO',
                            current_value=header_value,
                            recommendation='',
                            description=config['description']
                        ))
                        secure_count += 1
                    else:
                        findings.append(HeaderFinding(
                            header_name=header_name,
                            status='MISCONFIGURED',
                            severity=config['severity'],
                            current_value=header_value,
                            recommendation=message,
                            description=config['description']
                        ))
                        misconfigured_count += 1
        
        # Check for dangerous headers
        for header_name, config in self.DANGEROUS_HEADERS.items():
            header_value = self._get_header_case_insensitive(response_headers, header_name)
            if header_value:
                findings.append(HeaderFinding(
                    header_name=header_name,
                    status='WARNING',
                    severity=config['severity'],
                    current_value=header_value,
                    recommendation=f"Consider removing {header_name} header to prevent information disclosure",
                    description=config['description']
                ))
        
        # Calculate grade
        grade = self._calculate_grade(secure_count, missing_count, misconfigured_count)
        
        return SecurityHeadersReport(
            url=url,
            scan_time=datetime.now().isoformat(),
            overall_grade=grade,
            total_headers_checked=len(self.SECURITY_HEADERS),
            secure_headers=secure_count,
            missing_headers=missing_count,
            misconfigured_headers=misconfigured_count,
            findings=findings
        )
    
    def _get_header_case_insensitive(self, headers: Dict, name: str) -> Optional[str]:
        """Get header value regardless of case."""
        for key, value in headers.items():
            if key.lower() == name.lower():
                return value
        return None
    
    def _check_hsts(self, value: str) -> Tuple[bool, str]:
        """Check Strict-Transport-Security header."""
        value_lower = value.lower()
        if 'max-age=' not in value_lower:
            return False, "Missing max-age directive"
        
        # Extract max-age value
        try:
            max_age = int(value_lower.split('max-age=')[1].split(';')[0].strip())
            if max_age < 31536000:  # Less than 1 year
                return False, f"max-age too short ({max_age}s). Recommended: 31536000 (1 year)"
        except:
            return False, "Invalid max-age value"
        
        if 'includesubdomains' not in value_lower:
            return False, "Consider adding includeSubDomains"
        
        return True, ""
    
    def _check_csp(self, value: str) -> Tuple[bool, str]:
        """Check Content-Security-Policy header."""
        value_lower = value.lower()
        
        issues = []
        if "'unsafe-inline'" in value_lower:
            issues.append("Contains unsafe-inline (XSS risk)")
        if "'unsafe-eval'" in value_lower:
            issues.append("Contains unsafe-eval (code injection risk)")
        if "default-src" not in value_lower and "script-src" not in value_lower:
            issues.append("Missing default-src or script-src directive")
        
        if issues:
            return False, "; ".join(issues)
        return True, ""
    
    def _check_xcto(self, value: str) -> Tuple[bool, str]:
        """Check X-Content-Type-Options header."""
        if value.lower().strip() == 'nosniff':
            return True, ""
        return False, "Should be 'nosniff'"
    
    def _check_xfo(self, value: str) -> Tuple[bool, str]:
        """Check X-Frame-Options header."""
        valid_values = ['deny', 'sameorigin']
        if value.lower().strip() in valid_values:
            return True, ""
        if 'allow-from' in value.lower():
            return False, "ALLOW-FROM is deprecated, use CSP frame-ancestors instead"
        return False, "Should be 'DENY' or 'SAMEORIGIN'"
    
    def _check_xxss(self, value: str) -> Tuple[bool, str]:
        """Check X-XSS-Protection header."""
        if '1' in value and 'mode=block' in value.lower():
            return True, ""
        if value.strip() == '0':
            return True, ""  # Disabled is actually recommended now
        return False, "Should be '1; mode=block' or '0' (disabled)"
    
    def _check_referrer(self, value: str) -> Tuple[bool, str]:
        """Check Referrer-Policy header."""
        secure_policies = [
            'no-referrer', 'no-referrer-when-downgrade',
            'strict-origin', 'strict-origin-when-cross-origin',
            'same-origin', 'origin', 'origin-when-cross-origin'
        ]
        if value.lower().strip() in secure_policies:
            return True, ""
        if value.lower().strip() == 'unsafe-url':
            return False, "unsafe-url exposes full URL to all origins"
        return False, f"Consider using: {', '.join(secure_policies[:3])}"
    
    def _check_permissions(self, value: str) -> Tuple[bool, str]:
        """Check Permissions-Policy header."""
        # Any permissions policy is generally good
        if len(value) > 0:
            return True, ""
        return False, "Empty permissions policy"
    
    def _check_cache(self, value: str) -> Tuple[bool, str]:
        """Check Cache-Control header for sensitive pages."""
        value_lower = value.lower()
        if 'no-store' in value_lower or 'private' in value_lower:
            return True, ""
        return False, "Consider 'no-store' for sensitive data"
    
    def _check_cross_domain(self, value: str) -> Tuple[bool, str]:
        """Check X-Permitted-Cross-Domain-Policies header."""
        if value.lower().strip() == 'none':
            return True, ""
        return False, "Should be 'none' for maximum security"
    
    def _calculate_grade(self, secure: int, missing: int, misconfigured: int) -> str:
        """Calculate overall security grade."""
        total = len(self.SECURITY_HEADERS)
        score = (secure / total) * 100
        
        # Deduct for missing critical headers
        if missing > 0:
            score -= missing * 10
        if misconfigured > 0:
            score -= misconfigured * 5
        
        if score >= 90:
            return 'A'
        elif score >= 80:
            return 'B'
        elif score >= 60:
            return 'C'
        elif score >= 40:
            return 'D'
        return 'F'
