# janus/attack/open_redirect.py
"""
Open Redirect Detection Module.

Tests for open redirect vulnerabilities by injecting various payloads
into URL parameters that might control redirects.
"""

import requests
from dataclasses import dataclass, field, asdict
from typing import Dict, List, Any, Optional
from datetime import datetime
from urllib.parse import urlparse, urlencode, parse_qs, urlunparse


@dataclass
class RedirectFinding:
    """A single open redirect finding."""
    endpoint: str
    parameter: str
    payload: str
    vulnerable: bool
    severity: str
    redirect_location: Optional[str]
    evidence: str
    recommendation: str
    
    def to_dict(self) -> Dict:
        return asdict(self)


@dataclass
class OpenRedirectReport:
    """Complete open redirect scan report."""
    target_url: str
    scan_time: str
    vulnerable_params: int
    total_params_tested: int
    findings: List[RedirectFinding] = field(default_factory=list)
    
    def to_dict(self) -> Dict:
        return {
            **asdict(self),
            'findings': [f.to_dict() for f in self.findings]
        }


class OpenRedirectScanner:
    """
    Open Redirect Scanner.
    
    Tests for unvalidated redirects that could be abused for:
    - Phishing attacks
    - OAuth token theft
    - Bypassing security controls
    """
    
    # Common redirect parameter names
    REDIRECT_PARAMS = [
        'redirect', 'redirect_uri', 'redirect_url', 'redirectUrl', 'redirectUri',
        'return', 'return_to', 'returnTo', 'return_url', 'returnUrl',
        'next', 'next_url', 'nextUrl', 'url', 'goto', 'go', 'target',
        'dest', 'destination', 'redir', 'redirect_to', 'redirectTo',
        'out', 'view', 'login_url', 'logout', 'callback', 'callback_url',
        'forward', 'forward_url', 'success_url', 'success', 'fail_url',
        'link', 'site', 'continue', 'continue_url', 'ref', 'referrer'
    ]
    
    # Payloads for testing open redirects
    PAYLOADS = [
        # Basic external redirects
        'https://evil.com',
        'http://evil.com',
        '//evil.com',
        
        # Protocol-relative
        '//evil.com/path',
        '///evil.com',
        '////evil.com',
        
        # Backslash tricks
        '\\\\evil.com',
        '/\\evil.com',
        '\\/evil.com',
        
        # URL encoding bypasses
        '%2f%2fevil.com',
        '%2f%2f%2fevil.com',
        '%252f%252fevil.com',
        
        # @ symbol tricks
        'https://example.com@evil.com',
        'https://evil.com?@example.com',
        'https://evil.com#@example.com',
        
        # Unicode/CRLF
        'https://evil.com%00',
        'https://evil.com%0d%0a',
        
        # Data URI
        'data:text/html,<script>alert(1)</script>',
        
        # JavaScript (rare but possible)
        'javascript:alert(1)',
    ]
    
    def __init__(self, timeout: int = 10, follow_redirects: bool = False):
        self.timeout = timeout
        self.follow_redirects = follow_redirects
    
    def scan_url(
        self, 
        url: str, 
        token: Optional[str] = None,
        custom_params: Optional[List[str]] = None
    ) -> OpenRedirectReport:
        """
        Scan a URL for open redirect vulnerabilities.
        
        Args:
            url: Target URL to test
            token: Optional authorization token
            custom_params: Custom parameter names to test
        
        Returns:
            OpenRedirectReport with findings
        """
        findings = []
        params_to_test = custom_params or self.REDIRECT_PARAMS
        
        headers = {'Authorization': token} if token else {}
        
        for param in params_to_test:
            for payload in self.PAYLOADS:
                result = self._test_payload(url, param, payload, headers)
                if result:
                    findings.append(result)
        
        vulnerable_count = len([f for f in findings if f.vulnerable])
        
        return OpenRedirectReport(
            target_url=url,
            scan_time=datetime.now().isoformat(),
            vulnerable_params=vulnerable_count,
            total_params_tested=len(params_to_test),
            findings=findings
        )
    
    def scan_endpoint(
        self,
        endpoint: str,
        param_name: str,
        token: Optional[str] = None
    ) -> List[RedirectFinding]:
        """
        Scan a specific endpoint and parameter for open redirects.
        
        Args:
            endpoint: Target endpoint URL
            param_name: Parameter name to test
            token: Optional authorization token
        
        Returns:
            List of findings for this parameter
        """
        findings = []
        headers = {'Authorization': token} if token else {}
        
        for payload in self.PAYLOADS:
            result = self._test_payload(endpoint, param_name, payload, headers)
            if result and result.vulnerable:
                findings.append(result)
        
        return findings
    
    def _test_payload(
        self,
        url: str,
        param: str,
        payload: str,
        headers: Dict
    ) -> Optional[RedirectFinding]:
        """Test a single payload for open redirect."""
        # Build test URL
        parsed = urlparse(url)
        query_dict = parse_qs(parsed.query)
        query_dict[param] = [payload]
        
        new_query = urlencode(query_dict, doseq=True)
        test_url = urlunparse((
            parsed.scheme, parsed.netloc, parsed.path,
            parsed.params, new_query, parsed.fragment
        ))
        
        try:
            response = requests.get(
                test_url,
                headers=headers,
                timeout=self.timeout,
                allow_redirects=self.follow_redirects
            )
            
            # Check for redirect
            location = response.headers.get('Location')
            
            # Check if redirect points to external domain
            is_vulnerable = False
            evidence = ""
            
            if response.status_code in [301, 302, 303, 307, 308]:
                if location:
                    if self._is_external_redirect(location, payload):
                        is_vulnerable = True
                        evidence = f"Redirect to external location: {location}"
            
            # Also check for meta refresh or JavaScript redirects
            if not is_vulnerable and 'evil.com' in response.text.lower():
                is_vulnerable = True
                evidence = "Payload reflected in response body (potential JS/meta redirect)"
            
            if is_vulnerable:
                return RedirectFinding(
                    endpoint=url,
                    parameter=param,
                    payload=payload,
                    vulnerable=True,
                    severity='MEDIUM',
                    redirect_location=location,
                    evidence=evidence,
                    recommendation="Validate redirect destinations against an allowlist of trusted URLs"
                )
            
        except Exception as e:
            pass
        
        return None
    
    def _is_external_redirect(self, location: str, payload: str) -> bool:
        """Check if redirect location points to external domain."""
        if not location:
            return False
        
        # Check for evil.com in any form
        if 'evil.com' in location.lower():
            return True
        
        # Check if location matches any part of the payload
        payload_domain = urlparse(payload.replace('\\', '/')).netloc
        if payload_domain and payload_domain in location:
            return True
        
        # Protocol-relative check
        if location.startswith('//') and not location.startswith('///'):
            return True
        
        return False
    
    def quick_scan(
        self,
        url: str,
        token: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Quick scan with limited payloads for speed.
        
        Returns:
            Dict with summary
        """
        quick_payloads = [
            'https://evil.com',
            '//evil.com',
            'https://example.com@evil.com',
        ]
        
        findings = []
        headers = {'Authorization': token} if token else {}
        
        # Test common params with quick payloads
        for param in self.REDIRECT_PARAMS[:10]:
            for payload in quick_payloads:
                result = self._test_payload(url, param, payload, headers)
                if result and result.vulnerable:
                    findings.append({
                        'param': param,
                        'payload': payload,
                        'location': result.redirect_location
                    })
                    break  # One finding per param is enough
        
        return {
            'url': url,
            'vulnerable': len(findings) > 0,
            'vulnerable_params': len(findings),
            'findings': findings
        }
