# janus/analysis/cors_scanner.py
"""
CORS (Cross-Origin Resource Sharing) Misconfiguration Scanner.

Detects insecure CORS configurations that could allow:
- Credential theft via reflected origins
- Data exfiltration via wildcard origins
- Null origin bypasses
"""

import requests
from dataclasses import dataclass, field, asdict
from typing import Dict, List, Any, Optional
from datetime import datetime


@dataclass
class CORSFinding:
    """A single CORS finding."""
    vulnerability: str
    severity: str  # CRITICAL, HIGH, MEDIUM, LOW
    origin_tested: str
    acao_header: Optional[str]  # Access-Control-Allow-Origin
    acac_header: Optional[str]  # Access-Control-Allow-Credentials
    evidence: str
    recommendation: str
    
    def to_dict(self) -> Dict:
        return asdict(self)


@dataclass
class CORSReport:
    """Complete CORS analysis report."""
    url: str
    scan_time: str
    vulnerable: bool
    critical_findings: int
    high_findings: int
    findings: List[CORSFinding] = field(default_factory=list)
    
    def to_dict(self) -> Dict:
        return {
            **asdict(self),
            'findings': [f.to_dict() for f in self.findings]
        }


class CORSScanner:
    """
    CORS Misconfiguration Scanner.
    
    Tests for common CORS vulnerabilities including:
    - Origin reflection (reflects any origin in ACAO)
    - Null origin allowed  
    - Wildcard with credentials
    - Subdomain matching bypasses
    - Partial origin matching
    """
    
    # Test origins for various bypass techniques
    TEST_ORIGINS = {
        'reflection': [
            'https://evil.com',
            'https://attacker.com',
            'https://malicious.example.com',
        ],
        'null': [
            'null',
        ],
        'subdomain': [
            'https://evil.{domain}',
            'https://{domain}.evil.com',
        ],
        'partial': [
            'https://{domain}evil.com',
            'https://evil{domain}',
        ],
        'protocol': [
            'http://{domain}',  # HTTP instead of HTTPS
        ],
    }
    
    def __init__(self, timeout: int = 10):
        self.timeout = timeout
    
    def scan(self, url: str, token: Optional[str] = None) -> CORSReport:
        """
        Scan a URL for CORS misconfigurations.
        
        Args:
            url: Target URL to test
            token: Optional authorization token
        
        Returns:
            CORSReport with findings
        """
        findings = []
        base_headers = {'Authorization': token} if token else {}
        
        # Extract domain from URL for subdomain tests
        from urllib.parse import urlparse
        parsed = urlparse(url)
        domain = parsed.netloc
        
        # Test 1: Origin reflection
        for origin in self.TEST_ORIGINS['reflection']:
            result = self._test_origin(url, origin, base_headers)
            if result:
                findings.append(result)
        
        # Test 2: Null origin
        for origin in self.TEST_ORIGINS['null']:
            result = self._test_origin(url, origin, base_headers, is_null=True)
            if result:
                findings.append(result)
        
        # Test 3: Subdomain bypasses
        for origin_template in self.TEST_ORIGINS['subdomain']:
            origin = origin_template.replace('{domain}', domain)
            result = self._test_origin(url, origin, base_headers)
            if result:
                findings.append(result)
        
        # Test 4: Partial matching
        for origin_template in self.TEST_ORIGINS['partial']:
            origin = origin_template.replace('{domain}', domain.split('.')[0])
            result = self._test_origin(url, origin, base_headers)
            if result:
                findings.append(result)
        
        # Test 5: Protocol downgrade
        for origin_template in self.TEST_ORIGINS['protocol']:
            origin = origin_template.replace('{domain}', domain)
            result = self._test_origin(url, origin, base_headers)
            if result:
                findings.append(result)
        
        # Test 6: Wildcard check
        wildcard_finding = self._check_wildcard(url, base_headers)
        if wildcard_finding:
            findings.append(wildcard_finding)
        
        critical = sum(1 for f in findings if f.severity == 'CRITICAL')
        high = sum(1 for f in findings if f.severity == 'HIGH')
        
        return CORSReport(
            url=url,
            scan_time=datetime.now().isoformat(),
            vulnerable=len(findings) > 0,
            critical_findings=critical,
            high_findings=high,
            findings=findings
        )
    
    def _test_origin(
        self, 
        url: str, 
        origin: str, 
        base_headers: Dict,
        is_null: bool = False
    ) -> Optional[CORSFinding]:
        """Test a specific origin for CORS vulnerability."""
        headers = {**base_headers, 'Origin': origin}
        
        try:
            response = requests.get(url, headers=headers, timeout=self.timeout)
            
            acao = response.headers.get('Access-Control-Allow-Origin')
            acac = response.headers.get('Access-Control-Allow-Credentials')
            
            if acao is None:
                return None
            
            # Check if origin is reflected
            if acao == origin:
                severity = 'CRITICAL' if acac and acac.lower() == 'true' else 'HIGH'
                vuln_type = 'Null Origin Allowed' if is_null else 'Origin Reflection'
                
                return CORSFinding(
                    vulnerability=vuln_type,
                    severity=severity,
                    origin_tested=origin,
                    acao_header=acao,
                    acac_header=acac,
                    evidence=f"Origin '{origin}' is reflected in Access-Control-Allow-Origin" + 
                             (f" with credentials enabled" if acac else ""),
                    recommendation="Implement a strict allowlist of trusted origins. Never reflect arbitrary origins."
                )
            
        except Exception as e:
            return None
        
        return None
    
    def _check_wildcard(self, url: str, base_headers: Dict) -> Optional[CORSFinding]:
        """Check for wildcard CORS configuration."""
        headers = {**base_headers, 'Origin': 'https://test.com'}
        
        try:
            response = requests.get(url, headers=headers, timeout=self.timeout)
            
            acao = response.headers.get('Access-Control-Allow-Origin')
            acac = response.headers.get('Access-Control-Allow-Credentials')
            
            if acao == '*':
                if acac and acac.lower() == 'true':
                    return CORSFinding(
                        vulnerability='Wildcard with Credentials',
                        severity='CRITICAL',
                        origin_tested='*',
                        acao_header=acao,
                        acac_header=acac,
                        evidence="Wildcard (*) ACAO with Access-Control-Allow-Credentials: true (invalid but dangerous if cached)",
                        recommendation="Never use wildcard with credentials. Use specific origins."
                    )
                else:
                    return CORSFinding(
                        vulnerability='Wildcard Origin',
                        severity='MEDIUM',
                        origin_tested='*',
                        acao_header=acao,
                        acac_header=acac,
                        evidence="Wildcard (*) allows any origin to read responses (public API may be intentional)",
                        recommendation="Ensure this is intentional for public APIs. Use specific origins for sensitive endpoints."
                    )
        except:
            pass
        
        return None
    
    def quick_scan(self, url: str, token: Optional[str] = None) -> Dict[str, Any]:
        """
        Quick scan with simplified output.
        
        Returns:
            Dict with summary and key findings
        """
        report = self.scan(url, token)
        
        return {
            "url": report.url,
            "vulnerable": report.vulnerable,
            "critical": report.critical_findings,
            "high": report.high_findings,
            "total_findings": len(report.findings),
            "findings": [
                {
                    "vulnerability": f.vulnerability,
                    "severity": f.severity,
                    "origin": f.origin_tested
                }
                for f in report.findings
            ]
        }
