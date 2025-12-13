# janus/attack/bfla.py
"""
BFLA Scanner - Broken Function Level Authorization.
Tests for Vertical Privilege Escalation (Regular User -> Admin Functions).

Risk: BFLA is a CRITICAL vulnerability that allows low-privilege users
to access admin-only functions like user management, data export, or 
system configuration.

OWASP API5:2023 - Broken Function Level Authorization
"""

import requests
from typing import Dict, List, Any, Optional, Tuple, Set
from dataclasses import dataclass, asdict
from datetime import datetime
import re
from urllib.parse import urlparse


@dataclass
class BFLAResult:
    """Result of a BFLA test on an endpoint."""
    endpoint: str
    method: str
    vulnerable: bool
    severity: str  # CRITICAL, HIGH, MEDIUM
    admin_pattern_matched: str
    low_priv_status: int
    high_priv_status: int
    evidence: str
    recommendation: str
    
    def to_dict(self) -> Dict:
        return asdict(self)


class BFLAScanner:
    """
    Broken Function Level Authorization Scanner.
    
    Detects when low-privilege users can access admin-level functions.
    This is different from BOLA (horizontal) - BFLA is vertical escalation.
    """
    
    # Patterns that indicate privileged/admin endpoints
    ADMIN_PATTERNS: List[Tuple[str, str]] = [
        # Admin/Management
        (r'/admin', 'admin'),
        (r'/administrator', 'administrator'),
        (r'/management', 'management'),
        (r'/dashboard', 'dashboard'),
        (r'/panel', 'panel'),
        (r'/control', 'control'),
        
        # User Management
        (r'/users?/(?:create|delete|update|list|all|manage)', 'user_management'),
        (r'/accounts?/(?:create|delete|suspend|activate)', 'account_management'),
        (r'/roles?/', 'role_management'),
        (r'/permissions?/', 'permission_management'),
        
        # Data Export/Import
        (r'/export', 'data_export'),
        (r'/import', 'data_import'),
        (r'/backup', 'backup'),
        (r'/dump', 'data_dump'),
        (r'/download', 'download'),
        
        # Configuration
        (r'/config', 'configuration'),
        (r'/settings', 'settings'),
        (r'/setup', 'setup'),
        (r'/install', 'installation'),
        
        # Dangerous Operations
        (r'/delete', 'delete_operation'),
        (r'/remove', 'remove_operation'),
        (r'/purge', 'purge_operation'),
        (r'/reset', 'reset_operation'),
        (r'/truncate', 'truncate_operation'),
        
        # Financial/Billing
        (r'/billing', 'billing'),
        (r'/payment', 'payment'),
        (r'/refund', 'refund'),
        (r'/invoice', 'invoice'),
        
        # Logs/Audit
        (r'/logs?', 'logs'),
        (r'/audit', 'audit'),
        (r'/analytics', 'analytics'),
        (r'/metrics', 'metrics'),
        
        # Internal/Debug
        (r'/internal', 'internal'),
        (r'/debug', 'debug'),
        (r'/test', 'test'),
        (r'/dev', 'development'),
        (r'/_', 'internal_underscore'),
    ]
    
    # HTTP methods with higher privilege implications
    DANGEROUS_METHODS = {'DELETE', 'PUT', 'PATCH', 'POST'}
    
    def __init__(self, timeout: int = 10):
        self.timeout = timeout
        self.results: List[BFLAResult] = []
    
    def _identify_admin_endpoints(self, endpoints: List[Dict]) -> List[Dict]:
        """
        Filter endpoints that appear to be admin/privileged functions.
        
        Args:
            endpoints: List of endpoint dicts with 'path' and 'method' keys
        
        Returns:
            List of endpoints matching admin patterns
        """
        admin_endpoints = []
        
        for endpoint in endpoints:
            path = endpoint.get('path', '').lower()
            method = endpoint.get('method', 'GET').upper()
            
            for pattern, pattern_name in self.ADMIN_PATTERNS:
                if re.search(pattern, path, re.IGNORECASE):
                    admin_endpoints.append({
                        **endpoint,
                        'admin_pattern': pattern_name,
                        'risk_boost': 1.5 if method in self.DANGEROUS_METHODS else 1.0
                    })
                    break
        
        return admin_endpoints
    
    def _make_request(self, url: str, method: str, token: str,
                      body: Dict = None, headers: Dict = None) -> Tuple[int, Any]:
        """Make an HTTP request and return status code and response."""
        request_headers = {
            'Authorization': token if not token.startswith('Bearer') else token,
            'Content-Type': 'application/json',
            **(headers or {})
        }
        
        if not token.startswith('Bearer'):
            request_headers['Authorization'] = token
        
        try:
            response = requests.request(
                method=method,
                url=url,
                headers=request_headers,
                json=body,
                timeout=self.timeout,
                allow_redirects=False
            )
            
            try:
                response_body = response.json()
            except:
                response_body = response.text[:500]
            
            return response.status_code, response_body
            
        except Exception as e:
            return 0, {"error": str(e)}
    
    def test_endpoint(self, 
                      endpoint_url: str,
                      method: str,
                      low_priv_token: str,
                      high_priv_token: str = None,
                      body: Dict = None) -> BFLAResult:
        """
        Test a single endpoint for BFLA vulnerability.
        
        Args:
            endpoint_url: Full URL of the endpoint
            method: HTTP method
            low_priv_token: Token of a regular/low-privilege user
            high_priv_token: Optional token of admin user for comparison
            body: Optional request body
        
        Returns:
            BFLAResult with vulnerability details
        """
        # Identify admin pattern
        admin_pattern = "unknown"
        for pattern, name in self.ADMIN_PATTERNS:
            if re.search(pattern, endpoint_url, re.IGNORECASE):
                admin_pattern = name
                break
        
        # Test with low privilege token
        low_status, low_response = self._make_request(
            endpoint_url, method, low_priv_token, body
        )
        
        # Test with high privilege token if provided
        high_status = 200
        if high_priv_token:
            high_status, _ = self._make_request(
                endpoint_url, method, high_priv_token, body
            )
        
        # Analyze results
        vulnerable = False
        severity = "LOW"
        evidence = ""
        recommendation = ""
        
        # VULNERABLE: Low privilege user got success on admin endpoint
        if low_status in [200, 201, 202, 204]:
            vulnerable = True
            severity = "CRITICAL"
            evidence = f"Low-privilege user received HTTP {low_status} on admin function '{admin_pattern}'"
            recommendation = (
                "Implement proper role-based access control (RBAC). "
                "Verify user permissions server-side before executing privileged operations."
            )
        
        # Suspicious: Got redirect (might bypass auth)
        elif low_status in [301, 302, 303, 307, 308]:
            vulnerable = True
            severity = "HIGH"
            evidence = f"Redirect detected (HTTP {low_status}) - may indicate auth bypass attempt"
            recommendation = "Ensure redirects don't expose admin functionality."
        
        # BLOCKED: Proper access control
        elif low_status in [401, 403]:
            evidence = f"Properly blocked with HTTP {low_status}"
            recommendation = ""
        
        # Error states
        elif low_status >= 500:
            severity = "MEDIUM"
            evidence = f"Server error {low_status} - may indicate broken authorization logic"
            recommendation = "Investigate server-side error handling."
        
        else:
            evidence = f"Received HTTP {low_status}"
        
        result = BFLAResult(
            endpoint=endpoint_url,
            method=method,
            vulnerable=vulnerable,
            severity=severity,
            admin_pattern_matched=admin_pattern,
            low_priv_status=low_status,
            high_priv_status=high_status,
            evidence=evidence,
            recommendation=recommendation
        )
        
        self.results.append(result)
        return result
    
    def scan_endpoints(self,
                       base_url: str,
                       endpoints: List[str],
                       low_priv_token: str,
                       high_priv_token: str = None,
                       methods: List[str] = None) -> List[BFLAResult]:
        """
        Scan multiple endpoints for BFLA vulnerabilities.
        
        Args:
            base_url: Base API URL
            endpoints: List of endpoint paths to test
            low_priv_token: Regular user token
            high_priv_token: Admin user token (optional)
            methods: HTTP methods to test (default: GET)
        
        Returns:
            List of BFLAResult
        """
        methods = methods or ['GET']
        results = []
        
        # Convert to endpoint dicts
        endpoint_dicts = [{'path': e, 'method': m} for e in endpoints for m in methods]
        
        # Filter to admin endpoints
        admin_endpoints = self._identify_admin_endpoints(endpoint_dicts)
        
        print(f"[*] Found {len(admin_endpoints)} potential admin endpoints to test")
        
        for ep in admin_endpoints:
            full_url = f"{base_url.rstrip('/')}{ep['path']}"
            print(f"[*] Testing: {ep['method']} {full_url}")
            
            result = self.test_endpoint(
                full_url,
                ep['method'],
                low_priv_token,
                high_priv_token
            )
            results.append(result)
            
            if result.vulnerable:
                print(f"    [!] {result.severity}: {result.evidence}")
        
        return results
    
    def scan_from_database(self, 
                           db, 
                           base_url: str,
                           low_priv_token: str,
                           high_priv_token: str = None) -> List[BFLAResult]:
        """
        Scan endpoints learned from the Janus database.
        """
        endpoints = set()
        
        for token in db.get_all_tokens():
            learnings = db.get_learnings(token)
            for entry in learnings:
                template = entry.get('endpoint_template', '')
                if template:
                    endpoints.add(template)
        
        return self.scan_endpoints(
            base_url,
            list(endpoints),
            low_priv_token,
            high_priv_token
        )
    
    def generate_report(self) -> Dict:
        """Generate a summary report of BFLA findings."""
        vulnerable = [r for r in self.results if r.vulnerable]
        
        return {
            "total_tested": len(self.results),
            "vulnerabilities_found": len(vulnerable),
            "by_severity": {
                "CRITICAL": len([r for r in vulnerable if r.severity == "CRITICAL"]),
                "HIGH": len([r for r in vulnerable if r.severity == "HIGH"]),
                "MEDIUM": len([r for r in vulnerable if r.severity == "MEDIUM"]),
            },
            "findings": [r.to_dict() for r in self.results]
        }
