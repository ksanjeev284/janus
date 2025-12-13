# janus/reporting/sarif.py
"""
SARIF Reporter - Static Analysis Results Interchange Format.

SARIF is the standard format for security tools to integrate with:
- GitHub Security tab
- GitLab Security Dashboard
- Azure DevOps
- VS Code SARIF Viewer

This allows Janus to integrate directly into CI/CD pipelines
and show vulnerabilities in code review.

Reference: https://sarifweb.azurewebsites.net/
SARIF Version: 2.1.0
"""

import json
from typing import Dict, List, Any, Optional
from datetime import datetime, timezone
from dataclasses import dataclass
import hashlib


# SARIF severity levels
SARIF_LEVELS = {
    'CRITICAL': 'error',
    'HIGH': 'error',
    'MEDIUM': 'warning',
    'LOW': 'note',
    'INFO': 'note',
}

# CWE IDs for common vulnerabilities
CWE_MAPPINGS = {
    'BOLA': 'CWE-639',      # Authorization Bypass Through User-Controlled Key
    'IDOR': 'CWE-639',
    'BFLA': 'CWE-285',      # Improper Authorization
    'Mass Assignment': 'CWE-915',  # Improperly Controlled Modification
    'JWT': 'CWE-347',       # Improper Verification of Cryptographic Signature
    'SQLi': 'CWE-89',
    'XSS': 'CWE-79',
    'Race Condition': 'CWE-362',  # Concurrent Execution
    'PII Leak': 'CWE-359',  # Exposure of Private Personal Information
    'API Key': 'CWE-798',   # Use of Hardcoded Credentials
    'GraphQL': 'CWE-200',   # Exposure of Sensitive Information
    'CVE': 'CWE-1035',      # Known Vulnerability
}


@dataclass
class SARIFLocation:
    """Location of a finding (for API testing, this is the endpoint)."""
    uri: str
    start_line: int = 1
    end_line: int = 1
    start_column: int = 1
    end_column: int = 1
    message: str = ""


class SARIFReporter:
    """
    Generate SARIF 2.1.0 compliant reports for CI/CD integration.
    
    Features:
    - Valid SARIF JSON schema
    - CWE ID mappings
    - GitHub Code Scanning compatible
    - Fingerprinting for deduplication
    """
    
    SARIF_VERSION = "2.1.0"
    SCHEMA_URI = "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json"
    
    def __init__(self, 
                 tool_name: str = "Janus",
                 tool_version: str = "2.0.0",
                 tool_url: str = "https://github.com/janus-security/janus"):
        self.tool_name = tool_name
        self.tool_version = tool_version
        self.tool_url = tool_url
        self.rules: Dict[str, Dict] = {}
        self.results: List[Dict] = []
    
    def _generate_fingerprint(self, finding: Dict) -> str:
        """Generate a stable fingerprint for deduplication."""
        # Combine key fields for fingerprinting
        key_parts = [
            finding.get('endpoint', ''),
            finding.get('method', ''),
            finding.get('type', finding.get('status', '')),
            finding.get('evidence', '')[:100],
        ]
        fingerprint = hashlib.sha256('|'.join(key_parts).encode()).hexdigest()[:32]
        return fingerprint
    
    def _get_cwe(self, vuln_type: str) -> str:
        """Get CWE ID for a vulnerability type."""
        for key, cwe in CWE_MAPPINGS.items():
            if key.lower() in vuln_type.lower():
                return cwe
        return "CWE-200"  # Default: Information Exposure
    
    def _create_rule(self, rule_id: str, vuln_type: str, description: str) -> Dict:
        """Create a SARIF rule definition."""
        cwe = self._get_cwe(vuln_type)
        
        return {
            "id": rule_id,
            "name": vuln_type.replace(' ', ''),
            "shortDescription": {
                "text": vuln_type
            },
            "fullDescription": {
                "text": description
            },
            "helpUri": f"https://owasp.org/API-Security/",
            "properties": {
                "tags": ["security", "api", cwe],
                "security-severity": "8.0" if "CRITICAL" in vuln_type.upper() else "6.0"
            },
            "defaultConfiguration": {
                "level": "error" if "CRITICAL" in vuln_type.upper() else "warning"
            }
        }
    
    def add_finding(self,
                    endpoint: str,
                    vuln_type: str,
                    severity: str,
                    evidence: str,
                    method: str = "GET",
                    recommendation: str = "",
                    additional_info: Dict = None):
        """
        Add a security finding to the report.
        
        Args:
            endpoint: The vulnerable API endpoint
            vuln_type: Type of vulnerability (BOLA, BFLA, etc.)
            severity: CRITICAL, HIGH, MEDIUM, LOW
            evidence: Description of what was found
            method: HTTP method
            recommendation: How to fix
            additional_info: Extra data to include
        """
        # Create rule ID
        rule_id = f"janus/{vuln_type.lower().replace(' ', '-')}"
        
        # Add rule if not exists
        if rule_id not in self.rules:
            self.rules[rule_id] = self._create_rule(rule_id, vuln_type, evidence)
        
        # Create finding
        finding = {
            "endpoint": endpoint,
            "method": method,
            "type": vuln_type,
            "severity": severity,
            "evidence": evidence,
        }
        
        fingerprint = self._generate_fingerprint(finding)
        
        result = {
            "ruleId": rule_id,
            "level": SARIF_LEVELS.get(severity.upper(), "warning"),
            "message": {
                "text": f"{vuln_type} vulnerability detected at {method} {endpoint}. {evidence}"
            },
            "locations": [
                {
                    "physicalLocation": {
                        "artifactLocation": {
                            "uri": endpoint,
                            "uriBaseId": "API"
                        }
                    },
                    "logicalLocations": [
                        {
                            "name": endpoint.split('/')[-1] if '/' in endpoint else endpoint,
                            "fullyQualifiedName": f"{method} {endpoint}",
                            "kind": "endpoint"
                        }
                    ]
                }
            ],
            "partialFingerprints": {
                "primaryLocationLineHash": fingerprint
            },
            "properties": {
                "severity": severity,
                "method": method,
                "cwe": self._get_cwe(vuln_type),
                **(additional_info or {})
            }
        }
        
        if recommendation:
            result["fixes"] = [
                {
                    "description": {
                        "text": recommendation
                    }
                }
            ]
        
        self.results.append(result)
    
    def from_scan_report(self, scan_report: Dict) -> 'SARIFReporter':
        """
        Convert a Janus scan report to SARIF format.
        
        Args:
            scan_report: Standard Janus JSON report
        
        Returns:
            Self for chaining
        """
        findings = scan_report.get('findings', [])
        
        for finding in findings:
            # Skip non-vulnerable findings
            status = finding.get('status', '').upper()
            if status not in ['VULNERABLE', 'NEEDS_REVIEW']:
                continue
            
            endpoint = finding.get('endpoint', 'unknown')
            method = finding.get('method', 'GET')
            severity = finding.get('severity', 'MEDIUM')
            evidence = finding.get('evidence', '')
            
            # Determine vulnerability type
            vuln_type = 'BOLA'  # Default
            if 'admin' in endpoint.lower():
                vuln_type = 'BFLA'
            elif 'jwt' in evidence.lower():
                vuln_type = 'JWT Vulnerability'
            elif 'mass' in str(finding).lower():
                vuln_type = 'Mass Assignment'
            
            self.add_finding(
                endpoint=endpoint,
                vuln_type=vuln_type,
                severity=severity,
                evidence=evidence,
                method=method,
                additional_info={
                    "confidence": finding.get('confidence', 0.0),
                    "similarity": finding.get('similarity_score', 0.0)
                }
            )
        
        return self
    
    def from_bfla_results(self, results: List[Dict]) -> 'SARIFReporter':
        """Add BFLA scan results to the report."""
        for r in results:
            if r.get('vulnerable'):
                self.add_finding(
                    endpoint=r.get('endpoint', ''),
                    vuln_type='BFLA',
                    severity=r.get('severity', 'HIGH'),
                    evidence=r.get('evidence', ''),
                    method=r.get('method', 'GET'),
                    recommendation=r.get('recommendation', '')
                )
        return self
    
    def from_pii_results(self, results: List[Dict]) -> 'SARIFReporter':
        """Add PII scan results to the report."""
        for r in results:
            for finding in r.get('findings', []):
                self.add_finding(
                    endpoint=r.get('endpoint', ''),
                    vuln_type=f"PII Leak: {finding.get('data_type', 'unknown')}",
                    severity=finding.get('severity', 'HIGH'),
                    evidence=f"Sensitive data '{finding.get('data_type')}' found at '{finding.get('field_path')}'",
                    recommendation=finding.get('recommendation', ''),
                    additional_info={
                        "compliance": finding.get('compliance_impact', []),
                        "field_path": finding.get('field_path', '')
                    }
                )
        return self
    
    def generate(self) -> Dict:
        """
        Generate the complete SARIF report.
        
        Returns:
            SARIF 2.1.0 compliant dictionary
        """
        sarif = {
            "$schema": self.SCHEMA_URI,
            "version": self.SARIF_VERSION,
            "runs": [
                {
                    "tool": {
                        "driver": {
                            "name": self.tool_name,
                            "version": self.tool_version,
                            "informationUri": self.tool_url,
                            "rules": list(self.rules.values()),
                            "properties": {
                                "tags": ["security", "api", "owasp"]
                            }
                        }
                    },
                    "results": self.results,
                    "invocations": [
                        {
                            "executionSuccessful": True,
                            "endTimeUtc": datetime.now(timezone.utc).isoformat().replace('+00:00', 'Z')
                        }
                    ],
                    "originalUriBaseIds": {
                        "API": {
                            "uri": "/"
                        }
                    }
                }
            ]
        }
        
        return sarif
    
    def save(self, filepath: str) -> str:
        """Save SARIF report to file."""
        sarif = self.generate()
        
        with open(filepath, 'w') as f:
            json.dump(sarif, f, indent=2)
        
        return filepath
    
    def to_json(self) -> str:
        """Get SARIF report as JSON string."""
        return json.dumps(self.generate(), indent=2)


def convert_to_sarif(janus_report: Dict, output_file: str = "janus_sarif.json") -> str:
    """
    Quick function to convert a Janus report to SARIF.
    
    Args:
        janus_report: Standard Janus JSON report
        output_file: Output file path
    
    Returns:
        Path to saved SARIF file
    """
    reporter = SARIFReporter()
    reporter.from_scan_report(janus_report)
    return reporter.save(output_file)


def get_exit_code(sarif_report: Dict, fail_on: str = "error") -> int:
    """
    Determine CI/CD exit code based on findings.
    
    Args:
        sarif_report: Generated SARIF report
        fail_on: Minimum level to fail on (error, warning, note)
    
    Returns:
        0 if no issues at fail level, 1 otherwise
    """
    fail_levels = {
        'error': ['error'],
        'warning': ['error', 'warning'],
        'note': ['error', 'warning', 'note'],
    }
    
    check_levels = fail_levels.get(fail_on, ['error'])
    
    for run in sarif_report.get('runs', []):
        for result in run.get('results', []):
            if result.get('level') in check_levels:
                return 1  # Fail the build
    
    return 0  # Success
