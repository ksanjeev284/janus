# janus/analysis/pii_scanner.py
"""
PII & Secrets Scanner - Sensitive Data Exposure Detection.
Scans API responses for accidentally leaked sensitive information.

Risk: APIs often return more data than intended, exposing:
- Personal Identifiable Information (PII) - violates GDPR/CCPA
- API Keys and Secrets - enables further attacks
- Password Hashes - enables offline cracking
- Financial Data - enables fraud

OWASP API3:2023 - Broken Object Property Level Authorization
"""

import re
from typing import Dict, List, Any, Optional, Tuple, Set
from dataclasses import dataclass, asdict
import json
import hashlib


@dataclass
class PIIFinding:
    """A single PII/Secret finding."""
    field_path: str  # JSON path where found (e.g., "user.email")
    data_type: str   # email, ssn, credit_card, api_key, etc.
    severity: str    # CRITICAL, HIGH, MEDIUM, LOW
    matched_value: str  # Redacted sample of the match
    pattern_name: str
    compliance_impact: List[str]  # GDPR, CCPA, PCI-DSS, etc.
    recommendation: str
    
    def to_dict(self) -> Dict:
        return asdict(self)


@dataclass
class ScanResult:
    """Result of scanning a response for PII/Secrets."""
    endpoint: str
    findings: List[PIIFinding]
    total_fields_scanned: int
    sensitive_fields_found: int
    risk_score: float  # 0.0 to 10.0
    compliance_violations: List[str]
    
    def to_dict(self) -> Dict:
        return {
            **asdict(self),
            "findings": [f.to_dict() for f in self.findings]
        }


class PIIScanner:
    """
    Passive PII and Secrets Scanner.
    
    Scans JSON response bodies for sensitive data that shouldn't be exposed.
    Helps with GDPR, CCPA, PCI-DSS, and HIPAA compliance.
    """
    
    # PII Patterns with compliance mappings
    PATTERNS: List[Tuple[str, str, str, List[str], str]] = [
        # Format: (regex, name, severity, compliance_impacts, recommendation)
        
        # === EMAILS ===
        (
            r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b',
            'email_address',
            'HIGH',
            ['GDPR', 'CCPA'],
            'Email addresses are PII. Only return if explicitly requested and necessary.'
        ),
        
        # === PHONE NUMBERS ===
        (
            r'\b(?:\+?1[-.\s]?)?\(?[0-9]{3}\)?[-.\s]?[0-9]{3}[-.\s]?[0-9]{4}\b',
            'phone_number',
            'HIGH',
            ['GDPR', 'CCPA'],
            'Phone numbers are PII. Mask or omit from responses.'
        ),
        
        # === SSN (US) ===
        (
            r'\b\d{3}[-\s]?\d{2}[-\s]?\d{4}\b',
            'ssn',
            'CRITICAL',
            ['GDPR', 'CCPA', 'HIPAA'],
            'CRITICAL: Social Security Numbers must NEVER be exposed in APIs.'
        ),
        
        # === CREDIT CARDS ===
        (
            r'\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13}|6(?:011|5[0-9]{2})[0-9]{12})\b',
            'credit_card',
            'CRITICAL',
            ['PCI-DSS', 'GDPR'],
            'CRITICAL: Credit card numbers violate PCI-DSS. Use tokenization.'
        ),
        
        # === CVV ===
        (
            r'"cvv"\s*:\s*"?\d{3,4}"?',
            'cvv_code',
            'CRITICAL',
            ['PCI-DSS'],
            'CRITICAL: CVV codes must NEVER be stored or returned.'
        ),
        
        # === PASSWORD HASHES ===
        (
            r'\$2[aby]?\$\d{1,2}\$[./A-Za-z0-9]{53}',
            'bcrypt_hash',
            'CRITICAL',
            ['OWASP'],
            'CRITICAL: Password hashes enable offline cracking. Never expose.'
        ),
        (
            r'\b[a-f0-9]{32}\b',
            'md5_hash',
            'HIGH',
            ['OWASP'],
            'Possible MD5 hash detected. Verify if this is a password hash.'
        ),
        (
            r'\b[a-f0-9]{64}\b',
            'sha256_hash',
            'HIGH',
            ['OWASP'],
            'Possible SHA256 hash detected. Verify if this is sensitive.'
        ),
        
        # === AWS KEYS ===
        (
            r'AKIA[0-9A-Z]{16}',
            'aws_access_key',
            'CRITICAL',
            ['Security'],
            'CRITICAL: AWS Access Key exposed! Rotate immediately.'
        ),
        (
            r'(?:AWS|aws).{0,20}(?:secret|SECRET).{0,20}[\'"][A-Za-z0-9/+=]{40}[\'"]',
            'aws_secret_key',
            'CRITICAL',
            ['Security'],
            'CRITICAL: AWS Secret Key exposed! Rotate immediately.'
        ),
        
        # === API KEYS (Generic) ===
        (
            r'(?:api[_-]?key|apikey|api_secret)["\']?\s*[:=]\s*["\']?[A-Za-z0-9]{32,}["\']?',
            'generic_api_key',
            'CRITICAL',
            ['Security'],
            'API key detected in response. Keys should never be returned to clients.'
        ),
        (
            r'(?:sk_live_|pk_live_|sk_test_|pk_test_)[A-Za-z0-9]{24,}',
            'stripe_key',
            'CRITICAL',
            ['Security', 'PCI-DSS'],
            'CRITICAL: Stripe API key exposed! Rotate immediately.'
        ),
        
        # === BEARER TOKENS ===
        (
            r'(?:bearer|Bearer)\s+[A-Za-z0-9\-_=]+\.[A-Za-z0-9\-_=]+\.[A-Za-z0-9\-_.+/=]*',
            'jwt_token',
            'HIGH',
            ['Security'],
            'JWT token in response body. Tokens should only be in headers.'
        ),
        
        # === PRIVATE KEYS ===
        (
            r'-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----',
            'private_key',
            'CRITICAL',
            ['Security'],
            'CRITICAL: Private key exposed! This is a severe security breach.'
        ),
        
        # === DATE OF BIRTH ===
        (
            r'"(?:dob|date_of_birth|birthdate|birth_date)"\s*:\s*"[^"]*"',
            'date_of_birth',
            'MEDIUM',
            ['GDPR', 'CCPA', 'HIPAA'],
            'Date of birth is PII. Consider if this field is necessary.'
        ),
        
        # === ADDRESSES ===
        (
            r'"(?:address|street_address|home_address|mailing_address)"\s*:\s*"[^"]*"',
            'physical_address',
            'MEDIUM',
            ['GDPR', 'CCPA'],
            'Physical addresses are PII. Mask or limit access.'
        ),
        
        # === IP ADDRESSES ===
        (
            r'\b(?:\d{1,3}\.){3}\d{1,3}\b',
            'ip_address',
            'LOW',
            ['GDPR'],
            'IP addresses are considered PII under GDPR.'
        ),
        
        # === MEDICAL DATA ===
        (
            r'"(?:diagnosis|medical_record|health_condition|insurance_id|patient_id)"\s*:\s*"[^"]*"',
            'medical_data',
            'CRITICAL',
            ['HIPAA', 'GDPR'],
            'CRITICAL: Medical data requires HIPAA compliance. Limit exposure.'
        ),
    ]
    
    # Field names that should never be in responses
    DANGEROUS_FIELD_NAMES: Set[str] = {
        'password', 'passwd', 'pwd', 'secret', 'private_key', 'privateKey',
        'password_hash', 'passwordHash', 'hashed_password', 'hashedPassword',
        'api_key', 'apiKey', 'api_secret', 'apiSecret',
        'access_token', 'accessToken', 'refresh_token', 'refreshToken',
        'ssn', 'social_security', 'socialSecurity', 'ssn_last4',
        'credit_card', 'creditCard', 'card_number', 'cardNumber',
        'cvv', 'cvc', 'security_code', 'securityCode',
        'pin', 'pin_code', 'pinCode',
    }
    
    def __init__(self, strict_mode: bool = True):
        """
        Initialize PII Scanner.
        
        Args:
            strict_mode: If True, also check field names (more false positives)
        """
        self.strict_mode = strict_mode
        self.findings: List[PIIFinding] = []
    
    def _redact_value(self, value: str, show_chars: int = 4) -> str:
        """Redact a sensitive value, showing only first few chars."""
        if len(value) <= show_chars:
            return '*' * len(value)
        return value[:show_chars] + '*' * (len(value) - show_chars)
    
    def _extract_paths(self, data: Any, prefix: str = "") -> List[Tuple[str, Any]]:
        """Recursively extract all field paths and values from JSON."""
        paths = []
        
        if isinstance(data, dict):
            for key, value in data.items():
                path = f"{prefix}.{key}" if prefix else key
                paths.append((path, value))
                paths.extend(self._extract_paths(value, path))
        elif isinstance(data, list):
            for i, item in enumerate(data):
                path = f"{prefix}[{i}]"
                paths.extend(self._extract_paths(item, path))
        
        return paths
    
    def scan_response(self, 
                      response_body: Any, 
                      endpoint: str = "unknown") -> ScanResult:
        """
        Scan a JSON response body for PII and secrets.
        
        Args:
            response_body: JSON response (dict, list, or string)
            endpoint: The endpoint this response came from
        
        Returns:
            ScanResult with findings
        """
        findings = []
        compliance_violations = set()
        
        # Parse JSON if string
        if isinstance(response_body, str):
            try:
                response_body = json.loads(response_body)
            except json.JSONDecodeError:
                # Scan raw string
                response_body = {"_raw": response_body}
        
        # Extract all paths and values
        paths = self._extract_paths(response_body)
        
        for path, value in paths:
            # Check field names in strict mode
            if self.strict_mode:
                field_name = path.split('.')[-1].lower()
                if field_name in self.DANGEROUS_FIELD_NAMES:
                    finding = PIIFinding(
                        field_path=path,
                        data_type='dangerous_field_name',
                        severity='HIGH',
                        matched_value=f"{field_name}=***",
                        pattern_name='dangerous_field',
                        compliance_impact=['Security'],
                        recommendation=f"Field '{field_name}' should not be in API responses."
                    )
                    findings.append(finding)
                    compliance_violations.add('Security')
            
            # Check value patterns
            if isinstance(value, str) and len(value) > 0:
                for pattern, name, severity, compliance, recommendation in self.PATTERNS:
                    if re.search(pattern, value, re.IGNORECASE):
                        finding = PIIFinding(
                            field_path=path,
                            data_type=name,
                            severity=severity,
                            matched_value=self._redact_value(value),
                            pattern_name=name,
                            compliance_impact=compliance,
                            recommendation=recommendation
                        )
                        findings.append(finding)
                        compliance_violations.update(compliance)
                        break  # One finding per field
        
        # Also scan the raw JSON string for patterns
        json_str = json.dumps(response_body) if not isinstance(response_body, str) else response_body
        for pattern, name, severity, compliance, recommendation in self.PATTERNS:
            matches = re.findall(pattern, json_str, re.IGNORECASE)
            # Only add if not already found in structured scan
            if matches and not any(f.pattern_name == name for f in findings):
                for match in matches[:3]:  # Limit to 3 matches per pattern
                    finding = PIIFinding(
                        field_path='<raw_body>',
                        data_type=name,
                        severity=severity,
                        matched_value=self._redact_value(match if isinstance(match, str) else str(match)),
                        pattern_name=name,
                        compliance_impact=compliance,
                        recommendation=recommendation
                    )
                    findings.append(finding)
                    compliance_violations.update(compliance)
        
        # Calculate risk score
        severity_scores = {'CRITICAL': 10.0, 'HIGH': 7.0, 'MEDIUM': 4.0, 'LOW': 1.0}
        if findings:
            max_severity = max(severity_scores.get(f.severity, 0) for f in findings)
            risk_score = min(10.0, max_severity + (len(findings) * 0.5))
        else:
            risk_score = 0.0
        
        return ScanResult(
            endpoint=endpoint,
            findings=findings,
            total_fields_scanned=len(paths),
            sensitive_fields_found=len(findings),
            risk_score=risk_score,
            compliance_violations=list(compliance_violations)
        )
    
    def scan_multiple(self, 
                      responses: List[Tuple[str, Any]]) -> List[ScanResult]:
        """
        Scan multiple responses.
        
        Args:
            responses: List of (endpoint, response_body) tuples
        
        Returns:
            List of ScanResult
        """
        results = []
        for endpoint, body in responses:
            result = self.scan_response(body, endpoint)
            results.append(result)
            if result.findings:
                print(f"[!] Found {len(result.findings)} sensitive fields in {endpoint}")
        return results
    
    def generate_report(self, results: List[ScanResult]) -> Dict:
        """Generate a compliance report."""
        all_findings = []
        all_violations = set()
        
        for result in results:
            all_findings.extend(result.findings)
            all_violations.update(result.compliance_violations)
        
        return {
            "summary": {
                "endpoints_scanned": len(results),
                "total_findings": len(all_findings),
                "compliance_violations": list(all_violations),
                "risk_rating": "CRITICAL" if any(f.severity == "CRITICAL" for f in all_findings) else
                              "HIGH" if any(f.severity == "HIGH" for f in all_findings) else
                              "MEDIUM" if any(f.severity == "MEDIUM" for f in all_findings) else "LOW"
            },
            "by_type": {
                name: len([f for f in all_findings if f.data_type == name])
                for name in set(f.data_type for f in all_findings)
            },
            "by_severity": {
                sev: len([f for f in all_findings if f.severity == sev])
                for sev in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']
            },
            "results": [r.to_dict() for r in results]
        }
