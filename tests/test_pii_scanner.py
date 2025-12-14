# tests/test_pii_scanner.py
"""
Tests for the PII Scanner module.
Verifies detection of sensitive data like SSN, credit cards, API keys, etc.
"""

import pytest
from janus.analysis.pii_scanner import PIIScanner


class TestPIIScanner:
    """Tests for PIIScanner class."""
    
    def test_scanner_initialization(self):
        """Test scanner can be initialized."""
        scanner = PIIScanner()
        assert scanner is not None
    
    def test_scanner_strict_mode(self):
        """Test scanner in strict mode."""
        scanner = PIIScanner(strict_mode=True)
        assert scanner.strict_mode is True
    
    def test_detect_ssn(self):
        """Test SSN detection."""
        scanner = PIIScanner(strict_mode=True)
        data = {"user": {"ssn": "123-45-6789"}}
        result = scanner.scan_response(data, "/api/test")
        
        assert len(result.findings) > 0
        ssn_findings = [f for f in result.findings if f.data_type == "SSN"]
        assert len(ssn_findings) > 0
    
    def test_detect_email(self):
        """Test email detection."""
        scanner = PIIScanner(strict_mode=True)
        data = {"contact": {"email": "user@example.com"}}
        result = scanner.scan_response(data, "/api/test")
        
        email_findings = [f for f in result.findings if f.data_type == "EMAIL"]
        assert len(email_findings) > 0
    
    def test_detect_phone(self):
        """Test phone number detection."""
        scanner = PIIScanner(strict_mode=True)
        data = {"phone": "555-123-4567"}
        result = scanner.scan_response(data, "/api/test")
        
        phone_findings = [f for f in result.findings if f.data_type == "PHONE"]
        assert len(phone_findings) > 0
    
    def test_detect_api_key(self):
        """Test API key detection."""
        scanner = PIIScanner(strict_mode=True)
        data = {"config": {"api_key": "sk_live_abcdef123456789"}}
        result = scanner.scan_response(data, "/api/test")
        
        api_findings = [f for f in result.findings if "API" in f.data_type or "KEY" in f.data_type]
        assert len(api_findings) > 0
    
    def test_detect_aws_key(self):
        """Test AWS access key detection."""
        scanner = PIIScanner(strict_mode=True)
        data = {"aws_key": "AKIAIOSFODNN7EXAMPLE"}
        result = scanner.scan_response(data, "/api/test")
        
        aws_findings = [f for f in result.findings if "AWS" in f.data_type]
        assert len(aws_findings) > 0
    
    def test_detect_credit_card(self):
        """Test credit card number detection."""
        scanner = PIIScanner(strict_mode=True)
        data = {"payment": {"card_number": "4532015112830366"}}
        result = scanner.scan_response(data, "/api/test")
        
        cc_findings = [f for f in result.findings if "CREDIT" in f.data_type or "CARD" in f.data_type]
        assert len(cc_findings) > 0
    
    def test_no_false_positive_on_safe_data(self):
        """Test that safe data doesn't trigger false positives."""
        scanner = PIIScanner(strict_mode=False)  # Non-strict to avoid field name matching
        data = {"id": 123, "name": "Test Product", "price": 99.99}
        result = scanner.scan_response(data, "/api/test")
        
        # Should have minimal or no findings for benign data
        critical_findings = [f for f in result.findings if f.severity == "CRITICAL"]
        assert len(critical_findings) == 0
    
    def test_compliance_violations(self):
        """Test that compliance violations are correctly identified."""
        scanner = PIIScanner(strict_mode=True)
        data = {"ssn": "123-45-6789", "email": "user@test.com"}
        result = scanner.scan_response(data, "/api/test")
        
        # Should flag GDPR and CCPA for PII
        assert len(result.compliance_violations) > 0
    
    def test_risk_score_calculation(self):
        """Test risk score is calculated correctly."""
        scanner = PIIScanner(strict_mode=True)
        
        # High-risk data
        high_risk_data = {"ssn": "123-45-6789", "api_key": "sk_live_test"}
        high_result = scanner.scan_response(high_risk_data, "/api/test")
        
        # Low-risk data  
        low_risk_data = {"email": "user@example.com"}
        low_result = scanner.scan_response(low_risk_data, "/api/test")
        
        # High-risk should have higher score
        assert high_result.risk_score >= low_result.risk_score
    
    def test_nested_pii_detection(self):
        """Test PII detection in nested structures."""
        scanner = PIIScanner(strict_mode=True)
        data = {
            "user": {
                "profile": {
                    "personal": {
                        "ssn": "987-65-4321"
                    }
                }
            }
        }
        result = scanner.scan_response(data, "/api/test")
        
        ssn_findings = [f for f in result.findings if f.data_type == "SSN"]
        assert len(ssn_findings) > 0
        # Check path includes nesting
        assert "user" in ssn_findings[0].field_path or "personal" in ssn_findings[0].field_path
    
    def test_array_pii_detection(self):
        """Test PII detection in arrays."""
        scanner = PIIScanner(strict_mode=True)
        data = {
            "users": [
                {"ssn": "111-22-3333"},
                {"ssn": "444-55-6666"}
            ]
        }
        result = scanner.scan_response(data, "/api/test")
        
        ssn_findings = [f for f in result.findings if f.data_type == "SSN"]
        assert len(ssn_findings) >= 2


class TestPIIFindingSeverity:
    """Tests for PII finding severity levels."""
    
    def test_ssn_is_critical(self):
        """SSN should be marked as CRITICAL."""
        scanner = PIIScanner(strict_mode=True)
        data = {"ssn": "123-45-6789"}
        result = scanner.scan_response(data, "/test")
        
        ssn_findings = [f for f in result.findings if f.data_type == "SSN"]
        if ssn_findings:
            assert ssn_findings[0].severity == "CRITICAL"
    
    def test_api_key_is_critical(self):
        """API keys should be marked as CRITICAL."""
        scanner = PIIScanner(strict_mode=True)
        data = {"api_key": "sk_live_abcdef123456"}
        result = scanner.scan_response(data, "/test")
        
        # Any secret/key finding should be critical
        critical_findings = [f for f in result.findings if f.severity == "CRITICAL"]
        assert len(critical_findings) > 0
