# tests/test_bfla.py
"""
Tests for the BFLA (Broken Function Level Authorization) Scanner.
Verifies detection of vertical privilege escalation vulnerabilities.
"""

import pytest
from janus.attack.bfla import BFLAScanner


class TestBFLAScanner:
    """Tests for BFLAScanner class."""
    
    def test_scanner_initialization(self):
        """Test scanner can be initialized."""
        scanner = BFLAScanner()
        assert scanner is not None
    
    def test_scan_admin_endpoints(self, live_server, alice_token):
        """Test scanning admin endpoints with low-privilege token."""
        scanner = BFLAScanner()
        
        endpoints = [
            '/api/admin/users',
            '/api/admin/config',
            '/api/admin/export',
        ]
        
        results = scanner.scan_endpoints(
            base_url=live_server,
            endpoints=endpoints,
            low_priv_token=alice_token
        )
        
        assert len(results) == len(endpoints)
        
        # bad_bank.py has BFLA vulnerabilities - should find some
        vulnerable = [r for r in results if r.vulnerable]
        assert len(vulnerable) > 0, "Should detect BFLA vulnerabilities in bad_bank"
    
    def test_finding_contains_evidence(self, live_server, alice_token):
        """Test that findings include evidence."""
        scanner = BFLAScanner()
        
        results = scanner.scan_endpoints(
            base_url=live_server,
            endpoints=['/api/admin/config'],
            low_priv_token=alice_token
        )
        
        for result in results:
            assert result.evidence is not None
            assert len(result.evidence) > 0
    
    def test_finding_has_severity(self, live_server, alice_token):
        """Test that findings have severity levels."""
        scanner = BFLAScanner()
        
        results = scanner.scan_endpoints(
            base_url=live_server,
            endpoints=['/api/admin/users'],
            low_priv_token=alice_token
        )
        
        for result in results:
            assert result.severity in ["LOW", "MEDIUM", "HIGH", "CRITICAL"]
    
    def test_secure_endpoint_not_flagged(self, live_server, alice_token):
        """Test that secure endpoints are not incorrectly flagged."""
        scanner = BFLAScanner()
        
        # Test a non-existent endpoint - should not be vulnerable (404)
        results = scanner.scan_endpoints(
            base_url=live_server,
            endpoints=['/api/nonexistent/secure/endpoint'],
            low_priv_token=alice_token
        )
        
        for result in results:
            # Non-existent endpoints should not be marked vulnerable
            if result.response_status == 404:
                assert not result.vulnerable


class TestBFLAFindingDataclass:
    """Tests for BFLA finding data structure."""
    
    def test_finding_to_dict(self, live_server, alice_token):
        """Test that findings can be serialized to dict."""
        scanner = BFLAScanner()
        
        results = scanner.scan_endpoints(
            base_url=live_server,
            endpoints=['/api/admin/config'],
            low_priv_token=alice_token
        )
        
        if results:
            result_dict = results[0].to_dict()
            assert 'endpoint' in result_dict
            assert 'method' in result_dict
            assert 'vulnerable' in result_dict
            assert 'severity' in result_dict
    
    def test_finding_has_recommendation(self, live_server, alice_token):
        """Test that vulnerable findings include recommendations."""
        scanner = BFLAScanner()
        
        results = scanner.scan_endpoints(
            base_url=live_server,
            endpoints=['/api/admin/users'],
            low_priv_token=alice_token
        )
        
        vulnerable = [r for r in results if r.vulnerable]
        for result in vulnerable:
            assert result.recommendation is not None
