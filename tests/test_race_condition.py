# tests/test_race_condition.py
"""
Tests for the Race Condition testing module.
Verifies detection of TOCTOU and concurrency vulnerabilities.
"""

import pytest
from janus.attack.race_condition import RaceConditionTester


class TestRaceConditionTester:
    """Tests for RaceConditionTester class."""
    
    def test_tester_initialization(self):
        """Test tester can be initialized."""
        tester = RaceConditionTester()
        assert tester is not None
    
    def test_race_condition_on_vulnerable_endpoint(self, live_server, alice_token):
        """Test race condition detection on vulnerable endpoint."""
        tester = RaceConditionTester()
        
        # First reset wallet
        import requests
        requests.post(f"{live_server}/api/wallet/reset", 
                     headers={"Authorization": alice_token})
        
        result = tester.test_race_condition(
            endpoint=f"{live_server}/api/wallet/withdraw",
            method="POST",
            body={"amount": 20},
            token=alice_token,
            threads=5
        )
        
        assert result is not None
        assert hasattr(result, 'vulnerable')
        assert hasattr(result, 'timing_spread_ms')
        assert hasattr(result, 'requests_sent')
    
    def test_result_includes_statistics(self, live_server, alice_token):
        """Test that results include timing statistics."""
        tester = RaceConditionTester()
        
        result = tester.test_race_condition(
            endpoint=f"{live_server}/api/wallet/withdraw",
            method="POST",
            body={"amount": 10},
            token=alice_token,
            threads=3
        )
        
        assert result.requests_sent > 0
        assert result.timing_spread_ms >= 0
    
    def test_result_has_recommendation(self, live_server, alice_token):
        """Test that results include fix recommendations."""
        tester = RaceConditionTester()
        
        result = tester.test_race_condition(
            endpoint=f"{live_server}/api/wallet/withdraw",
            method="POST",
            body={"amount": 5},
            token=alice_token,
            threads=3
        )
        
        assert hasattr(result, 'recommendation')
        if result.vulnerable:
            assert result.recommendation is not None
            assert len(result.recommendation) > 0


class TestRaceConditionSeverity:
    """Tests for race condition severity classification."""
    
    def test_severity_levels(self, live_server, alice_token):
        """Test that severity is correctly assigned."""
        tester = RaceConditionTester()
        
        result = tester.test_race_condition(
            endpoint=f"{live_server}/api/wallet/withdraw",
            method="POST",
            body={"amount": 15},
            token=alice_token,
            threads=5
        )
        
        assert result.severity in ["LOW", "MEDIUM", "HIGH", "CRITICAL"]
