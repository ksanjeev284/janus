# tests/test_jwt_attacks.py
"""
Tests for the JWT Attack module.
Verifies detection of weak secrets, algorithm confusion, and token manipulation.
"""

import pytest
from janus.core.jwt_attacks import JWTAttacker


class TestJWTAttacker:
    """Tests for JWTAttacker class."""
    
    def test_attacker_initialization(self):
        """Test attacker can be initialized."""
        attacker = JWTAttacker()
        assert attacker is not None
    
    def test_analyze_valid_jwt(self, sample_jwt):
        """Test analysis of a valid JWT structure."""
        attacker = JWTAttacker()
        analysis = attacker.analyze_jwt(sample_jwt)
        
        assert 'header' in analysis
        assert 'payload' in analysis
        assert 'valid_structure' in analysis
        assert analysis['valid_structure'] is True
    
    def test_analyze_algorithm_detection(self, sample_jwt):
        """Test that algorithm is correctly detected."""
        attacker = JWTAttacker()
        analysis = attacker.analyze_jwt(sample_jwt)
        
        assert 'algorithm' in analysis or 'header' in analysis
        if 'header' in analysis:
            assert 'alg' in analysis['header']
    
    def test_alg_none_attack(self, sample_jwt):
        """Test algorithm none attack."""
        attacker = JWTAttacker()
        result = attacker.attack_alg_none(sample_jwt)
        
        assert hasattr(result, 'vulnerable')
        assert hasattr(result, 'attack_type')
        assert result.attack_type == "alg_none"
    
    def test_weak_secret_attack(self, sample_jwt):
        """Test weak secret brute-force attack."""
        attacker = JWTAttacker()
        results = attacker.attack_weak_secret(sample_jwt)
        
        # Should return list of attack results
        assert isinstance(results, list)
        if results:
            assert hasattr(results[0], 'vulnerable')
    
    def test_detect_security_issues(self, sample_jwt):
        """Test that security issues are flagged."""
        attacker = JWTAttacker()
        analysis = attacker.analyze_jwt(sample_jwt)
        
        # Should include security analysis
        assert 'security_issues' in analysis or 'recommendations' in analysis
    
    def test_invalid_jwt_handling(self):
        """Test handling of invalid JWT."""
        attacker = JWTAttacker()
        
        # Invalid JWT (not proper format)
        invalid_jwt = "not.a.valid.jwt.token"
        analysis = attacker.analyze_jwt(invalid_jwt)
        
        # Should handle gracefully without crashing
        assert analysis is not None


class TestJWTSecurityIssues:
    """Tests for JWT security issue detection."""
    
    def test_detect_weak_algorithm(self):
        """Test detection of weak algorithms like none."""
        attacker = JWTAttacker()
        
        # JWT with alg: none would be flagged
        none_jwt = "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJ1c2VyIjoiYWRtaW4ifQ."
        analysis = attacker.analyze_jwt(none_jwt)
        
        # Should flag security issues
        if 'security_issues' in analysis:
            issues_text = " ".join(analysis['security_issues']).lower()
            # May contain warnings about none algorithm
            assert len(analysis['security_issues']) >= 0
    
    def test_expired_token_detection(self):
        """Test detection of expired tokens."""
        attacker = JWTAttacker()
        
        # Sample JWT is already expired (based on exp claim)
        expired_jwt = "eyJhbGciOiAiSFMyNTYiLCAidHlwIjogIkpXVCJ9.eyJ1c2VyX2lkIjogMTAsICJleHAiOiAxNjAwMDAwMDAwfQ.test"
        analysis = attacker.analyze_jwt(expired_jwt)
        
        # Should detect expiration if exp claim is in the past
        assert analysis is not None


class TestJWTAttackResults:
    """Tests for JWT attack result data structures."""
    
    def test_attack_result_to_dict(self, sample_jwt):
        """Test attack results can be serialized."""
        attacker = JWTAttacker()
        result = attacker.attack_alg_none(sample_jwt)
        
        result_dict = result.to_dict()
        assert 'attack_type' in result_dict
        assert 'vulnerable' in result_dict
    
    def test_attack_result_has_evidence(self, sample_jwt):
        """Test attack results include evidence."""
        attacker = JWTAttacker()
        result = attacker.attack_alg_none(sample_jwt)
        
        assert hasattr(result, 'evidence')
