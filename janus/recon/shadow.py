# janus/recon/shadow.py
"""
Shadow API Detector Module.
Compares observed endpoints against OpenAPI/Swagger documentation
to find undocumented (shadow) APIs.
"""

import json
import re
from typing import Dict, List, Any, Optional, Set, Tuple
from dataclasses import dataclass, asdict
from pathlib import Path
import fnmatch

try:
    import yaml
    YAML_AVAILABLE = True
except ImportError:
    YAML_AVAILABLE = False


@dataclass
class ShadowAPIResult:
    """A detected shadow API endpoint."""
    endpoint: str
    method: str
    risk_level: str  # CRITICAL, HIGH, MEDIUM, LOW
    reason: str
    first_seen: Optional[str] = None
    request_count: int = 0
    sample_params: Optional[Dict] = None
    
    def to_dict(self) -> Dict:
        return asdict(self)


@dataclass
class EndpointSpec:
    """An endpoint from the OpenAPI spec."""
    path: str
    method: str
    summary: Optional[str] = None
    deprecated: bool = False
    security: Optional[List] = None


class ShadowAPIDetector:
    """
    Detects undocumented (shadow) API endpoints by comparing
    observed traffic against the official OpenAPI specification.
    """
    
    # High-risk patterns in endpoint names
    HIGH_RISK_PATTERNS = [
        r'/admin',
        r'/internal',
        r'/debug',
        r'/test',
        r'/dev',
        r'/staging',
        r'/beta',
        r'/backup',
        r'/dump',
        r'/export',
        r'/config',
        r'/setup',
        r'/install',
        r'/reset',
        r'/delete',
        r'/purge',
        r'/seed',
        r'/migrate',
        r'/console',
        r'/shell',
        r'/exec',
        r'/eval',
        r'/sql',
        r'/graphql',  # GraphQL endpoints need special attention
        r'/_',  # Underscore-prefixed routes often internal
        r'/\.',  # Dot-prefixed routes (hidden)
    ]
    
    # Patterns that suggest sensitive data
    SENSITIVE_PATTERNS = [
        r'/user',
        r'/account',
        r'/profile',
        r'/password',
        r'/auth',
        r'/token',
        r'/session',
        r'/payment',
        r'/billing',
        r'/credit',
        r'/financial',
        r'/pii',
        r'/private',
        r'/secret',
    ]
    
    def __init__(self):
        self.documented_endpoints: Set[Tuple[str, str]] = set()
        self.observed_endpoints: Dict[Tuple[str, str], Dict] = {}
        self.spec_loaded = False
    
    def load_openapi_spec(self, spec_path: str) -> bool:
        """
        Load an OpenAPI/Swagger specification file.
        
        Args:
            spec_path: Path to openapi.json or openapi.yaml
        """
        try:
            path = Path(spec_path)
            
            if not path.exists():
                print(f"[!] OpenAPI spec not found: {spec_path}")
                return False
            
            with open(path, 'r', encoding='utf-8') as f:
                if path.suffix in ['.yaml', '.yml']:
                    if not YAML_AVAILABLE:
                        print("[!] PyYAML not installed. Install with: pip install pyyaml")
                        return False
                    spec = yaml.safe_load(f)
                else:
                    spec = json.load(f)
            
            # Parse paths
            paths = spec.get('paths', {})
            for path_pattern, methods in paths.items():
                for method in methods.keys():
                    if method.upper() in ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'HEAD', 'OPTIONS']:
                        # Normalize path pattern
                        normalized = self._normalize_path(path_pattern)
                        self.documented_endpoints.add((normalized, method.upper()))
            
            self.spec_loaded = True
            print(f"[+] Loaded OpenAPI spec: {len(self.documented_endpoints)} endpoints")
            return True
            
        except Exception as e:
            print(f"[!] Failed to load OpenAPI spec: {e}")
            return False
    
    def _normalize_path(self, path: str) -> str:
        """
        Normalize a path pattern for comparison.
        Converts path parameters to wildcards.
        
        /users/{id} -> /users/*
        /orders/{order_id}/items/{item_id} -> /orders/*/items/*
        """
        # Replace path parameters
        normalized = re.sub(r'\{[^}]+\}', '*', path)
        # Remove trailing slashes
        normalized = normalized.rstrip('/')
        # Ensure leading slash
        if not normalized.startswith('/'):
            normalized = '/' + normalized
        return normalized
    
    def _match_endpoint(self, observed: str, documented: str) -> bool:
        """
        Check if an observed endpoint matches a documented pattern.
        Uses fnmatch for wildcard matching.
        """
        # Direct match
        if observed == documented:
            return True
        
        # Wildcard match
        if fnmatch.fnmatch(observed, documented):
            return True
        
        # Try matching with wildcards for numeric IDs
        observed_normalized = re.sub(r'/\d+', '/*', observed)
        if observed_normalized == documented:
            return True
        
        # Try matching with wildcards for UUIDs
        observed_normalized = re.sub(r'/[a-f0-9-]{36}', '/*', observed, flags=re.IGNORECASE)
        if observed_normalized == documented:
            return True
        
        return False
    
    def add_observed_endpoint(self, path: str, method: str, 
                              params: Dict = None, timestamp: str = None):
        """
        Add an observed endpoint from traffic.
        
        Args:
            path: The endpoint path (e.g., /api/users/123)
            method: HTTP method
            params: Optional request parameters
            timestamp: When this was observed
        """
        normalized = self._normalize_path(path)
        key = (normalized, method.upper())
        
        if key not in self.observed_endpoints:
            self.observed_endpoints[key] = {
                'original_paths': [path],
                'first_seen': timestamp,
                'count': 1,
                'params': params
            }
        else:
            self.observed_endpoints[key]['count'] += 1
            if path not in self.observed_endpoints[key]['original_paths']:
                self.observed_endpoints[key]['original_paths'].append(path)
    
    def _assess_risk(self, endpoint: str, method: str) -> Tuple[str, str]:
        """
        Assess the risk level of an undocumented endpoint.
        
        Returns:
            Tuple of (risk_level, reason)
        """
        endpoint_lower = endpoint.lower()
        
        # Check high-risk patterns
        for pattern in self.HIGH_RISK_PATTERNS:
            if re.search(pattern, endpoint_lower):
                matched = re.search(pattern, endpoint_lower).group()
                return "CRITICAL", f"Contains high-risk pattern: {matched}"
        
        # Check sensitive patterns
        for pattern in self.SENSITIVE_PATTERNS:
            if re.search(pattern, endpoint_lower):
                matched = re.search(pattern, endpoint_lower).group()
                if method in ['DELETE', 'PUT', 'PATCH']:
                    return "HIGH", f"Write access to sensitive endpoint: {matched}"
                return "MEDIUM", f"Contains sensitive pattern: {matched}"
        
        # Destructive methods are higher risk
        if method in ['DELETE', 'PUT', 'PATCH']:
            return "MEDIUM", f"Undocumented {method} endpoint"
        
        return "LOW", "Undocumented endpoint"
    
    def detect_shadow_apis(self) -> List[ShadowAPIResult]:
        """
        Compare observed endpoints against documented ones.
        
        Returns:
            List of ShadowAPIResult for undocumented endpoints
        """
        if not self.spec_loaded:
            print("[!] No OpenAPI spec loaded. All endpoints will be flagged.")
        
        shadow_apis = []
        
        for (path, method), data in self.observed_endpoints.items():
            # Check if documented
            is_documented = False
            
            if self.spec_loaded:
                for (doc_path, doc_method) in self.documented_endpoints:
                    if method == doc_method and self._match_endpoint(path, doc_path):
                        is_documented = True
                        break
            
            if not is_documented:
                risk_level, reason = self._assess_risk(path, method)
                
                shadow_apis.append(ShadowAPIResult(
                    endpoint=path,
                    method=method,
                    risk_level=risk_level,
                    reason=reason if self.spec_loaded else "No OpenAPI spec loaded - all endpoints flagged",
                    first_seen=data.get('first_seen'),
                    request_count=data.get('count', 0),
                    sample_params=data.get('params')
                ))
        
        # Sort by risk
        risk_order = {'CRITICAL': 0, 'HIGH': 1, 'MEDIUM': 2, 'LOW': 3}
        shadow_apis.sort(key=lambda x: (risk_order.get(x.risk_level, 4), -x.request_count))
        
        return shadow_apis
    
    def load_from_database(self, db) -> None:
        """
        Load observed endpoints from Janus database.
        
        Args:
            db: JanusDatabase instance
        """
        for token in db.get_all_tokens():
            learnings = db.get_learnings(token)
            for entry in learnings:
                path = entry.get('endpoint_template', '').replace('{id}', entry.get('id', '*'))
                method = entry.get('method', 'GET')
                self.add_observed_endpoint(path, method)
    
    def generate_report(self, shadow_apis: List[ShadowAPIResult]) -> Dict:
        """Generate a summary report."""
        return {
            "total_observed": len(self.observed_endpoints),
            "total_documented": len(self.documented_endpoints),
            "shadow_apis_found": len(shadow_apis),
            "by_risk": {
                "CRITICAL": len([s for s in shadow_apis if s.risk_level == "CRITICAL"]),
                "HIGH": len([s for s in shadow_apis if s.risk_level == "HIGH"]),
                "MEDIUM": len([s for s in shadow_apis if s.risk_level == "MEDIUM"]),
                "LOW": len([s for s in shadow_apis if s.risk_level == "LOW"]),
            },
            "shadow_apis": [s.to_dict() for s in shadow_apis]
        }
