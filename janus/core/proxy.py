# janus/core/proxy.py
"""
The Janus Proxy - Traffic Learning Engine.
Hooks into mitmproxy to passively learn user-resource ownership.
"""

from mitmproxy import http
import json
import re
import os
import sys

# Add parent directory to path for imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(__file__))))

from janus.core.database import JanusDatabase


class JanusProxy:
    """
    Mitmproxy addon that learns user-resource ownership patterns.
    """
    
    # Default patterns - can be extended via config
    DEFAULT_PATTERNS = [
        r'/api/[^/]+/(\d+)',           # Generic: /api/anything/123
        r'/api/[^/]+/(\d+)/[^/]+',     # Nested: /api/users/123/orders
        r'/v\d+/[^/]+/(\d+)',          # Versioned: /v1/orders/555
        r'/orders/(\d+)',
        r'/users/(\d+)',
        r'/profile/(\d+)',
        r'/accounts/(\d+)',
        r'/transactions/(\d+)',
        r'/items/(\d+)',
        r'/products/(\d+)',
        r'/documents/(\d+)',
        # UUID patterns
        r'/api/[^/]+/([a-f0-9-]{36})',
        r'/[^/]+/([a-f0-9]{24})',      # MongoDB ObjectId
    ]
    
    def __init__(self, target_hosts=None, patterns=None, db=None):
        self.target_hosts = target_hosts or ["localhost", "127.0.0.1"]
        self.patterns = patterns or self.DEFAULT_PATTERNS
        self.db = db or JanusDatabase()
        self.compiled_patterns = [re.compile(p) for p in self.patterns]
        print(f"--- JANUS PROXY ACTIVE (storage: {self.db.backend_name}) ---")
        print(f"    Monitoring: {', '.join(self.target_hosts)}")
        print(f"    Patterns: {len(self.patterns)} ID patterns loaded")
    
    def _is_target(self, host: str) -> bool:
        """Check if host is in our target list."""
        return any(target in host for target in self.target_hosts)
    
    def _extract_id(self, path: str) -> tuple:
        """Extract resource ID from URL path."""
        for pattern in self.compiled_patterns:
            match = pattern.search(path)
            if match:
                resource_id = match.group(1)
                # Create template by replacing the ID with {id}
                template = pattern.sub(lambda m: m.group().replace(m.group(1), '{id}'), path)
                return resource_id, template
        return None, None
    
    def _extract_token(self, request) -> str:
        """Extract authentication token from request."""
        # Check multiple common auth headers
        auth_headers = [
            "Authorization",
            "X-Auth-Token",
            "X-API-Key",
            "Api-Key",
            "Bearer",
            "X-Access-Token",
        ]
        
        for header in auth_headers:
            value = request.headers.get(header)
            if value:
                return value
        
        # Check cookies for session tokens
        cookies = request.headers.get("Cookie", "")
        if "session" in cookies.lower() or "token" in cookies.lower():
            return f"cookie:{cookies[:50]}"
        
        return None
    
    def response(self, flow: http.HTTPFlow):
        """
        Hook into mitmproxy response handling.
        We analyze responses (not just requests) to only learn from successful calls.
        """
        request = flow.request
        response = flow.response
        
        # Filter: Only target hosts
        if not self._is_target(request.pretty_host):
            return
        
        # Filter: Only successful responses
        if response.status_code >= 400:
            return
        
        # Extract token
        token = self._extract_token(request)
        if not token:
            return
        
        # Extract resource ID
        resource_id, endpoint_template = self._extract_id(request.path)
        if not resource_id:
            return
        
        # Store the learning
        entry = {
            "method": request.method,
            "endpoint_template": endpoint_template,
            "id": resource_id,
            "original_response_size": len(response.content),
            "content_type": response.headers.get("Content-Type", "unknown"),
        }
        
        self.db.store_learning(token, entry)
        
        # Log
        token_preview = token[:15] + "..." if len(token) > 15 else token
        print(f"[+] LEARNED: {token_preview} owns ID {resource_id} on {endpoint_template}")


# Create global instance for mitmproxy
_proxy = JanusProxy()

def response(flow: http.HTTPFlow):
    """Entry point for mitmproxy."""
    _proxy.response(flow)
