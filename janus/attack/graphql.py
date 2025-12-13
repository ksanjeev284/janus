# janus/attack/graphql.py
"""
GraphQL Attack Module - The "Shatter" Module.
Tests for common GraphQL vulnerabilities.
"""

import asyncio
import json
from typing import Dict, List, Any, Optional, Tuple
from dataclasses import dataclass, asdict

try:
    import aiohttp
    AIOHTTP_AVAILABLE = True
except ImportError:
    AIOHTTP_AVAILABLE = False
    import requests


@dataclass
class GraphQLAttackResult:
    """Result of a GraphQL attack."""
    attack_type: str
    vulnerable: bool
    severity: str  # CRITICAL, HIGH, MEDIUM, LOW
    evidence: str
    recommendation: str
    response_sample: Optional[str] = None
    response_time_ms: Optional[float] = None
    
    def to_dict(self) -> Dict:
        return asdict(self)


class GraphQLAttacker:
    """
    GraphQL-specific attack module.
    
    Attacks:
    1. Introspection - Reveal schema/types
    2. Depth Attack - Deeply nested queries (DoS)
    3. Batching Attack - Multiple queries in one request
    4. Field Suggestions - Leak field names via errors
    5. Mutation Probing - Find write operations
    """
    
    # Standard introspection query
    INTROSPECTION_QUERY = """
    query IntrospectionQuery {
      __schema {
        queryType { name }
        mutationType { name }
        subscriptionType { name }
        types {
          ...FullType
        }
        directives {
          name
          description
          locations
          args {
            ...InputValue
          }
        }
      }
    }
    
    fragment FullType on __Type {
      kind
      name
      description
      fields(includeDeprecated: true) {
        name
        description
        args {
          ...InputValue
        }
        type {
          ...TypeRef
        }
        isDeprecated
        deprecationReason
      }
      inputFields {
        ...InputValue
      }
      interfaces {
        ...TypeRef
      }
      enumValues(includeDeprecated: true) {
        name
        description
        isDeprecated
        deprecationReason
      }
      possibleTypes {
        ...TypeRef
      }
    }
    
    fragment InputValue on __InputValue {
      name
      description
      type {
        ...TypeRef
      }
      defaultValue
    }
    
    fragment TypeRef on __Type {
      kind
      name
      ofType {
        kind
        name
        ofType {
          kind
          name
          ofType {
            kind
            name
          }
        }
      }
    }
    """
    
    # Simpler introspection for faster check
    SIMPLE_INTROSPECTION = """
    query {
      __schema {
        types {
          name
          fields {
            name
          }
        }
      }
    }
    """
    
    # Just type names
    MINIMAL_INTROSPECTION = """
    query { __schema { types { name } } }
    """
    
    def __init__(self, timeout: int = 30):
        self.timeout = timeout
    
    def _make_request(self, url: str, query: str, variables: Dict = None,
                      headers: Dict = None) -> Tuple[int, Any, float]:
        """
        Make a GraphQL request.
        
        Returns:
            Tuple of (status_code, response_json, response_time_ms)
        """
        import time
        
        request_headers = {
            "Content-Type": "application/json",
            **(headers or {})
        }
        
        payload = {"query": query}
        if variables:
            payload["variables"] = variables
        
        start = time.time()
        
        try:
            response = requests.post(
                url,
                json=payload,
                headers=request_headers,
                timeout=self.timeout
            )
            elapsed = (time.time() - start) * 1000
            
            try:
                body = response.json()
            except json.JSONDecodeError:
                body = {"_raw": response.text[:500]}
            
            return response.status_code, body, elapsed
            
        except requests.Timeout:
            return 0, {"error": "timeout"}, self.timeout * 1000
        except Exception as e:
            return 0, {"error": str(e)}, 0
    
    async def _make_request_async(self, url: str, query: str, 
                                   variables: Dict = None,
                                   headers: Dict = None) -> Tuple[int, Any, float]:
        """Async version of make_request."""
        import time
        
        if not AIOHTTP_AVAILABLE:
            return self._make_request(url, query, variables, headers)
        
        request_headers = {
            "Content-Type": "application/json",
            **(headers or {})
        }
        
        payload = {"query": query}
        if variables:
            payload["variables"] = variables
        
        start = time.time()
        
        try:
            async with aiohttp.ClientSession() as session:
                async with session.post(
                    url,
                    json=payload,
                    headers=request_headers,
                    timeout=aiohttp.ClientTimeout(total=self.timeout)
                ) as response:
                    elapsed = (time.time() - start) * 1000
                    try:
                        body = await response.json()
                    except:
                        body = {"_raw": await response.text()}
                    return response.status, body, elapsed
                    
        except asyncio.TimeoutError:
            return 0, {"error": "timeout"}, self.timeout * 1000
        except Exception as e:
            return 0, {"error": str(e)}, 0
    
    def attack_introspection(self, url: str, headers: Dict = None) -> GraphQLAttackResult:
        """
        Test if GraphQL introspection is enabled.
        
        Risk: Introspection reveals the entire API schema, types, and operations.
        """
        print(f"[*] Testing GraphQL introspection on {url}")
        
        # Try minimal first (faster)
        status, body, elapsed = self._make_request(url, self.MINIMAL_INTROSPECTION, headers=headers)
        
        if status == 0:
            return GraphQLAttackResult(
                attack_type="introspection",
                vulnerable=False,
                severity="INFO",
                evidence=f"Request failed: {body.get('error', 'unknown')}",
                recommendation=""
            )
        
        # Check if introspection returned data
        if "data" in body and body["data"]:
            schema = body.get("data", {}).get("__schema", {})
            types = schema.get("types", [])
            
            if types:
                # Get full introspection
                _, full_body, _ = self._make_request(url, self.SIMPLE_INTROSPECTION, headers=headers)
                
                type_names = [t.get("name") for t in types if not t.get("name", "").startswith("__")]
                
                return GraphQLAttackResult(
                    attack_type="introspection",
                    vulnerable=True,
                    severity="HIGH",
                    evidence=f"Introspection enabled! Found {len(type_names)} types: {', '.join(type_names[:10])}{'...' if len(type_names) > 10 else ''}",
                    recommendation="Disable introspection in production. Set introspection: false in your GraphQL server config.",
                    response_sample=json.dumps(types[:5], indent=2)[:500]
                )
        
        # Check for errors that might indicate partial success
        errors = body.get("errors", [])
        if errors:
            error_msg = errors[0].get("message", "") if errors else ""
            if "introspection" in error_msg.lower():
                return GraphQLAttackResult(
                    attack_type="introspection",
                    vulnerable=False,
                    severity="INFO",
                    evidence=f"Introspection disabled: {error_msg[:100]}",
                    recommendation=""
                )
        
        return GraphQLAttackResult(
            attack_type="introspection",
            vulnerable=False,
            severity="INFO",
            evidence="Introspection query returned no data",
            recommendation=""
        )
    
    def attack_depth(self, url: str, depth: int = 20, 
                     headers: Dict = None) -> GraphQLAttackResult:
        """
        Test for query depth limit vulnerability (DoS).
        
        Risk: Deeply nested queries can overload the server.
        """
        print(f"[*] Testing GraphQL depth limit with {depth} levels")
        
        # Build a deeply nested query
        # We need to know a type that references itself. Try common patterns.
        test_queries = [
            # Self-referential User -> friends pattern
            self._build_depth_query("user", "friends", "id", depth),
            # Post -> comments -> replies pattern
            self._build_depth_query("post", "comments", "id", depth),
            # Node pattern (common in Relay)
            self._build_depth_query("node", "children", "id", depth),
            # Generic nested
            self._build_depth_query("item", "related", "id", depth),
        ]
        
        for query in test_queries:
            status, body, elapsed = self._make_request(url, query, headers=headers)
            
            if status == 0:
                if elapsed >= self.timeout * 1000 * 0.9:
                    # Timeout - might indicate vulnerability
                    return GraphQLAttackResult(
                        attack_type="depth_limit",
                        vulnerable=True,
                        severity="HIGH",
                        evidence=f"Request timed out after {elapsed:.0f}ms - server may be overloaded",
                        recommendation="Implement query depth limiting (e.g., graphql-depth-limit)",
                        response_time_ms=elapsed
                    )
                continue
            
            # Check if query was executed (even with errors about fields not existing)
            if "data" in body:
                return GraphQLAttackResult(
                    attack_type="depth_limit",
                    vulnerable=True,
                    severity="MEDIUM",
                    evidence=f"Deep query ({depth} levels) was processed in {elapsed:.0f}ms",
                    recommendation="Implement query depth limiting",
                    response_time_ms=elapsed,
                    response_sample=json.dumps(body)[:300]
                )
            
            # Check for depth limit error
            errors = body.get("errors", [])
            for error in errors:
                msg = error.get("message", "").lower()
                if "depth" in msg or "too deep" in msg or "exceeds" in msg:
                    return GraphQLAttackResult(
                        attack_type="depth_limit",
                        vulnerable=False,
                        severity="INFO",
                        evidence=f"Depth limit enforced: {error.get('message', '')[:100]}",
                        recommendation=""
                    )
        
        return GraphQLAttackResult(
            attack_type="depth_limit",
            vulnerable=False,
            severity="INFO",
            evidence="Could not determine depth limit status (queries may not match schema)",
            recommendation="Verify depth limiting is configured"
        )
    
    def _build_depth_query(self, root: str, nested: str, field: str, depth: int) -> str:
        """Build a deeply nested query."""
        inner = field
        for _ in range(depth):
            inner = f"{nested} {{ {inner} }}"
        return f"query {{ {root} {{ {inner} }} }}"
    
    def attack_batching(self, url: str, batch_size: int = 50,
                        headers: Dict = None) -> GraphQLAttackResult:
        """
        Test for query batching vulnerability.
        
        Risk: Batch queries can bypass rate limiting and amplify attacks.
        """
        print(f"[*] Testing GraphQL batching with {batch_size} queries")
        
        # Build batch of introspection queries
        batch = [{"query": "query { __typename }"} for _ in range(batch_size)]
        
        request_headers = {
            "Content-Type": "application/json",
            **(headers or {})
        }
        
        try:
            response = requests.post(
                url,
                json=batch,
                headers=request_headers,
                timeout=self.timeout
            )
            
            if response.status_code == 200:
                body = response.json()
                if isinstance(body, list) and len(body) > 1:
                    return GraphQLAttackResult(
                        attack_type="batching",
                        vulnerable=True,
                        severity="MEDIUM",
                        evidence=f"Batching enabled! Server processed {len(body)} queries in one request",
                        recommendation="Limit batch size or disable batching. Implement query cost analysis.",
                        response_sample=json.dumps(body[:3])[:300]
                    )
        except Exception as e:
            print(f"[!] Batching test error: {e}")
        
        return GraphQLAttackResult(
            attack_type="batching",
            vulnerable=False,
            severity="INFO",
            evidence="Batching not detected or disabled",
            recommendation=""
        )
    
    def attack_field_suggestion(self, url: str, 
                                headers: Dict = None) -> GraphQLAttackResult:
        """
        Test for field suggestion leaks in error messages.
        
        Risk: Error messages can reveal valid field names.
        """
        print("[*] Testing for field suggestion leaks")
        
        # Query with intentionally wrong field name
        test_query = """
        query { 
            usre { id }
        }
        """
        
        status, body, _ = self._make_request(url, test_query, headers=headers)
        
        errors = body.get("errors", [])
        for error in errors:
            msg = error.get("message", "")
            # Look for suggestions
            if "did you mean" in msg.lower() or "similar" in msg.lower():
                return GraphQLAttackResult(
                    attack_type="field_suggestion",
                    vulnerable=True,
                    severity="LOW",
                    evidence=f"Field suggestions leak valid names: {msg[:200]}",
                    recommendation="Disable field suggestions in production to prevent information disclosure"
                )
        
        return GraphQLAttackResult(
            attack_type="field_suggestion",
            vulnerable=False,
            severity="INFO",
            evidence="No field suggestions detected in errors",
            recommendation=""
        )
    
    def scan_graphql(self, url: str, headers: Dict = None,
                     full_scan: bool = True) -> List[GraphQLAttackResult]:
        """
        Run all GraphQL attacks against a target.
        
        Args:
            url: GraphQL endpoint URL
            headers: Optional auth headers
            full_scan: If True, run all attacks
        
        Returns:
            List of GraphQLAttackResult
        """
        print(f"\n[*] Starting GraphQL scan on {url}")
        results = []
        
        # Always test introspection
        results.append(self.attack_introspection(url, headers))
        
        if full_scan:
            # Test depth limit
            results.append(self.attack_depth(url, depth=20, headers=headers))
            
            # Test batching
            results.append(self.attack_batching(url, headers=headers))
            
            # Test field suggestions
            results.append(self.attack_field_suggestion(url, headers))
        
        # Summary
        vulnerable = [r for r in results if r.vulnerable]
        print(f"\n[+] GraphQL scan complete: {len(vulnerable)}/{len(results)} vulnerabilities found")
        
        return results
    
    async def scan_graphql_async(self, url: str, headers: Dict = None) -> List[GraphQLAttackResult]:
        """Async version of scan_graphql."""
        # For now, just wrap the sync version
        # In production, you'd parallelize the attacks
        return self.scan_graphql(url, headers)
