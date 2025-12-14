# janus/attack/graphql_introspection.py
"""
GraphQL Introspection & Security Analyzer.

Advanced GraphQL security testing:
- Schema introspection
- Hidden query/mutation discovery
- Field suggestion attacks
- Depth limit testing
- Batch query attacks
- Query complexity analysis
"""

import requests
import json
from dataclasses import dataclass, field, asdict
from typing import Dict, List, Any, Optional, Set
from datetime import datetime


@dataclass
class GraphQLType:
    """A GraphQL type discovered through introspection."""
    name: str
    kind: str  # OBJECT, INPUT_OBJECT, ENUM, SCALAR, etc.
    fields: List[str] = field(default_factory=list)
    description: Optional[str] = None
    
    def to_dict(self) -> Dict:
        return asdict(self)


@dataclass
class GraphQLOperation:
    """A GraphQL query or mutation."""
    name: str
    operation_type: str  # query, mutation, subscription
    arguments: List[str] = field(default_factory=list)
    return_type: str = ""
    description: Optional[str] = None
    
    def to_dict(self) -> Dict:
        return asdict(self)


@dataclass 
class GraphQLSecurityFinding:
    """A security finding in GraphQL."""
    issue: str
    severity: str
    evidence: str
    recommendation: str
    
    def to_dict(self) -> Dict:
        return asdict(self)


@dataclass
class GraphQLReport:
    """GraphQL introspection and security report."""
    endpoint: str
    scan_time: str
    introspection_enabled: bool
    types_discovered: int
    queries_found: int
    mutations_found: int
    subscriptions_found: int
    security_findings: List[GraphQLSecurityFinding] = field(default_factory=list)
    types: List[GraphQLType] = field(default_factory=list)
    queries: List[GraphQLOperation] = field(default_factory=list)
    mutations: List[GraphQLOperation] = field(default_factory=list)
    subscriptions: List[GraphQLOperation] = field(default_factory=list)
    sensitive_fields: List[str] = field(default_factory=list)
    
    def to_dict(self) -> Dict:
        return {
            'endpoint': self.endpoint,
            'scan_time': self.scan_time,
            'introspection_enabled': self.introspection_enabled,
            'types_discovered': self.types_discovered,
            'queries_found': self.queries_found,
            'mutations_found': self.mutations_found,
            'subscriptions_found': self.subscriptions_found,
            'security_findings': [f.to_dict() for f in self.security_findings],
            'types': [t.to_dict() for t in self.types],
            'queries': [q.to_dict() for q in self.queries],
            'mutations': [m.to_dict() for m in self.mutations],
            'subscriptions': [s.to_dict() for s in self.subscriptions],
            'sensitive_fields': self.sensitive_fields
        }


class GraphQLIntrospector:
    """
    GraphQL Security Analyzer.
    
    Performs introspection and security analysis on GraphQL endpoints.
    """
    
    # Full introspection query
    INTROSPECTION_QUERY = '''
    query IntrospectionQuery {
      __schema {
        queryType { name }
        mutationType { name }
        subscriptionType { name }
        types {
          kind
          name
          description
          fields(includeDeprecated: true) {
            name
            description
            args {
              name
              type { name kind ofType { name kind } }
            }
            type { name kind ofType { name kind ofType { name kind } } }
          }
          inputFields {
            name
            type { name kind }
          }
          enumValues(includeDeprecated: true) {
            name
            description
          }
        }
        directives {
          name
          description
          locations
        }
      }
    }
    '''
    
    # Sensitive field names to flag
    SENSITIVE_FIELDS = [
        'password', 'passwd', 'pwd', 'secret', 'token', 'apiKey', 'api_key',
        'accessToken', 'access_token', 'refreshToken', 'refresh_token',
        'privateKey', 'private_key', 'ssn', 'creditCard', 'credit_card',
        'cvv', 'pin', 'authToken', 'auth_token', 'sessionId', 'session_id',
        'adminPassword', 'admin_password', 'rootPassword', 'root_password',
        'internalId', 'internal_id', 'debug', 'isAdmin', 'is_admin',
        'role', 'permissions', 'privilege'
    ]
    
    # Dangerous mutations
    DANGEROUS_MUTATIONS = [
        'delete', 'remove', 'drop', 'destroy', 'reset', 'admin', 'root',
        'updateRole', 'update_role', 'setPassword', 'set_password',
        'createAdmin', 'create_admin', 'deleteAll', 'delete_all',
        'truncate', 'wipe', 'purge', 'disable', 'enable'
    ]
    
    def __init__(self, timeout: int = 30):
        self.timeout = timeout
    
    def analyze(
        self,
        endpoint: str,
        token: Optional[str] = None,
        deep_scan: bool = True
    ) -> GraphQLReport:
        """
        Perform full GraphQL security analysis.
        
        Args:
            endpoint: GraphQL endpoint URL
            token: Authorization token
            deep_scan: Whether to perform additional security tests
        
        Returns:
            GraphQLReport with findings
        """
        headers = self._build_headers(token)
        security_findings = []
        types = []
        queries = []
        mutations = []
        subscriptions = []
        sensitive_fields = []
        
        # Step 1: Try introspection
        introspection_enabled = False
        schema = self._run_introspection(endpoint, headers)
        
        if schema:
            introspection_enabled = True
            security_findings.append(GraphQLSecurityFinding(
                issue='Introspection Enabled',
                severity='MEDIUM',
                evidence='Full schema introspection is enabled',
                recommendation='Disable introspection in production environments'
            ))
            
            # Parse schema
            types, queries, mutations, subscriptions = self._parse_schema(schema)
            
            # Find sensitive fields
            sensitive_fields = self._find_sensitive_fields(types)
            if sensitive_fields:
                security_findings.append(GraphQLSecurityFinding(
                    issue='Sensitive Fields Exposed',
                    severity='HIGH',
                    evidence=f"Found {len(sensitive_fields)} potentially sensitive fields: {', '.join(sensitive_fields[:5])}",
                    recommendation='Review and restrict access to sensitive fields'
                ))
            
            # Check for dangerous mutations
            dangerous = self._find_dangerous_mutations(mutations)
            if dangerous:
                security_findings.append(GraphQLSecurityFinding(
                    issue='Dangerous Mutations Available',
                    severity='HIGH',
                    evidence=f"Found potentially dangerous mutations: {', '.join(dangerous[:5])}",
                    recommendation='Ensure proper authorization on administrative mutations'
                ))
        
        if deep_scan:
            # Test for batch query attacks
            if self._test_batch_queries(endpoint, headers):
                security_findings.append(GraphQLSecurityFinding(
                    issue='Batch Queries Allowed',
                    severity='MEDIUM',
                    evidence='Server accepts multiple queries in a single request',
                    recommendation='Implement batch query limits to prevent DoS attacks'
                ))
            
            # Test for deep nesting (DoS)
            depth = self._test_query_depth(endpoint, headers)
            if depth > 10:
                security_findings.append(GraphQLSecurityFinding(
                    issue='No Query Depth Limit',
                    severity='HIGH',
                    evidence=f'Server accepts queries with depth > {depth}',
                    recommendation='Implement query depth limiting (recommended: 10)'
                ))
            
            # Test field suggestions
            if self._test_field_suggestions(endpoint, headers):
                security_findings.append(GraphQLSecurityFinding(
                    issue='Field Suggestions Enabled',
                    severity='LOW',
                    evidence='Error messages suggest valid field names',
                    recommendation='Disable field suggestions in production'
                ))
        
        return GraphQLReport(
            endpoint=endpoint,
            scan_time=datetime.now().isoformat(),
            introspection_enabled=introspection_enabled,
            types_discovered=len(types),
            queries_found=len(queries),
            mutations_found=len(mutations),
            subscriptions_found=len(subscriptions),
            security_findings=security_findings,
            types=types,
            queries=queries,
            mutations=mutations,
            subscriptions=subscriptions,
            sensitive_fields=sensitive_fields
        )
    
    def _build_headers(self, token: Optional[str]) -> Dict:
        """Build request headers."""
        headers = {
            'Content-Type': 'application/json',
            'User-Agent': 'Janus-GraphQL-Scanner/1.0'
        }
        if token:
            headers['Authorization'] = token
        return headers
    
    def _run_introspection(self, endpoint: str, headers: Dict) -> Optional[Dict]:
        """Execute introspection query."""
        try:
            response = requests.post(
                endpoint,
                json={'query': self.INTROSPECTION_QUERY},
                headers=headers,
                timeout=self.timeout
            )
            
            if response.status_code == 200:
                data = response.json()
                if 'data' in data and '__schema' in data.get('data', {}):
                    return data['data']['__schema']
        except Exception:
            pass
        return None
    
    def _parse_schema(self, schema: Dict) -> tuple:
        """Parse introspection schema into structured data."""
        types = []
        queries = []
        mutations = []
        subscriptions = []
        
        query_type_name = schema.get('queryType', {}).get('name', 'Query')
        mutation_type_name = schema.get('mutationType', {}).get('name', 'Mutation')
        subscription_type_name = schema.get('subscriptionType', {}).get('name', 'Subscription')
        
        for type_def in schema.get('types', []):
            name = type_def.get('name', '')
            
            # Skip internal types
            if name.startswith('__'):
                continue
            
            kind = type_def.get('kind', '')
            fields = [f.get('name', '') for f in type_def.get('fields', []) or []]
            
            types.append(GraphQLType(
                name=name,
                kind=kind,
                fields=fields,
                description=type_def.get('description')
            ))
            
            # Extract operations
            if name == query_type_name:
                for field in type_def.get('fields', []) or []:
                    queries.append(self._parse_operation(field, 'query'))
            elif name == mutation_type_name:
                for field in type_def.get('fields', []) or []:
                    mutations.append(self._parse_operation(field, 'mutation'))
            elif name == subscription_type_name:
                for field in type_def.get('fields', []) or []:
                    subscriptions.append(self._parse_operation(field, 'subscription'))
        
        return types, queries, mutations, subscriptions
    
    def _parse_operation(self, field: Dict, op_type: str) -> GraphQLOperation:
        """Parse a single operation."""
        args = [arg.get('name', '') for arg in field.get('args', []) or []]
        return_type = self._get_type_name(field.get('type', {}))
        
        return GraphQLOperation(
            name=field.get('name', ''),
            operation_type=op_type,
            arguments=args,
            return_type=return_type,
            description=field.get('description')
        )
    
    def _get_type_name(self, type_def: Dict) -> str:
        """Extract type name from type definition."""
        if type_def.get('name'):
            return type_def['name']
        if type_def.get('ofType'):
            return self._get_type_name(type_def['ofType'])
        return 'Unknown'
    
    def _find_sensitive_fields(self, types: List[GraphQLType]) -> List[str]:
        """Find potentially sensitive field names."""
        sensitive = []
        for t in types:
            for field in t.fields:
                field_lower = field.lower()
                for sensitive_name in self.SENSITIVE_FIELDS:
                    if sensitive_name.lower() in field_lower:
                        sensitive.append(f"{t.name}.{field}")
                        break
        return sensitive
    
    def _find_dangerous_mutations(self, mutations: List[GraphQLOperation]) -> List[str]:
        """Find potentially dangerous mutations."""
        dangerous = []
        for m in mutations:
            name_lower = m.name.lower()
            for dangerous_name in self.DANGEROUS_MUTATIONS:
                if dangerous_name.lower() in name_lower:
                    dangerous.append(m.name)
                    break
        return dangerous
    
    def _test_batch_queries(self, endpoint: str, headers: Dict) -> bool:
        """Test if batch queries are allowed."""
        try:
            batch = [
                {'query': '{ __typename }'},
                {'query': '{ __typename }'},
                {'query': '{ __typename }'}
            ]
            response = requests.post(
                endpoint,
                json=batch,
                headers=headers,
                timeout=self.timeout
            )
            return response.status_code == 200 and isinstance(response.json(), list)
        except Exception:
            return False
    
    def _test_query_depth(self, endpoint: str, headers: Dict, max_depth: int = 20) -> int:
        """Test how deep queries can nest."""
        for depth in range(5, max_depth + 1, 5):
            query = self._generate_deep_query(depth)
            try:
                response = requests.post(
                    endpoint,
                    json={'query': query},
                    headers=headers,
                    timeout=self.timeout
                )
                if response.status_code != 200:
                    return depth - 5
                data = response.json()
                if 'errors' in data:
                    return depth - 5
            except Exception:
                return depth - 5
        return max_depth
    
    def _generate_deep_query(self, depth: int) -> str:
        """Generate a deeply nested query."""
        inner = '__typename'
        for _ in range(depth):
            inner = f'... on Query {{ {inner} }}'
        return f'query {{ {inner} }}'
    
    def _test_field_suggestions(self, endpoint: str, headers: Dict) -> bool:
        """Test if field suggestions are enabled."""
        try:
            query = '{ userz }'  # Intentional typo
            response = requests.post(
                endpoint,
                json={'query': query},
                headers=headers,
                timeout=self.timeout
            )
            text = response.text.lower()
            return 'did you mean' in text or 'suggestions' in text
        except Exception:
            return False
    
    def quick_scan(self, endpoint: str, token: Optional[str] = None) -> Dict[str, Any]:
        """Quick scan for GraphQL issues."""
        report = self.analyze(endpoint, token, deep_scan=False)
        
        return {
            "endpoint": endpoint,
            "introspection_enabled": report.introspection_enabled,
            "types": report.types_discovered,
            "queries": report.queries_found,
            "mutations": report.mutations_found,
            "security_issues": len(report.security_findings),
            "findings": [f.to_dict() for f in report.security_findings]
        }
