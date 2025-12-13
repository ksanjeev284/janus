# janus/core/smart_diff.py
"""
Smart Diff Comparator - The Advanced "AI" Judge.
Uses deepdiff to intelligently compare responses while ignoring noise.
"""

from typing import Dict, List, Any, Tuple, Set, Optional
from dataclasses import dataclass
import re
import json

try:
    from deepdiff import DeepDiff
    DEEPDIFF_AVAILABLE = True
except ImportError:
    DEEPDIFF_AVAILABLE = False
    print("[!] Warning: deepdiff not installed. Install with: pip install deepdiff")


@dataclass
class DiffResult:
    """Result of a smart comparison."""
    similarity: float
    confidence: str  # HIGH, MEDIUM, LOW
    sensitive_data_leaked: bool
    leaked_fields: List[str]
    noise_filtered: List[str]
    analysis: str
    raw_diff: Optional[Dict] = None


class SmartDiffComparator:
    """
    Advanced response comparator that filters noise and detects sensitive data leaks.
    """
    
    # Fields to IGNORE (noise - changes every request)
    NOISY_FIELDS: Set[str] = {
        'timestamp', 'time', 'date', 'datetime', 'created_at', 'updated_at',
        'request_id', 'requestId', 'req_id', 'trace_id', 'traceId', 'correlation_id',
        'nonce', 'csrf', 'csrf_token', 'csrfToken',
        'session_id', 'sessionId', 'sid',
        'uuid', 'guid', 'id',  # Generic IDs that change
        'expires', 'expiry', 'exp', 'iat', 'nbf',  # JWT timestamps
        'random', 'rand', 'seed',
        'version', 'v', 'build',
        'cache', 'etag', 'last_modified',
    }
    
    # Fields that indicate SENSITIVE data (high priority for leak detection)
    SENSITIVE_FIELDS: Set[str] = {
        # PII
        'email', 'mail', 'e_mail',
        'phone', 'mobile', 'telephone', 'tel',
        'address', 'street', 'city', 'zip', 'postal', 'country',
        'ssn', 'social_security', 'national_id', 'passport',
        'dob', 'date_of_birth', 'birthday', 'birth_date',
        'name', 'first_name', 'last_name', 'full_name', 'username',
        
        # Financial
        'balance', 'amount', 'price', 'cost', 'salary', 'income',
        'credit_card', 'card_number', 'cvv', 'cvc', 'expiry_date',
        'account_number', 'bank_account', 'routing_number', 'iban', 'swift',
        'transaction', 'payment', 'order',
        
        # Auth/Security
        'password', 'passwd', 'pwd', 'secret', 'api_key', 'apikey',
        'token', 'access_token', 'refresh_token', 'auth',
        'private_key', 'private', 'key',
        
        # Privilege
        'role', 'roles', 'permission', 'permissions', 'admin', 'is_admin',
        'superuser', 'is_superuser', 'privilege', 'level', 'tier',
    }
    
    # Patterns to detect sensitive data in values
    SENSITIVE_PATTERNS = [
        (r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b', 'email'),
        (r'\b\d{3}[-.]?\d{3}[-.]?\d{4}\b', 'phone'),
        (r'\b\d{3}[-]?\d{2}[-]?\d{4}\b', 'ssn'),
        (r'\b(?:\d{4}[-\s]?){3}\d{4}\b', 'credit_card'),
        (r'\b[A-Z]{2}\d{2}[A-Z0-9]{4}\d{7}([A-Z0-9]?){0,16}\b', 'iban'),
    ]
    
    def __init__(self, custom_noisy_fields: Set[str] = None, 
                 custom_sensitive_fields: Set[str] = None):
        self.noisy_fields = self.NOISY_FIELDS.copy()
        self.sensitive_fields = self.SENSITIVE_FIELDS.copy()
        
        if custom_noisy_fields:
            self.noisy_fields.update(custom_noisy_fields)
        if custom_sensitive_fields:
            self.sensitive_fields.update(custom_sensitive_fields)
    
    def _normalize_key(self, key: str) -> str:
        """Normalize key for comparison (lowercase, remove special chars)."""
        return re.sub(r'[^a-z0-9]', '', key.lower())
    
    def _is_noisy_key(self, key: str) -> bool:
        """Check if a key is considered noisy."""
        normalized = self._normalize_key(key)
        return any(self._normalize_key(n) in normalized for n in self.noisy_fields)
    
    def _is_sensitive_key(self, key: str) -> bool:
        """Check if a key contains sensitive data."""
        normalized = self._normalize_key(key)
        return any(self._normalize_key(s) in normalized for s in self.sensitive_fields)
    
    def _extract_keys_recursive(self, data: Any, prefix: str = "") -> List[str]:
        """Recursively extract all keys from nested structure."""
        keys = []
        if isinstance(data, dict):
            for key, value in data.items():
                full_key = f"{prefix}.{key}" if prefix else key
                keys.append(full_key)
                keys.extend(self._extract_keys_recursive(value, full_key))
        elif isinstance(data, list) and data:
            keys.extend(self._extract_keys_recursive(data[0], f"{prefix}[]"))
        return keys
    
    def _find_sensitive_in_value(self, value: Any) -> List[str]:
        """Check if a value contains sensitive patterns."""
        found = []
        if isinstance(value, str):
            for pattern, name in self.SENSITIVE_PATTERNS:
                if re.search(pattern, value, re.IGNORECASE):
                    found.append(name)
        return found
    
    def _build_exclude_paths(self, data: Any) -> List[str]:
        """Build list of paths to exclude (noisy fields)."""
        exclude = []
        all_keys = self._extract_keys_recursive(data)
        for key in all_keys:
            leaf = key.split('.')[-1].replace('[]', '')
            if self._is_noisy_key(leaf):
                exclude.append(f"root{key.replace('.', '][')}".replace("][", "']['"))
        return exclude
    
    def compare_responses(self, baseline: Any, attack: Any) -> DiffResult:
        """
        Compare baseline (legitimate) response with attack response.
        
        Returns smart analysis considering noise and sensitive data.
        """
        # Parse JSON if strings
        if isinstance(baseline, str):
            try:
                baseline = json.loads(baseline)
            except json.JSONDecodeError:
                baseline = {"_raw": baseline}
        
        if isinstance(attack, str):
            try:
                attack = json.loads(attack)
            except json.JSONDecodeError:
                attack = {"_raw": attack}
        
        # Handle error responses
        if isinstance(attack, dict):
            attack_str = json.dumps(attack).lower()
            if any(kw in attack_str for kw in ['error', 'unauthorized', 'forbidden', 'denied']):
                return DiffResult(
                    similarity=0.0,
                    confidence="HIGH",
                    sensitive_data_leaked=False,
                    leaked_fields=[],
                    noise_filtered=[],
                    analysis="Access denied - endpoint is secure"
                )
        
        # Use deepdiff if available
        if DEEPDIFF_AVAILABLE:
            return self._compare_with_deepdiff(baseline, attack)
        else:
            return self._compare_fallback(baseline, attack)
    
    def _compare_with_deepdiff(self, baseline: Any, attack: Any) -> DiffResult:
        """Use deepdiff for smart comparison."""
        # Build exclude regex for noisy fields
        exclude_regex = [f".*{field}.*" for field in self.noisy_fields]
        
        diff = DeepDiff(
            baseline, 
            attack,
            exclude_regex_paths=exclude_regex,
            ignore_order=True,
            verbose_level=2
        )
        
        # Analyze the diff
        noise_filtered = []
        leaked_fields = []
        sensitive_leaked = False
        
        # Check all keys in attack response
        attack_keys = self._extract_keys_recursive(attack)
        for key in attack_keys:
            leaf = key.split('.')[-1].replace('[]', '')
            if self._is_noisy_key(leaf):
                noise_filtered.append(key)
            elif self._is_sensitive_key(leaf):
                # Check if this key exists in baseline too
                baseline_keys = self._extract_keys_recursive(baseline)
                if key in baseline_keys or any(leaf in bk for bk in baseline_keys):
                    leaked_fields.append(key)
                    sensitive_leaked = True
        
        # Also check values for sensitive patterns
        def check_values(data, path=""):
            nonlocal leaked_fields, sensitive_leaked
            if isinstance(data, dict):
                for k, v in data.items():
                    check_values(v, f"{path}.{k}" if path else k)
            elif isinstance(data, list):
                for i, item in enumerate(data):
                    check_values(item, f"{path}[{i}]")
            else:
                patterns = self._find_sensitive_in_value(data)
                if patterns:
                    leaked_fields.extend([f"{path}:{p}" for p in patterns])
                    sensitive_leaked = True
        
        check_values(attack)
        
        # Calculate similarity (inverse of diff size)
        total_diff_items = sum(len(v) if isinstance(v, (dict, list)) else 1 
                               for v in diff.values()) if diff else 0
        
        # Base similarity on structure match minus meaningful differences
        if not diff:
            similarity = 1.0
        else:
            # Fewer differences = higher similarity
            similarity = max(0.0, 1.0 - (total_diff_items * 0.1))
        
        # Determine confidence
        if sensitive_leaked and similarity > 0.5:
            confidence = "HIGH"
            analysis = f"CRITICAL: Sensitive data leaked ({', '.join(list(set(leaked_fields))[:5])})"
        elif similarity > 0.8:
            confidence = "HIGH"
            analysis = "Responses are structurally identical - likely BOLA vulnerability"
        elif similarity > 0.5:
            confidence = "MEDIUM"
            analysis = "Partial structure match - needs manual review"
        else:
            confidence = "LOW"
            analysis = "Responses differ significantly - likely secure"
        
        return DiffResult(
            similarity=similarity,
            confidence=confidence,
            sensitive_data_leaked=sensitive_leaked,
            leaked_fields=list(set(leaked_fields)),
            noise_filtered=noise_filtered,
            analysis=analysis,
            raw_diff=dict(diff) if diff else None
        )
    
    def _compare_fallback(self, baseline: Any, attack: Any) -> DiffResult:
        """Fallback comparison without deepdiff."""
        from difflib import SequenceMatcher
        
        # Filter noisy keys
        def filter_noisy(data: Any) -> Any:
            if isinstance(data, dict):
                return {k: filter_noisy(v) for k, v in data.items() 
                        if not self._is_noisy_key(k)}
            elif isinstance(data, list):
                return [filter_noisy(item) for item in data]
            return data
        
        filtered_baseline = filter_noisy(baseline)
        filtered_attack = filter_noisy(attack)
        
        # Compare as strings
        str1 = json.dumps(filtered_baseline, sort_keys=True)
        str2 = json.dumps(filtered_attack, sort_keys=True)
        
        similarity = SequenceMatcher(None, str1, str2).ratio()
        
        # Check for sensitive fields
        leaked_fields = []
        attack_keys = self._extract_keys_recursive(attack)
        for key in attack_keys:
            if self._is_sensitive_key(key.split('.')[-1]):
                leaked_fields.append(key)
        
        sensitive_leaked = len(leaked_fields) > 0 and similarity > 0.5
        
        if sensitive_leaked:
            confidence = "HIGH"
            analysis = f"Sensitive data potentially leaked: {', '.join(leaked_fields[:3])}"
        elif similarity > 0.8:
            confidence = "HIGH" 
            analysis = "High similarity - potential vulnerability"
        elif similarity > 0.5:
            confidence = "MEDIUM"
            analysis = "Moderate similarity - review recommended"
        else:
            confidence = "LOW"
            analysis = "Low similarity - likely secure"
        
        return DiffResult(
            similarity=similarity,
            confidence=confidence,
            sensitive_data_leaked=sensitive_leaked,
            leaked_fields=leaked_fields,
            noise_filtered=[],
            analysis=analysis
        )
