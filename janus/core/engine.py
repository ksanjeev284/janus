# janus/core/engine.py
"""
The Janus Attack Engine - The "Local AI" Judge.
Uses statistical analysis and deep structure comparison to detect BOLA vulnerabilities.
Now with Smart Diff, Mass Assignment, JWT attacks, and HTML reporting.
"""

import json
import requests
from typing import Dict, List, Any, Optional, Tuple
from dataclasses import dataclass, field, asdict
from difflib import SequenceMatcher
from datetime import datetime

from .database import JanusDatabase
from .smart_diff import SmartDiffComparator, DEEPDIFF_AVAILABLE
from .mass_assignment import MassAssignmentTester
from .jwt_attacks import JWTAttacker
from .stealth import GhostWalker, StealthConfig, ghost_mode


@dataclass
class VulnerabilityFinding:
    """Represents a single vulnerability finding."""
    endpoint: str
    method: str
    resource_id: str
    status: str  # VULNERABLE, BLOCKED, FALSE_POSITIVE, NEEDS_REVIEW
    confidence: float  # 0.0 - 1.0
    severity: str  # CRITICAL, HIGH, MEDIUM, LOW, INFO
    vulnerability_type: str  # BOLA, IDOR, etc.
    evidence: str
    recommendation: str
    original_response: Optional[Dict] = None
    attack_response: Optional[Dict] = None
    structure_similarity: float = 0.0
    timestamp: str = field(default_factory=lambda: datetime.now().isoformat())
    
    def to_dict(self) -> Dict:
        return asdict(self)


@dataclass
class ScanReport:
    """Complete scan report."""
    scan_id: str
    target_host: str
    victim_token: str
    attacker_token: str
    start_time: str
    end_time: Optional[str]
    total_endpoints: int
    vulnerabilities_found: int
    secure_endpoints: int
    needs_review: int
    findings: List[VulnerabilityFinding]
    
    def to_dict(self) -> Dict:
        return {
            **asdict(self),
            'findings': [f.to_dict() for f in self.findings]
        }


class DeepStructureAnalyzer:
    """
    The "Local AI" - Analyzes JSON structures at any depth level.
    This is the brain that replaces expensive OpenAI/Gemini calls.
    """
    
    @staticmethod
    def extract_structure(data: Any, prefix: str = "", max_depth: int = 10) -> List[str]:
        """
        Recursively extract the structural skeleton of any JSON.
        
        Example:
            {"user": {"profile": {"id": 123, "name": "alice"}}}
        Becomes:
            ["user", "user.profile", "user.profile.id", "user.profile.name"]
        """
        if max_depth <= 0:
            return [f"{prefix}[MAX_DEPTH]"]
        
        structure = []
        
        if isinstance(data, dict):
            for key, value in data.items():
                path = f"{prefix}.{key}" if prefix else key
                structure.append(path)
                # Add type hint
                structure.append(f"{path}:{type(value).__name__}")
                # Recurse into nested structures
                if isinstance(value, (dict, list)):
                    structure.extend(
                        DeepStructureAnalyzer.extract_structure(value, path, max_depth - 1)
                    )
        elif isinstance(data, list):
            structure.append(f"{prefix}[]")
            if data:
                # Analyze first element as representative
                structure.extend(
                    DeepStructureAnalyzer.extract_structure(data[0], f"{prefix}[]", max_depth - 1)
                )
                # Note array length for additional context
                structure.append(f"{prefix}[len={len(data)}]")
        else:
            # Leaf node - add type info
            structure.append(f"{prefix}:{type(data).__name__}")
        
        return structure
    
    @staticmethod
    def extract_keys_recursive(data: Any, prefix: str = "") -> List[str]:
        """Extract just the key paths (simpler comparison)."""
        keys = []
        if isinstance(data, dict):
            for key, value in data.items():
                path = f"{prefix}.{key}" if prefix else key
                keys.append(path)
                if isinstance(value, (dict, list)):
                    keys.extend(DeepStructureAnalyzer.extract_keys_recursive(value, path))
        elif isinstance(data, list) and data and isinstance(data[0], dict):
            keys.extend(DeepStructureAnalyzer.extract_keys_recursive(data[0], f"{prefix}[]"))
        return keys
    
    @staticmethod
    def calculate_similarity(struct1: List[str], struct2: List[str]) -> float:
        """
        Calculate similarity between two structures using multiple algorithms.
        Returns a weighted average for more accurate detection.
        """
        if not struct1 and not struct2:
            return 1.0
        if not struct1 or not struct2:
            return 0.0
        
        # Method 1: SequenceMatcher on sorted structures
        sorted1, sorted2 = sorted(struct1), sorted(struct2)
        seq_similarity = SequenceMatcher(None, sorted1, sorted2).ratio()
        
        # Method 2: Jaccard similarity (set overlap)
        set1, set2 = set(struct1), set(struct2)
        intersection = len(set1 & set2)
        union = len(set1 | set2)
        jaccard = intersection / union if union > 0 else 0.0
        
        # Method 3: Key-only similarity (ignores type annotations)
        keys1 = [s.split(':')[0] for s in struct1 if ':' in s or '.' in s]
        keys2 = [s.split(':')[0] for s in struct2 if ':' in s or '.' in s]
        key_similarity = SequenceMatcher(None, sorted(keys1), sorted(keys2)).ratio() if keys1 and keys2 else seq_similarity
        
        # Weighted average: prioritize key structure
        return (seq_similarity * 0.3) + (jaccard * 0.3) + (key_similarity * 0.4)
    
    @staticmethod
    def compare_responses(body1: Any, body2: Any) -> Tuple[float, str]:
        """
        Compare two response bodies and return similarity + analysis.
        This is the core "AI" logic.
        """
        try:
            # Parse JSON if strings
            if isinstance(body1, str):
                body1 = json.loads(body1)
            if isinstance(body2, str):
                body2 = json.loads(body2)
        except json.JSONDecodeError:
            # Fallback for non-JSON responses
            if isinstance(body1, str) and isinstance(body2, str):
                return SequenceMatcher(None, body1[:500], body2[:500]).ratio(), "text_comparison"
            return 0.0, "parse_error"
        
        # Extract deep structures
        struct1 = DeepStructureAnalyzer.extract_structure(body1)
        struct2 = DeepStructureAnalyzer.extract_structure(body2)
        
        similarity = DeepStructureAnalyzer.calculate_similarity(struct1, struct2)
        
        # Determine analysis type
        if similarity >= 0.95:
            analysis = "identical_structure"
        elif similarity >= 0.80:
            analysis = "very_similar_structure"
        elif similarity >= 0.60:
            analysis = "similar_structure"
        elif similarity >= 0.40:
            analysis = "partially_similar"
        else:
            analysis = "different_structure"
        
        return similarity, analysis


class JanusEngine:
    """
    The main attack and analysis engine.
    Coordinates learning data with attack logic.
    Now includes Smart Diff, Mass Assignment, and JWT attack capabilities.
    """
    
    # Thresholds for vulnerability classification
    VULN_THRESHOLD = 0.70  # Above this = likely vulnerable
    REVIEW_THRESHOLD = 0.40  # Between review and vuln = needs review
    
    def __init__(self, database: Optional[JanusDatabase] = None):
        self.db = database or JanusDatabase()
        self.analyzer = DeepStructureAnalyzer()
        self.smart_diff = SmartDiffComparator()
        self.mass_assignment = MassAssignmentTester()
        self.jwt_attacker = JWTAttacker()
        self.stealth_config = StealthConfig() # Default config, can be updated
        self.ghost = GhostWalker(self.stealth_config)
        self.use_smart_diff = DEEPDIFF_AVAILABLE
        print(f"[*] Janus Engine initialized (storage: {self.db.backend_name})")
        if self.use_smart_diff:
            print(f"[*] Smart Diff enabled (deepdiff available)")
            
    def enable_stealth(self, enabled: bool = True):
        """Enable or disable stealth mode."""
        self.stealth_config.enabled = enabled
        print(f"[*] Stealth Mode: {'ENABLED' if enabled else 'DISABLED'}")
    
    def get_learned_tokens(self) -> List[str]:
        """Get all tokens that have been learned."""
        return self.db.get_all_tokens()
    
    def get_targets(self, victim_token: str) -> List[Dict]:
        """Get all learned endpoints for a victim."""
        return self.db.get_learnings(victim_token)
    
    @ghost_mode
    def _make_request(self, method: str, url: str, token: str, 
                      timeout: int = 10, stealth: bool = False) -> Tuple[int, Any, str]:
        """Make HTTP request and return (status, body, raw_text)."""
        # Get base headers (auth)
        headers = {"Authorization": token}
        
        # Apply stealth headers if enabled
        if stealth or self.stealth_config.enabled:
            stealth_headers = self.ghost.get_stealth_headers(url)
            headers.update(stealth_headers)
            # Ensure Auth header isn't overwritten if it's crucial, 
            # though stealth headers usually don't include Authorization
            if "Authorization" not in headers:
                headers["Authorization"] = token

        proxies = None
        if (stealth or self.stealth_config.enabled) and self.stealth_config.use_tor:
            if self.ghost.check_tor():
                 proxies = self.ghost.get_tor_proxy()

        try:
            resp = requests.request(method, url, headers=headers, timeout=timeout, proxies=proxies)
            try:
                body = resp.json()
            except json.JSONDecodeError:
                body = {"_raw": resp.text[:500]}
            return resp.status_code, body, resp.text
        except requests.RequestException as e:
            return 0, {"_error": str(e)}, str(e)
    
    def _classify_vulnerability(self, attack_status: int, similarity: float,
                                 attack_response: Any) -> Tuple[str, float, str]:
        """
        Classify the vulnerability based on response analysis.
        Returns: (status, confidence, severity)
        """
        # Check for obvious blocks
        if attack_status >= 400:
            return "BLOCKED", 0.95, "INFO"
        
        # Check for soft denials (200 OK but error message)
        if isinstance(attack_response, dict):
            response_text = json.dumps(attack_response).lower()
            denial_keywords = ['error', 'unauthorized', 'forbidden', 'denied', 'invalid']
            if any(kw in response_text for kw in denial_keywords):
                return "FALSE_POSITIVE", 0.60, "INFO"
        
        # Analyze by similarity
        if similarity >= self.VULN_THRESHOLD:
            confidence = min(0.50 + (similarity * 0.50), 0.99)
            severity = "CRITICAL" if similarity >= 0.95 else "HIGH"
            return "VULNERABLE", confidence, severity
        elif similarity >= self.REVIEW_THRESHOLD:
            return "NEEDS_REVIEW", 0.50, "MEDIUM"
        else:
            return "LIKELY_SAFE", 0.70, "LOW"
    
    def launch_attack(self, victim_token: str, attacker_token: str, 
                      target_host: str) -> ScanReport:
        """
        Execute the BOLA attack campaign.
        
        Args:
            victim_token: Token of the legitimate user (learned from proxy)
            attacker_token: Token of the attacker trying unauthorized access
            target_host: Base URL of the target API
        """
        import uuid
        
        start_time = datetime.now()
        scan_id = str(uuid.uuid4())[:8]
        
        targets = self.get_targets(victim_token)
        findings: List[VulnerabilityFinding] = []
        
        print(f"[*] Scan {scan_id}: Loaded {len(targets)} learning points")
        
        for target in targets:
            # Build the attack URL
            endpoint = target['endpoint_template'].replace('{id}', target['id'])
            url = f"{target_host.rstrip('/')}{endpoint}"
            method = target.get('method', 'GET')
            
            print(f"[*] Testing: {method} {url}")
            
            # Step 1: Get baseline (victim's view)
            orig_status, orig_body, _ = self._make_request(method, url, victim_token)
            
            # Step 2: Attack (attacker's attempt)
            attack_status, attack_body, attack_raw = self._make_request(method, url, attacker_token)
            
            # Step 3: Deep structure comparison
            similarity, analysis = self.analyzer.compare_responses(orig_body, attack_body)
            
            # Step 4: Classify the vulnerability
            status, confidence, severity = self._classify_vulnerability(
                attack_status, similarity, attack_body
            )
            
            # Build evidence string
            if status == "VULNERABLE":
                evidence = f"Attacker received HTTP {attack_status} with {similarity:.0%} structure similarity ({analysis})"
            elif status == "BLOCKED":
                evidence = f"Access denied with HTTP {attack_status}"
            elif status == "FALSE_POSITIVE":
                evidence = f"HTTP {attack_status} but response contains denial message"
            else:
                evidence = f"HTTP {attack_status}, {similarity:.0%} similarity - {analysis}"
            
            finding = VulnerabilityFinding(
                endpoint=url,
                method=method,
                resource_id=target['id'],
                status=status,
                confidence=confidence,
                severity=severity,
                vulnerability_type="BOLA/IDOR",
                evidence=evidence,
                recommendation="Implement object-level authorization checks" if status == "VULNERABLE" else "",
                original_response=orig_body if status == "VULNERABLE" else None,
                attack_response=attack_body if status in ["VULNERABLE", "NEEDS_REVIEW"] else None,
                structure_similarity=similarity
            )
            findings.append(finding)
            
            # Log result
            status_icon = "🚨" if status == "VULNERABLE" else "✓" if status == "BLOCKED" else "?"
            print(f"  {status_icon} {status} (confidence: {confidence:.0%})")
        
        # Build report
        vulnerable = [f for f in findings if f.status == "VULNERABLE"]
        blocked = [f for f in findings if f.status == "BLOCKED"]
        review = [f for f in findings if f.status in ["NEEDS_REVIEW", "FALSE_POSITIVE", "LIKELY_SAFE"]]
        
        report = ScanReport(
            scan_id=scan_id,
            target_host=target_host,
            victim_token=victim_token[:20] + "...",
            attacker_token=attacker_token[:20] + "...",
            start_time=start_time.isoformat(),
            end_time=datetime.now().isoformat(),
            total_endpoints=len(findings),
            vulnerabilities_found=len(vulnerable),
            secure_endpoints=len(blocked),
            needs_review=len(review),
            findings=findings
        )
        
        return report
    
    def save_report(self, report: ScanReport, output_path: str) -> None:
        """Save scan report to JSON file."""
        with open(output_path, 'w') as f:
            json.dump(report.to_dict(), f, indent=2)
        print(f"[+] Report saved to {output_path}")
