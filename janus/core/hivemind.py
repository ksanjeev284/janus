# janus/core/hivemind.py
"""
Hive-Mind Module - Real-Time Team Collaboration.

In a professional penetration test, multiple team members work together.
This module enables:
- Real-time sharing of discovered vulnerabilities
- Shared "Loot Box" for stolen tokens, keys, and credentials
- WebSocket-based live feed
- Redis-backed state synchronization

All team members see each other's findings in real-time.
"""

import json
from typing import Dict, List, Any, Optional, Set
from datetime import datetime, timezone
from dataclasses import dataclass, asdict
import asyncio
import uuid

try:
    import redis
    REDIS_AVAILABLE = True
except ImportError:
    REDIS_AVAILABLE = False

try:
    from fastapi import WebSocket
    WEBSOCKET_AVAILABLE = True
except ImportError:
    WEBSOCKET_AVAILABLE = False


@dataclass
class TeamFinding:
    """A vulnerability finding shared with the team."""
    id: str
    timestamp: str
    user: str
    finding_type: str  # BOLA, BFLA, PII, etc.
    endpoint: str
    severity: str
    evidence: str
    target_host: str
    
    def to_dict(self) -> Dict:
        return asdict(self)
    
    def to_json(self) -> str:
        return json.dumps(self.to_dict())


@dataclass
class LootItem:
    """A piece of "loot" - stolen credential or sensitive data."""
    id: str
    timestamp: str
    found_by: str
    loot_type: str  # token, api_key, password_hash, pii, etc.
    value: str  # The actual credential (redacted for display)
    source_endpoint: str
    notes: str = ""
    
    def to_dict(self) -> Dict:
        return asdict(self)
    
    def redacted_dict(self) -> Dict:
        """Return dict with value redacted for safe display."""
        d = self.to_dict()
        if len(self.value) > 8:
            d['value'] = self.value[:4] + '*' * (len(self.value) - 8) + self.value[-4:]
        else:
            d['value'] = '*' * len(self.value)
        return d


class HiveMind:
    """
    Team collaboration hub using Redis for real-time sync.
    
    Features:
    - Live finding feed across all team members
    - Shared loot box for credentials
    - User presence tracking
    - Scan status sharing
    """
    
    # Redis key prefixes
    KEY_FINDINGS = "janus:findings"
    KEY_LOOT = "janus:loot"
    KEY_USERS = "janus:users"
    KEY_SCANS = "janus:scans"
    KEY_CHANNEL = "janus:live"
    
    def __init__(self, 
                 redis_url: str = "redis://localhost:6379",
                 team_id: str = "default",
                 user_name: str = None):
        self.team_id = team_id
        self.user_name = user_name or f"agent_{uuid.uuid4().hex[:6]}"
        self.redis_url = redis_url
        
        self.redis: Optional[redis.Redis] = None
        self.pubsub: Optional[redis.client.PubSub] = None
        self.connected = False
        
        # Local cache for offline mode
        self._local_findings: List[TeamFinding] = []
        self._local_loot: List[LootItem] = []
        
        # WebSocket connections for live updates
        self._websockets: Set[WebSocket] = set()
    
    def connect(self) -> bool:
        """Connect to Redis for team sync."""
        if not REDIS_AVAILABLE:
            print("[HiveMind] Redis not installed. Running in local mode.")
            return False
        
        try:
            self.redis = redis.from_url(self.redis_url)
            self.redis.ping()
            self.pubsub = self.redis.pubsub()
            self.connected = True
            
            # Register user presence
            self._register_user()
            
            print(f"[HiveMind] Connected as '{self.user_name}' to team '{self.team_id}'")
            return True
            
        except Exception as e:
            print(f"[HiveMind] Redis connection failed: {e}. Running in local mode.")
            return False
    
    def disconnect(self):
        """Disconnect and clean up."""
        if self.connected and self.redis:
            self._unregister_user()
            self.pubsub.close()
            self.redis.close()
        self.connected = False
    
    def _register_user(self):
        """Register this user as active in the team."""
        if not self.connected:
            return
        
        key = f"{self.KEY_USERS}:{self.team_id}"
        user_data = {
            "name": self.user_name,
            "joined_at": datetime.now(timezone.utc).isoformat(),
            "status": "active"
        }
        self.redis.hset(key, self.user_name, json.dumps(user_data))
        self.redis.expire(key, 3600)  # 1 hour TTL
    
    def _unregister_user(self):
        """Remove user from active users."""
        if not self.connected:
            return
        
        key = f"{self.KEY_USERS}:{self.team_id}"
        self.redis.hdel(key, self.user_name)
    
    def get_active_users(self) -> List[Dict]:
        """Get list of active team members."""
        if not self.connected:
            return [{"name": self.user_name, "status": "local"}]
        
        key = f"{self.KEY_USERS}:{self.team_id}"
        users = []
        
        for name, data in self.redis.hgetall(key).items():
            user = json.loads(data)
            user['name'] = name.decode() if isinstance(name, bytes) else name
            users.append(user)
        
        return users
    
    def share_finding(self, finding: TeamFinding):
        """
        Share a vulnerability finding with the team.
        
        This is broadcast to all connected team members in real-time.
        """
        # Add to local cache
        self._local_findings.append(finding)
        
        if not self.connected:
            return
        
        # Store in Redis
        key = f"{self.KEY_FINDINGS}:{self.team_id}"
        self.redis.lpush(key, finding.to_json())
        self.redis.ltrim(key, 0, 999)  # Keep last 1000 findings
        
        # Publish to live channel
        message = {
            "type": "finding",
            "data": finding.to_dict(),
            "from": self.user_name
        }
        self.redis.publish(f"{self.KEY_CHANNEL}:{self.team_id}", json.dumps(message))
    
    def add_loot(self, loot: LootItem):
        """
        Add a piece of loot (credential/secret) to the shared loot box.
        """
        self._local_loot.append(loot)
        
        if not self.connected:
            return
        
        key = f"{self.KEY_LOOT}:{self.team_id}"
        self.redis.hset(key, loot.id, json.dumps(loot.to_dict()))
        
        # Publish notification (with redacted value)
        message = {
            "type": "loot",
            "data": loot.redacted_dict(),
            "from": self.user_name
        }
        self.redis.publish(f"{self.KEY_CHANNEL}:{self.team_id}", json.dumps(message))
    
    def get_findings(self, limit: int = 100) -> List[TeamFinding]:
        """Get recent findings from the team."""
        if not self.connected:
            return self._local_findings[-limit:]
        
        key = f"{self.KEY_FINDINGS}:{self.team_id}"
        raw_findings = self.redis.lrange(key, 0, limit - 1)
        
        findings = []
        for raw in raw_findings:
            data = json.loads(raw)
            findings.append(TeamFinding(**data))
        
        return findings
    
    def get_loot(self) -> List[LootItem]:
        """Get all loot from the shared loot box."""
        if not self.connected:
            return self._local_loot
        
        key = f"{self.KEY_LOOT}:{self.team_id}"
        raw_loot = self.redis.hgetall(key)
        
        loot = []
        for id_, raw in raw_loot.items():
            data = json.loads(raw)
            loot.append(LootItem(**data))
        
        return loot
    
    def create_finding(self,
                       finding_type: str,
                       endpoint: str,
                       severity: str,
                       evidence: str,
                       target_host: str = "") -> TeamFinding:
        """Create and share a new finding."""
        finding = TeamFinding(
            id=uuid.uuid4().hex,
            timestamp=datetime.now(timezone.utc).isoformat(),
            user=self.user_name,
            finding_type=finding_type,
            endpoint=endpoint,
            severity=severity,
            evidence=evidence,
            target_host=target_host
        )
        
        self.share_finding(finding)
        return finding
    
    def create_loot(self,
                    loot_type: str,
                    value: str,
                    source_endpoint: str,
                    notes: str = "") -> LootItem:
        """Create and add a new piece of loot."""
        loot = LootItem(
            id=uuid.uuid4().hex,
            timestamp=datetime.now(timezone.utc).isoformat(),
            found_by=self.user_name,
            loot_type=loot_type,
            value=value,
            source_endpoint=source_endpoint,
            notes=notes
        )
        
        self.add_loot(loot)
        return loot
    
    # =========================================================================
    # WebSocket Support for Live Feed
    # =========================================================================
    
    async def subscribe_live(self, callback):
        """
        Subscribe to live updates from the team.
        
        Args:
            callback: Async function called with each message
        """
        if not self.connected:
            return
        
        channel = f"{self.KEY_CHANNEL}:{self.team_id}"
        self.pubsub.subscribe(channel)
        
        for message in self.pubsub.listen():
            if message['type'] == 'message':
                data = json.loads(message['data'])
                await callback(data)
    
    async def broadcast_to_websockets(self, message: Dict):
        """Broadcast a message to all connected WebSocket clients."""
        disconnected = set()
        
        for ws in self._websockets:
            try:
                await ws.send_json(message)
            except:
                disconnected.add(ws)
        
        self._websockets -= disconnected
    
    def add_websocket(self, ws: WebSocket):
        """Register a new WebSocket connection."""
        self._websockets.add(ws)
    
    def remove_websocket(self, ws: WebSocket):
        """Remove a WebSocket connection."""
        self._websockets.discard(ws)
    
    # =========================================================================
    # Status and Reporting
    # =========================================================================
    
    def get_team_stats(self) -> Dict:
        """Get team statistics."""
        return {
            "team_id": self.team_id,
            "connected": self.connected,
            "user": self.user_name,
            "active_users": len(self.get_active_users()),
            "total_findings": len(self.get_findings()),
            "total_loot": len(self.get_loot()),
        }
    
    def export_findings(self, filepath: str):
        """Export all findings to a JSON file."""
        findings = [f.to_dict() for f in self.get_findings(limit=10000)]
        
        with open(filepath, 'w') as f:
            json.dump({
                "team_id": self.team_id,
                "exported_at": datetime.now(timezone.utc).isoformat(),
                "exported_by": self.user_name,
                "findings": findings
            }, f, indent=2)
        
        return filepath


# Singleton for easy access
_hivemind: Optional[HiveMind] = None


def get_hivemind(redis_url: str = None, team_id: str = "default", user_name: str = None) -> HiveMind:
    """Get or create the HiveMind instance."""
    global _hivemind
    
    if _hivemind is None:
        _hivemind = HiveMind(
            redis_url=redis_url or "redis://localhost:6379",
            team_id=team_id,
            user_name=user_name
        )
        _hivemind.connect()
    
    return _hivemind
