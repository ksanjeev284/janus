# janus/core/database.py
"""
Hybrid Database Layer - Supports both JSON file and Redis storage.
Automatically falls back to JSON if Redis is unavailable.
"""

import json
import os
from typing import List, Dict, Any, Optional
from abc import ABC, abstractmethod

# Default paths
DEFAULT_DATA_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(__file__))), "data")
DEFAULT_JSON_FILE = os.path.join(DEFAULT_DATA_DIR, "janus_data.json")


class BaseStorage(ABC):
    """Abstract base class for storage backends."""
    
    @abstractmethod
    def store_learning(self, token: str, entry: Dict[str, Any]) -> None:
        """Store a learned request entry for a token."""
        pass
    
    @abstractmethod
    def get_learnings(self, token: str) -> List[Dict[str, Any]]:
        """Get all learned entries for a token."""
        pass
    
    @abstractmethod
    def get_all_tokens(self) -> List[str]:
        """Get all tokens that have been learned."""
        pass
    
    @abstractmethod
    def clear_token(self, token: str) -> None:
        """Clear all learnings for a specific token."""
        pass
    
    @abstractmethod
    def clear_all(self) -> None:
        """Clear all stored data."""
        pass


class JSONStorage(BaseStorage):
    """File-based JSON storage - works everywhere, no dependencies."""
    
    def __init__(self, file_path: str = DEFAULT_JSON_FILE):
        self.file_path = file_path
        os.makedirs(os.path.dirname(file_path), exist_ok=True)
        if not os.path.exists(file_path):
            self._save({})
    
    def _load(self) -> Dict:
        try:
            with open(self.file_path, 'r') as f:
                return json.load(f)
        except (FileNotFoundError, json.JSONDecodeError):
            return {}
    
    def _save(self, data: Dict) -> None:
        with open(self.file_path, 'w') as f:
            json.dump(data, f, indent=2)
    
    def _make_key(self, token: str) -> str:
        return f"janus:user:{token}"
    
    def store_learning(self, token: str, entry: Dict[str, Any]) -> None:
        data = self._load()
        key = self._make_key(token)
        if key not in data:
            data[key] = []
        # Avoid duplicates
        if entry not in data[key]:
            data[key].append(entry)
            self._save(data)
    
    def get_learnings(self, token: str) -> List[Dict[str, Any]]:
        data = self._load()
        return data.get(self._make_key(token), [])
    
    def get_all_tokens(self) -> List[str]:
        data = self._load()
        return [k.replace("janus:user:", "") for k in data.keys()]
    
    def clear_token(self, token: str) -> None:
        data = self._load()
        key = self._make_key(token)
        if key in data:
            del data[key]
            self._save(data)
    
    def clear_all(self) -> None:
        self._save({})


class RedisStorage(BaseStorage):
    """Redis-based storage - faster, better for production."""
    
    def __init__(self, host: str = 'localhost', port: int = 6379, db: int = 0):
        import redis
        self.redis = redis.Redis(host=host, port=port, db=db)
        # Test connection
        self.redis.ping()
    
    def _make_key(self, token: str) -> str:
        return f"janus:user:{token}"
    
    def store_learning(self, token: str, entry: Dict[str, Any]) -> None:
        key = self._make_key(token)
        entry_json = json.dumps(entry)
        # Check for duplicates
        existing = self.redis.lrange(key, 0, -1)
        if entry_json.encode() not in existing:
            self.redis.rpush(key, entry_json)
    
    def get_learnings(self, token: str) -> List[Dict[str, Any]]:
        entries = self.redis.lrange(self._make_key(token), 0, -1)
        return [json.loads(e.decode()) for e in entries]
    
    def get_all_tokens(self) -> List[str]:
        keys = self.redis.keys("janus:user:*")
        return [k.decode().replace("janus:user:", "") for k in keys]
    
    def clear_token(self, token: str) -> None:
        self.redis.delete(self._make_key(token))
    
    def clear_all(self) -> None:
        keys = self.redis.keys("janus:user:*")
        if keys:
            self.redis.delete(*keys)


class JanusDatabase:
    """
    Smart database wrapper that auto-selects backend.
    Tries Redis first, falls back to JSON.
    """
    
    def __init__(self, prefer_redis: bool = True, redis_host: str = 'localhost', 
                 redis_port: int = 6379, json_path: str = DEFAULT_JSON_FILE):
        self.backend: BaseStorage
        self.backend_name: str
        
        if prefer_redis:
            try:
                self.backend = RedisStorage(host=redis_host, port=redis_port)
                self.backend_name = "redis"
            except Exception:
                self.backend = JSONStorage(file_path=json_path)
                self.backend_name = "json"
        else:
            self.backend = JSONStorage(file_path=json_path)
            self.backend_name = "json"
    
    def __getattr__(self, name):
        """Delegate all storage methods to the backend."""
        return getattr(self.backend, name)
