import time
from typing import Dict, Any, Optional

class CacheManager:
    """
    A simple in-memory cache for API responses.
    In production, this should be replaced by Redis.
    """
    def __init__(self, ttl_seconds: int = 3600):
        self.cache: Dict[str, Dict[str, Any]] = {}
        self.ttl = ttl_seconds

    def get(self, url: str) -> Optional[Dict[str, Any]]:
        entry = self.cache.get(url)
        if not entry:
            return None
            
        if time.time() > entry["expires_at"]:
            del self.cache[url]
            return None
            
        return entry["data"]

    def set(self, url: str, data: Dict[str, Any]):
        self.cache[url] = {
            "data": data,
            "expires_at": time.time() + self.ttl
        }

# Global singleton
cache_manager = CacheManager()
