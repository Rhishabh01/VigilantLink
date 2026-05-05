from cachetools import TTLCache
from typing import Dict, Any, Optional

class CacheManager:
    """
    LRU Cache with TTL for API responses.
    Uses cachetools.TTLCache to prevent memory leaks and automatically expire entries.
    Max 500 entries, 1 hour TTL.
    """
    def __init__(self, maxsize: int = 500, ttl: int = 3600):
        self.cache: TTLCache = TTLCache(maxsize=maxsize, ttl=ttl)

    def get(self, url: str) -> Optional[Dict[str, Any]]:
        return self.cache.get(url)

    def set(self, url: str, data: Dict[str, Any]):
        self.cache[url] = data

# Global singleton
cache_manager = CacheManager()
