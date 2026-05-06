from cachetools import TTLCache
from typing import Dict, Any, Optional
import logging

logger = logging.getLogger(__name__)

class CacheManager:
    """
    Two-tier cache supporting progressive analysis.
    
    - full_cache: Complete results (stage 2). TTL: 1 hour.
    - partial_cache: Stage 1 results (metadata + heuristics). TTL: 30 min.
    - pending: In-flight Tier 2 results awaiting poll. TTL: 60 sec auto-cleanup.
    """
    def __init__(self):
        self.full_cache: TTLCache = TTLCache(maxsize=500, ttl=3600)      # 1 hour
        self.partial_cache: TTLCache = TTLCache(maxsize=1000, ttl=1800)   # 30 min
        self.pending: TTLCache = TTLCache(maxsize=200, ttl=60)            # 60 sec

    # --- Full result cache (stage 2 complete) ---
    def get(self, url: str) -> Optional[Dict[str, Any]]:
        return self.full_cache.get(url)

    def set(self, url: str, data: Dict[str, Any]):
        self.full_cache[url] = data

    # --- Partial result cache (stage 1) ---
    def get_partial(self, url: str) -> Optional[Dict[str, Any]]:
        return self.partial_cache.get(url)

    def set_partial(self, url: str, data: Dict[str, Any]):
        self.partial_cache[url] = data

    # --- Pending deep scan results ---
    def get_pending(self, request_id: str) -> Optional[Dict[str, Any]]:
        return self.pending.get(request_id)

    def set_pending(self, request_id: str, data: Dict[str, Any]):
        self.pending[request_id] = data

    def has_pending(self, request_id: str) -> bool:
        return request_id in self.pending

# Global singleton
cache_manager = CacheManager()
