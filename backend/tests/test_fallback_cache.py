import asyncio
import sys
import time
from pathlib import Path

import pytest
from cachetools import TTLCache

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from app.services.redis_cache import RedisCache

def test_fallback_cache_eviction():
    async def run_test():
        # Force Redis to fail connection to test fallback
        cache = RedisCache(redis_url="redis://invalid.local:6379/0")
        await cache.connect()
        
        assert not cache._is_connected
        
        # Check that fallback is using TTLCache
        assert isinstance(cache._fallback_pending, TTLCache)
        assert isinstance(cache._fallback_full, TTLCache)
        assert isinstance(cache._fallback_partial, TTLCache)
        
        # Check max sizes
        assert cache._fallback_pending.maxsize == 1000
        assert cache._fallback_full.maxsize == 1000
        assert cache._fallback_partial.maxsize == 2000

        # Fill beyond max size to test LRU/eviction
        # We will simulate filling _fallback_pending
        for i in range(1100):
            await cache.set_pending(f"req_{i}", {"s": 2})
            
        # The cache should not exceed 1000 items
        assert len(cache._fallback_pending) == 1000
        
        # The first 100 items should have been evicted
        assert await cache.get_pending("req_0") is None
        assert await cache.get_pending("req_99") is None
        
        # The last 1000 items should be present
        assert await cache.get_pending("req_1099") == {"s": 2}

    asyncio.run(run_test())
