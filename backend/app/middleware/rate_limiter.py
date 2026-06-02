"""
Leaky Bucket Rate Limiter: Per-session hover spam protection.

Parameters:
  capacity     = 10 tokens (burst allowance)
  leak_rate    = 2 tokens/second (sustained throughput)
  cost_per_req = 1 token

Behavior:
  - Bucket starts full (10 tokens).
  - Each /analyze call costs 1 token.
  - Tokens regenerate at 2/sec.
  - When empty: HTTP 429 with Retry-After header.
"""

import asyncio
import logging
import time
from typing import Dict, Optional

from fastapi import HTTPException, Request

logger = logging.getLogger(__name__)

# Atomic leaky bucket Lua script for Redis
LUA_SCRIPT = """
local key = KEYS[1]
local capacity = tonumber(ARGV[1])
local leak_rate = tonumber(ARGV[2])
local now = tonumber(ARGV[3])
local cost = tonumber(ARGV[4])

local bucket = redis.call('HMGET', key, 'tokens', 'last_leak')
local tokens = capacity
local last_leak = now

if bucket[1] then
    tokens = tonumber(bucket[1])
    last_leak = tonumber(bucket[2])
    local elapsed = now - last_leak
    tokens = math.min(capacity, tokens + elapsed * leak_rate)
end

if tokens >= cost then
    tokens = tokens - cost
    redis.call('HMSET', key, 'tokens', tokens, 'last_leak', now)
    redis.call('EXPIRE', key, 60)
    return {1, tokens}
else
    local retry_after = (cost - tokens) / leak_rate
    return {0, retry_after}
end
"""


class LeakyBucket:
    """Single session's token bucket."""

    __slots__ = ("capacity", "leak_rate", "tokens", "last_leak")

    def __init__(self, capacity: int = 10, leak_rate: float = 2.0) -> None:
        self.capacity = capacity
        self.leak_rate = leak_rate
        self.tokens = float(capacity)
        self.last_leak = time.monotonic()

    def try_consume(self, cost: float = 1.0) -> bool:
        """Leak tokens based on elapsed time, then try to consume."""
        now = time.monotonic()
        elapsed = now - self.last_leak
        self.tokens = min(self.capacity, self.tokens + elapsed * self.leak_rate)
        self.last_leak = now

        if self.tokens >= cost:
            self.tokens -= cost
            return True
        return False

    @property
    def retry_after(self) -> float:
        """Seconds until 1 token is available."""
        if self.tokens >= 1.0:
            return 0.0
        return (1.0 - self.tokens) / self.leak_rate


class SessionRateLimiter:
    """
    Per-session leaky bucket rate limiter.
    Sessions identified by X-Session-ID header, falling back to client IP.
    """

    def __init__(self, capacity: int = 10, leak_rate: float = 2.0, redis_cache=None) -> None:
        self._buckets: Dict[str, LeakyBucket] = {}
        self._capacity = capacity
        self._leak_rate = leak_rate
        self._lock = asyncio.Lock()
        self._cleanup_counter = 0
        self.redis_cache = redis_cache

    async def check(self, request: Request) -> None:
        """
        Check rate limit for the request. Raises HTTP 429 if exceeded.
        """
        session_id = request.headers.get(
            "X-Session-ID",
            request.client.host if request.client else "unknown",
        )

        # Use Redis if available to prevent bypass across multiple workers
        if self.redis_cache and self.redis_cache._is_connected and self.redis_cache._redis:
            now = time.time()
            try:
                res = await self.redis_cache._redis.eval(
                    LUA_SCRIPT,
                    1,
                    f"vl:ratelimit:{session_id}",
                    self._capacity,
                    self._leak_rate,
                    now,
                    1.0
                )
                success, value = res
                if not success:
                    retry = round(float(value), 1)
                    logger.warning(f"Rate limit exceeded (Redis) for session={session_id}, retry_after={retry}s")
                    raise HTTPException(
                        status_code=429,
                        detail="Rate limit exceeded. Slow down hover requests.",
                        headers={"Retry-After": str(retry)},
                    )
                return
            except Exception as e:
                # If HTTPException was raised, re-raise it
                if isinstance(e, HTTPException):
                    raise
                # Otherwise, log Redis error and fall back to local memory
                logger.warning(f"Redis rate limiting failed, falling back to local: {e}")

        async with self._lock:
            if session_id not in self._buckets:
                self._buckets[session_id] = LeakyBucket(
                    self._capacity, self._leak_rate
                )
            bucket = self._buckets[session_id]

            # Periodic cleanup of stale buckets (every 100 requests)
            self._cleanup_counter += 1
            if self._cleanup_counter >= 100:
                self._cleanup_counter = 0
                self._cleanup_stale_buckets()

        if not bucket.try_consume():
            retry = round(bucket.retry_after, 1)
            logger.warning(f"Rate limit exceeded (Local) for session={session_id}, retry_after={retry}s")
            raise HTTPException(
                status_code=429,
                detail="Rate limit exceeded. Slow down hover requests.",
                headers={"Retry-After": str(retry)},
            )

    def _cleanup_stale_buckets(self) -> None:
        """Remove buckets that haven't been used in 60 seconds."""
        now = time.monotonic()
        stale_keys = [
            k for k, b in self._buckets.items()
            if (now - b.last_leak) > 60.0
        ]
        for k in stale_keys:
            del self._buckets[k]
        if stale_keys:
            logger.debug(f"Cleaned up {len(stale_keys)} stale rate-limit buckets")
