"""
Redis Cache: Multi-layer caching with Soft-TTL invalidation.

Schema: Redis Hash per canonical URL at key vl:report:<sha256_prefix>
Soft-TTL: 10 min — serve stale, trigger background refresh.
Hard-TTL: 1 hour — Redis auto-expires.

Why Redis over in-memory:
  - Shared across all Uvicorn workers and container replicas
  - Persists across deploys (RDB/AOF)
  - Single source of truth — no cache fragmentation
  - Native TTL and atomic operations
"""

import asyncio
import hashlib
import json
import logging
import time
from typing import Any, Dict, Optional

import redis.asyncio as redis

logger = logging.getLogger(__name__)

HARD_TTL_S: int = 3600      # 1 hour — Redis auto-expires
SOFT_TTL_S: int = 600       # 10 min — triggers background refresh
PARTIAL_TTL_S: int = 300    # 5 min for stage-1 partials
PENDING_TTL_S: int = 300    # 5 min for in-flight deep scan results
KEY_PREFIX: str = "vl:report:"
PENDING_PREFIX: str = "vl:pending:"
REFRESH_LOCK_PREFIX: str = "vl:refresh_lock:"

# Fields that are JSON-encoded lists/dicts in Redis
_JSON_FIELDS = frozenset({"hops", "sec"})
# Fields stored as "0"/"1" booleans
_BOOL_FIELDS = frozenset()
# Fields stored as integer strings
_INT_FIELDS = frozenset({"s", "ms"})
# Internal fields excluded from deserialized output
_INTERNAL_FIELDS = frozenset({"created_at", "refreshed_at"})


def _cache_key(canonical_url: str) -> str:
    """Generate Redis key from canonical URL."""
    h = hashlib.sha256(canonical_url.encode()).hexdigest()[:16]
    return f"{KEY_PREFIX}{h}"


class RedisCache:
    """
    Production cache backed by Redis.
    Supports full reports, partial (stage-1), and pending (polling) entries.
    Implements soft-TTL: serves stale data while refreshing in background.
    """

    def __init__(self, redis_url: str = "redis://localhost:6379/0") -> None:
        self._redis_url = redis_url
        self._redis: Optional[redis.Redis] = None
        self._is_connected = False
        # Fallback for when Redis is unavailable (only works for single-process)
        self._fallback_pending: Dict[str, Any] = {}

    async def connect(self) -> None:
        """Initialize Redis connection pool."""
        try:
            self._redis = redis.from_url(
                self._redis_url,
                decode_responses=True,
                max_connections=20,
                socket_timeout=2.0
            )
            await self._redis.ping()
            self._is_connected = True
            logger.info(f"Redis connected at {self._redis_url}")
        except (redis.ConnectionError, redis.TimeoutError, ConnectionRefusedError) as e:
            self._redis = None
            self._is_connected = False
            logger.warning(f"Redis unavailable ({e}). Running in degraded NO-CACHE mode.")

    async def close(self) -> None:
        """Close Redis connection."""
        if self._is_connected and self._redis:
            await self._redis.aclose()
            logger.info("Redis connection closed")

    # ------------------------------------------------------------------
    # Full report cache (stage 2 complete)
    # ------------------------------------------------------------------

    async def get_full(self, canonical_url: str) -> Optional[Dict[str, Any]]:
        """
        Get cached full report. If past soft-TTL, returns stale data
        AND triggers a background refresh (at most once per 30s lock).
        """
        if not self._is_connected or not self._redis:
            return None

        key = _cache_key(canonical_url)
        try:
            data = await self._redis.hgetall(key)
        except redis.RedisError as e:
            logger.error(f"Redis GET failed: {e}")
            return None

        if not data:
            return None

        report = _deserialize(data)

        # Soft-TTL check
        refreshed_at = float(data.get("refreshed_at", 0))
        age = time.time() - refreshed_at
        if age > SOFT_TTL_S:
            await self._maybe_trigger_refresh(canonical_url)

        return report

    async def set_full(
        self, canonical_url: str, report: Dict[str, Any]
    ) -> None:
        """Store complete stage-2 report with hard TTL."""
        if not self._is_connected or not self._redis:
            return

        key = _cache_key(canonical_url)
        now = str(int(time.time()))
        flat = _serialize(report)
        flat["created_at"] = flat.get("created_at", now)
        flat["refreshed_at"] = now

        try:
            async with self._redis.pipeline(transaction=True) as pipe:
                await pipe.hset(key, mapping=flat)
                await pipe.expire(key, HARD_TTL_S)
                await pipe.execute()
        except redis.RedisError as e:
            logger.error(f"Redis SET full failed: {e}")

    # ------------------------------------------------------------------
    # Partial report cache (stage 1)
    # ------------------------------------------------------------------

    async def get_partial(self, canonical_url: str) -> Optional[Dict[str, Any]]:
        """Get cached stage-1 partial report."""
        if not self._is_connected or not self._redis:
            return None

        key = f"{_cache_key(canonical_url)}:partial"
        try:
            raw = await self._redis.get(key)
            return json.loads(raw) if raw else None
        except redis.RedisError as e:
            logger.error(f"Redis GET partial failed: {e}")
            return None

    async def set_partial(
        self, canonical_url: str, report: Dict[str, Any]
    ) -> None:
        """Store stage-1 partial report."""
        if not self._is_connected or not self._redis:
            return

        key = f"{_cache_key(canonical_url)}:partial"
        try:
            await self._redis.set(key, json.dumps(report), ex=PARTIAL_TTL_S)
        except redis.RedisError as e:
            logger.error(f"Redis SET partial failed: {e}")

    # ------------------------------------------------------------------
    # Pending deep scan results (polled by extension)
    # ------------------------------------------------------------------

    async def get_pending(self, request_id: str) -> Optional[Dict[str, Any]]:
        """Get pending deep scan result by request_id."""
        print(f"[POLL READ] request_id={request_id}")
        
        if self._is_connected and self._redis:
            key = f"{PENDING_PREFIX}{request_id}"
            try:
                raw = await self._redis.get(key)
                if raw:
                    res = json.loads(raw)
                    print(f"[POLL READ] Found in Redis: s={res.get('s')}")
                    return res
            except redis.RedisError as e:
                logger.error(f"Redis GET pending failed: {e}")
        
        # Fallback check
        res = self._fallback_pending.get(request_id)
        if res:
            print(f"[POLL READ] Found in Fallback: s={res.get('s')}")
        else:
            print(f"[POLL READ] Not found")
        return res

    async def set_pending(
        self, request_id: str, report: Dict[str, Any]
    ) -> None:
        """Store pending deep scan result for polling."""
        print(f"[PHASE2 SAVE] request_id={request_id}")
        
        if self._is_connected and self._redis:
            key = f"{PENDING_PREFIX}{request_id}"
            try:
                await self._redis.set(key, json.dumps(report), ex=PENDING_TTL_S)
                print(f"[PHASE2 SAVE] Stored in Redis")
                return
            except redis.RedisError as e:
                logger.error(f"Redis SET pending failed: {e}")
        
        # Fallback storage
        self._fallback_pending[request_id] = report
        print(f"[PHASE2 SAVE] Stored in Fallback")
        # Self-cleanup after 5 mins to prevent memory leak
        async def _cleanup():
            await asyncio.sleep(PENDING_TTL_S)
            self._fallback_pending.pop(request_id, None)
        asyncio.create_task(_cleanup())

    # ------------------------------------------------------------------
    # Background refresh (soft-TTL)
    # ------------------------------------------------------------------

    async def _maybe_trigger_refresh(self, canonical_url: str) -> None:
        """Acquire a 30s lock and trigger background refresh if lock obtained."""
        if not self._is_connected or not self._redis:
            return
            
        lock_key = f"{REFRESH_LOCK_PREFIX}{hashlib.sha256(canonical_url.encode()).hexdigest()[:16]}"
        try:
            acquired = await self._redis.set(lock_key, "1", nx=True, ex=30)
            if acquired:
                logger.info(f"Soft-TTL expired, triggering background refresh")
                asyncio.create_task(self._background_refresh(canonical_url))
        except redis.RedisError as e:
            logger.error(f"Redis refresh lock failed: {e}")

    async def _background_refresh(self, canonical_url: str) -> None:
        """Re-run Phase 1+2 and update cache in background."""
        # Import here to avoid circular dependency
        from .orchestrator import run_phase1, run_phase2
        try:
            p1 = await run_phase1(canonical_url)
            p2 = await run_phase2(canonical_url, p1)

            metadata = p1.get("metadata") or {}
            sec2 = p2["security"]
            stage2 = {
                "s": 2,
                "id": "refresh",
                "url": canonical_url,
                "furl": p1["final_url"],
                "hops": [{"u": h["url"], "c": h["status_code"]} for h in p1["hops"]],
                "t": metadata.get("title"),
                "d": metadata.get("description"),
                "img": metadata.get("image_url"),
                "fav": metadata.get("favicon_url"),
                "ss": None,
                "sec": {
                    "safe": sec2["is_safe"],
                    "v": sec2["verdict"],
                    "rs": sec2["risk_score"],
                    "tt": sec2["threat_type"],
                    "vf": sec2["vendor_flags"],
                    "tv": sec2["total_vendors"],
                    "age": sec2.get("ssl_cert_age_days"),
                    "sr": sec2["suspicious_redirects"],
                    "ts": sec2["typosquatting_detected"],
                    "r": sec2["reasons"],
                    "gsb": sec2.get("gsb_matched", False),
                    "gsbt": sec2.get("gsb_threat_type", None),
                },
                "ms": p2["duration_ms"],
            }
            await self.set_full(canonical_url, stage2)
            logger.info(f"Background refresh complete for {canonical_url[:60]}")
        except Exception as e:
            logger.error(f"Background refresh failed: {e}")


# ------------------------------------------------------------------
# Serialization helpers
# ------------------------------------------------------------------

def _serialize(d: Dict[str, Any]) -> Dict[str, str]:
    """Flatten dict to string values for Redis HSET."""
    flat: Dict[str, str] = {}
    for k, v in d.items():
        if isinstance(v, (list, dict)):
            flat[k] = json.dumps(v)
        elif isinstance(v, bool):
            flat[k] = "1" if v else "0"
        elif v is None:
            flat[k] = ""
        else:
            flat[k] = str(v)
    return flat


def _deserialize(data: Dict[str, str]) -> Dict[str, Any]:
    """Reconstruct typed dict from Redis hash strings."""
    result: Dict[str, Any] = {}
    for k, v in data.items():
        if k in _INTERNAL_FIELDS:
            continue
        elif k in _JSON_FIELDS:
            result[k] = json.loads(v) if v else []
        elif k in _BOOL_FIELDS:
            result[k] = v == "1"
        elif k in _INT_FIELDS:
            result[k] = int(v) if v else 0
        else:
            result[k] = v if v else None
    return result