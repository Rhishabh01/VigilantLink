"""
Request Collapser: Deduplicates concurrent requests for the same normalized URL.

If 100 users hover the same shortened URL simultaneously, only the first caller
executes the backend fetch. All subsequent callers await the same Future.
"""

import asyncio
import logging
from typing import Any, Awaitable, Callable, Dict

logger = logging.getLogger(__name__)


class RequestCollapser:
    """
    Per-URL lock ensuring only one in-flight fetch per canonical URL.
    First caller executes; all others await the same Future.
    """

    def __init__(self) -> None:
        self._in_flight: Dict[str, asyncio.Future[Dict[str, Any]]] = {}
        self._lock = asyncio.Lock()

    async def deduplicated_call(
        self,
        key: str,
        coro_factory: Callable[[], Awaitable[Dict[str, Any]]],
    ) -> Dict[str, Any]:
        """
        Execute coro_factory() for the given key, collapsing duplicate calls.

        Args:
            key: Canonical (normalized) URL string.
            coro_factory: Zero-arg async callable that produces the result.

        Returns:
            The result dict from the single execution.
        """
        async with self._lock:
            if key in self._in_flight:
                existing_future = self._in_flight[key]
                logger.debug(f"Request collapsed for key={key[:40]}...")
                # Release lock, then await the existing future
                return await existing_future

            # This caller is the "owner" — create a Future for others to wait on
            loop = asyncio.get_running_loop()
            future: asyncio.Future[Dict[str, Any]] = loop.create_future()
            self._in_flight[key] = future

        # Execute outside the lock so we don't block other keys
        try:
            result = await coro_factory()
            future.set_result(result)
            return result
        except Exception as exc:
            future.set_exception(exc)
            raise
        finally:
            async with self._lock:
                self._in_flight.pop(key, None)


# Global singleton
request_collapser = RequestCollapser()
