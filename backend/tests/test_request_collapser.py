import asyncio
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from app.services.request_collapser import RequestCollapser


def test_deduplicated_call_success():
    async def scenario():
        collapser = RequestCollapser()
        calls = 0

        async def factory():
            nonlocal calls
            calls += 1
            await asyncio.sleep(0)
            return {"ok": True}

        results = await asyncio.gather(
            collapser.deduplicated_call("key", factory),
            collapser.deduplicated_call("key", factory),
            collapser.deduplicated_call("key", factory),
        )

        assert results == [{"ok": True}, {"ok": True}, {"ok": True}]
        assert calls == 1
        assert collapser._in_flight == {}

    asyncio.run(scenario())


def test_deduplicated_call_exception():
    async def scenario():
        collapser = RequestCollapser()
        calls = 0

        async def factory():
            nonlocal calls
            calls += 1
            await asyncio.sleep(0)
            raise RuntimeError("boom")

        results = await asyncio.gather(
            collapser.deduplicated_call("key", factory),
            collapser.deduplicated_call("key", factory),
            return_exceptions=True,
        )

        assert len(results) == 2
        assert all(isinstance(result, RuntimeError) for result in results)
        assert {str(result) for result in results} == {"boom"}
        assert calls == 1
        assert collapser._in_flight == {}

    asyncio.run(scenario())


def test_deduplicated_call_cancellation_propagates_and_cleans_up():
    async def scenario():
        collapser = RequestCollapser()
        started = asyncio.Event()

        async def factory():
            started.set()
            try:
                await asyncio.sleep(10)
            except asyncio.CancelledError:
                raise
            return {"unexpected": True}

        owner_task = asyncio.create_task(collapser.deduplicated_call("key", factory))
        await started.wait()

        owner_task.cancel()

        with pytest.raises(asyncio.CancelledError):
            await owner_task

        assert collapser._in_flight == {}
        result = await collapser.deduplicated_call("key", lambda: _return_value({"ok": True}))
        assert result == {"ok": True}

    asyncio.run(scenario())


def test_multiple_waiters_receive_same_cancellation_and_recover():
    async def scenario():
        collapser = RequestCollapser()
        started = asyncio.Event()
        released = asyncio.Event()
        calls = 0

        async def factory():
            nonlocal calls
            calls += 1
            started.set()
            await released.wait()
            return {"unexpected": True}

        owner_task = asyncio.create_task(collapser.deduplicated_call("key", factory))
        await started.wait()

        waiter_one = asyncio.create_task(collapser.deduplicated_call("key", factory))
        waiter_two = asyncio.create_task(collapser.deduplicated_call("key", factory))
        await asyncio.sleep(0)

        owner_task.cancel()
        released.set()

        results = await asyncio.gather(
            owner_task,
            waiter_one,
            waiter_two,
            return_exceptions=True,
        )

        assert len(results) == 3
        assert all(isinstance(result, asyncio.CancelledError) for result in results)
        assert calls == 1
        assert collapser._in_flight == {}

        recovered = await collapser.deduplicated_call("key", lambda: _return_value({"ok": True}))
        assert recovered == {"ok": True}

    asyncio.run(scenario())


def test_multiple_waiters_receive_same_success_result():
    async def scenario():
        collapser = RequestCollapser()
        started = asyncio.Event()
        released = asyncio.Event()
        calls = 0

        async def factory():
            nonlocal calls
            calls += 1
            started.set()
            await released.wait()
            return {"value": 7}

        owner_task = asyncio.create_task(collapser.deduplicated_call("key", factory))
        await started.wait()

        waiter_one = asyncio.create_task(collapser.deduplicated_call("key", factory))
        waiter_two = asyncio.create_task(collapser.deduplicated_call("key", factory))
        released.set()

        results = await asyncio.gather(owner_task, waiter_one, waiter_two)

        assert results == [{"value": 7}, {"value": 7}, {"value": 7}]
        assert calls == 1
        assert collapser._in_flight == {}

    asyncio.run(scenario())


async def _return_value(value):
    return value
