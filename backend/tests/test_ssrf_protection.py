import sys
import asyncio
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from app.utils.url_validator import resolve_and_validate, is_ip_blocked
from app.services.tracer import trace_url
from app.services.metadata_fetcher import fetch_metadata

def test_is_ip_blocked():
    assert is_ip_blocked("127.0.0.1") is True
    assert is_ip_blocked("10.0.0.1") is True
    assert is_ip_blocked("192.168.1.1") is True
    assert is_ip_blocked("8.8.8.8") is False
    assert is_ip_blocked("1.1.1.1") is False

def test_resolve_and_validate():
    # Localhost should be blocked
    safe, ip, reason = resolve_and_validate("http://127.0.0.1/test")
    assert safe is False
    assert "Blocked IP" in reason

    # Localhost scheme check
    safe, ip, reason = resolve_and_validate("ftp://127.0.0.1/test")
    assert safe is False
    assert "Blocked scheme" in reason

    # Safe public URL
    safe, ip, reason = resolve_and_validate("https://www.google.com")
    assert safe is True
    assert ip is not None

def test_trace_url_ssrf_blocked():
    async def scenario():
        res = await trace_url("http://127.0.0.1/trace")
        assert res.get("ssrf_blocked") is True
        assert "final_url" in res
    asyncio.run(scenario())

def test_fetch_metadata_ssrf_blocked():
    async def scenario():
        res = await fetch_metadata("http://127.0.0.1/meta")
        assert res is None
    asyncio.run(scenario())
