import sys
from pathlib import Path
from unittest.mock import Mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from app.middleware.rate_limiter import SessionRateLimiter

class MockRequest:
    def __init__(self, host="127.0.0.1", headers=None):
        self.client = Mock()
        self.client.host = host
        self.headers = headers or {}

def test_rate_limiter_simple_ip():
    limiter = SessionRateLimiter(capacity=10, leak_rate=2.0)
    
    # 1. Standard fallback to client.host
    req = MockRequest(host="203.0.113.10")
    # We can check that the buckets are keyed by IP:anon
    # We call check on request, which consumes 1 token
    # Let's inspect limiter._buckets keys
    import asyncio
    asyncio.run(limiter.check(req))
    assert "203.0.113.10:anon" in limiter._buckets

def test_rate_limiter_x_forwarded_for():
    limiter = SessionRateLimiter(capacity=10, leak_rate=2.0)
    
    # 2. Single IP in X-Forwarded-For
    req = MockRequest(host="10.0.0.1", headers={"x-forwarded-for": "203.0.113.20"})
    import asyncio
    asyncio.run(limiter.check(req))
    assert "203.0.113.20:anon" in limiter._buckets

def test_rate_limiter_x_forwarded_for_spoofed():
    limiter = SessionRateLimiter(capacity=10, leak_rate=2.0)
    
    # 3. Spoofed header (multiple IPs) - should extract rightmost (last) IP
    req = MockRequest(host="10.0.0.1", headers={"x-forwarded-for": "1.1.1.1, 2.2.2.2, 203.0.113.30"})
    import asyncio
    asyncio.run(limiter.check(req))
    
    # The rightmost IP is 203.0.113.30 (appended by proxy)
    # The spoofed IPs (1.1.1.1, 2.2.2.2) should be ignored
    assert "203.0.113.30:anon" in limiter._buckets
    assert "1.1.1.1:anon" not in limiter._buckets
    assert "2.2.2.2:anon" not in limiter._buckets
