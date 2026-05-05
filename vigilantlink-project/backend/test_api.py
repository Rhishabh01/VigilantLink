import httpx
import asyncio
import json

async def test():
    async with httpx.AsyncClient(timeout=30) as client:
        try:
            res = await client.post("http://127.0.0.1:8000/analyze", json={"url": "http://apple.com/"})
            print(f"Status: {res.status_code}")
            print(json.dumps(res.json(), indent=2))
        except Exception as e:
            print(f"Error: {e}")

asyncio.run(test())
