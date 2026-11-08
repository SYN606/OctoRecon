import httpx
import asyncio
from typing import Any, Optional
from config import TIMEOUT, USER_AGENT, FOLLOW_REDIRECTS, VERIFY_SSL, MAX_CONCURRENT

class HTTPClient:
    def __init__(self, max_concurrent: Optional[int] = None):
        # Use a Semaphore to prevent socket exhaustion when running modules concurrently
        concurrency = max_concurrent or MAX_CONCURRENT
        self.semaphore = asyncio.Semaphore(concurrency)
        limits = httpx.Limits(max_keepalive_connections=50, max_connections=200, keepalive_expiry=30.0)
        self.client = httpx.AsyncClient(
            timeout=httpx.Timeout(TIMEOUT, connect=10.0),
            headers={"User-Agent": USER_AGENT},
            follow_redirects=FOLLOW_REDIRECTS,
            verify=VERIFY_SSL,
            limits=limits
        )

    async def get(self, url: str, **kwargs: Any) -> httpx.Response:
        async with self.semaphore:
            return await self.client.get(url, **kwargs)
    
    async def head(self, url: str, **kwargs: Any) -> httpx.Response:
        async with self.semaphore:
            return await self.client.head(url, **kwargs)

    async def post(self, url: str, **kwargs: Any) -> httpx.Response:
        async with self.semaphore:
            return await self.client.post(url, **kwargs)

    async def options(self, url: str, **kwargs: Any) -> httpx.Response:
        async with self.semaphore:
            return await self.client.options(url, **kwargs)
            
    async def request(self, method: str, url: str, **kwargs: Any) -> httpx.Response:
        async with self.semaphore:
            return await self.client.request(method, url, **kwargs)

    async def close(self):
        await self.client.aclose()
