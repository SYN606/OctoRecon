import httpx
import asyncio
from typing import Any
from config import TIMEOUT, USER_AGENT, FOLLOW_REDIRECTS, VERIFY_SSL

class HTTPClient:
    def __init__(self, max_concurrent: int = 50):
        # Use a Semaphore to prevent socket exhaustion when running 100s of modules concurrently
        self.semaphore = asyncio.Semaphore(max_concurrent)
        self.client = httpx.AsyncClient(
            timeout=TIMEOUT,
            headers={"User-Agent": USER_AGENT},
            follow_redirects=FOLLOW_REDIRECTS,
            verify=VERIFY_SSL
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