"""
Async HTTP Client
Author : 0ct0pu3
VERSION : 1.0.0
"""

import httpx

from config import (
    TIMEOUT,
    USER_AGENT,
    FOLLOW_REDIRECTS,
    VERIFY_SSL,
)


class HTTPClient:

    def __init__(self):

        self.client = httpx.AsyncClient(
            timeout=TIMEOUT,
            headers={
                "User-Agent": USER_AGENT
            },
            follow_redirects=FOLLOW_REDIRECTS,
            verify=VERIFY_SSL,
        )

    async def get(self, url, **kwargs):

        return await self.client.get(
            url,
            **kwargs
        )

    async def head(self, url, **kwargs):

        return await self.client.head(
            url,
            **kwargs
        )

    async def post(self, url, **kwargs):

        return await self.client.post(
            url,
            **kwargs
        )

    async def options(self, url, **kwargs):

        return await self.client.options(
            url,
            **kwargs
        )

    async def request(
        self,
        method,
        url,
        **kwargs,
    ):

        return await self.client.request(
            method,
            url,
            **kwargs,
        )

    async def close(self):

        await self.client.aclose()