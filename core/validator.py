"""
VALIDATOR
Author : 0ct0pu3
VERSION : 1.0.0
"""
import validators

from urllib.parse import urlparse


class URLValidator:

    @staticmethod
    def validate(url: str) -> str:

        if not url.startswith(("http://", "https://")):
            url = "https://" + url

        if not validators.url(url):
            raise ValueError("Invalid URL")

        parsed = urlparse(url)

        if parsed.scheme not in ("http", "https"):
            raise ValueError("Unsupported URL Scheme")

        return url