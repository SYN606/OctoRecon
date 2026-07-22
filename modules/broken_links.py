"""
Broken Link Scanner
Author : 0ct0pu3
Version : 1.0.0
"""

import time

from urllib.parse import (
    urljoin,
    urlparse,
)

import httpx

from core.report_schema import Report

from bs4 import BeautifulSoup

from rich.table import Table

from core.base_module import BaseModule

SOCIAL_DOMAINS = {
    "facebook.com",
    "instagram.com",
    "linkedin.com",
    "twitter.com",
    "x.com",
    "github.com",
    "youtube.com",
    "discord.com",
    "discord.gg",
    "t.me",
    "telegram.me",
    "whatsapp.com",
    "wa.me",
}


DOCUMENT_EXTENSIONS = (
    ".pdf",
    ".doc",
    ".docx",
    ".xls",
    ".xlsx",
    ".ppt",
    ".pptx",
    ".zip",
    ".rar",
    ".7z",
)


IMAGE_EXTENSIONS = (
    ".png",
    ".jpg",
    ".jpeg",
    ".gif",
    ".svg",
    ".bmp",
    ".webp",
    ".ico",
)


CSS_EXTENSIONS = (
    ".css",
)


JS_EXTENSIONS = (
    ".js",
)


class LinkExtractor:

    def __init__(self, target, html):

        self.target = target
        self.base_domain = urlparse(target).netloc

        self.soup = BeautifulSoup(
            html,
            "html.parser",
        )

    def normalize(self, url):

        if not url:
            return None

        url = url.strip()

        if (
            url.startswith("#")
            or url.startswith("javascript:")
            or url.startswith("mailto:")
            or url.startswith("tel:")
        ):
            return None

        return urljoin(
            self.target,
            url,
        )

    def categorize(self, url):

        parsed = urlparse(url)

        host = parsed.netloc.lower()

        path = parsed.path.lower()

        if any(
            host.endswith(domain)
            for domain in SOCIAL_DOMAINS
        ):
            return "social"

        if path.endswith(IMAGE_EXTENSIONS):
            return "images"

        if path.endswith(CSS_EXTENSIONS):
            return "css"

        if path.endswith(JS_EXTENSIONS):
            return "javascript"

        if path.endswith(DOCUMENT_EXTENSIONS):
            return "documents"

        if host == self.base_domain:
            return "internal"

        return "external"

    def extract(self):

        links = []

        selectors = [

            ("a", "href"),

            ("img", "src"),

            ("script", "src"),

            ("link", "href"),

        ]

        for tag, attribute in selectors:

            for element in self.soup.find_all(tag):

                raw = element.get(attribute)

                url = self.normalize(raw)

                if not url:
                    continue

                links.append(
                    {
                        "url": url,
                        "type": self.categorize(url),
                    }
                )

        unique = []

        visited = set()

        for item in links:

            if item["url"] in visited:
                continue

            visited.add(item["url"])

            unique.append(item)

        return unique


class LinkChecker:

    def __init__(self, client):

        self.client = client

    async def _request(self, method, url):

        start = time.perf_counter()

        response = await self.client.request(
            method,
            url,
            follow_redirects=True,
        )

        elapsed = round(
            (time.perf_counter() - start) * 1000,
            2,
        )

        return response, elapsed

    async def check(self, item):

        url = item["url"]

        result = {
            "url": url,
            "type": item["type"],
            "status": "UNKNOWN",
            "status_code": None,
            "response_time": None,
            "content_type": "-",
            "redirects": 0,
            "broken": False,
        }

        try:

            try:

                response, elapsed = await self._request(
                    "HEAD",
                    url,
                )

            except Exception:

                response, elapsed = await self._request(
                    "GET",
                    url,
                )

            result["status_code"] = response.status_code

            result["response_time"] = elapsed

            result["redirects"] = len(
                response.history
            )

            result["content_type"] = response.headers.get(
                "Content-Type",
                "-",
            )

            if response.status_code < 300:

                result["status"] = "OK"

            elif response.status_code < 400:

                result["status"] = "REDIRECT"

            elif response.status_code == 403:

                result["status"] = "FORBIDDEN"

            elif response.status_code == 404:

                result["status"] = "BROKEN"

                result["broken"] = True

            elif response.status_code >= 500:

                result["status"] = "SERVER ERROR"

                result["broken"] = True

            else:

                result["status"] = "ERROR"

                result["broken"] = True

        except httpx.ConnectTimeout:

            result["status"] = "TIMEOUT"

            result["broken"] = True

        except httpx.ReadTimeout:

            result["status"] = "TIMEOUT"

            result["broken"] = True

        except httpx.ConnectError:

            result["status"] = "CONNECTION ERROR"

            result["broken"] = True

        except httpx.NetworkError:

            result["status"] = "NETWORK ERROR"

            result["broken"] = True

        except httpx.HTTPError:

            result["status"] = "HTTP ERROR"

            result["broken"] = True

        except Exception as e:

            result["status"] = f"ERROR ({e})"

            result["broken"] = True

        return result


class BrokenLinkScanner(BaseModule):

    name = "Broken Links"
    slug = "broken-links"

    aliases = [
        "brokenlinks",
        "broken-link",
        "broken",
    ]

    category = "Web"

    description = (
        "Check internal, external and static resource links for availability."
    )

    async def run(self, scanner):

        response = scanner.response

        extractor = LinkExtractor(
            scanner.target,
            response.text,
        )

        links = extractor.extract()

        checker = LinkChecker(
            scanner.client.client
        )

        table = Table(title="Broken Links Found")

        table.add_column("Type", style="cyan")
        table.add_column("Status")
        table.add_column("Code")
        table.add_column("Time")
        table.add_column("URL", overflow="fold")

        summary = {
            "internal": 0,
            "external": 0,
            "social": 0,
            "images": 0,
            "css": 0,
            "javascript": 0,
            "documents": 0,
            "broken": 0,
            "redirects": 0,
            "total": len(links),
        }

        results = []

        for item in links:

            result = await checker.check(item)

            results.append(result)

            link_type = result["type"]

            if link_type in summary:
                summary[link_type] += 1

            if result["broken"]:
                summary["broken"] += 1

            if result["redirects"] > 0:
                summary["redirects"] += 1

            # Console stays clean — only broken links get a row here.
            # Every link (OK, redirect, broken, everything) still goes
            # into the full report below.
            if not result["broken"]:
                continue

            status = result["status"]

            if status == "BROKEN":
                status_text = "[red]BROKEN[/red]"

            elif status == "FORBIDDEN":
                status_text = "[magenta]403[/magenta]"

            else:
                status_text = f"[red]{status}[/red]"

            table.add_row(
                result["type"],
                status_text,
                str(result["status_code"]),
                (
                    f"{result['response_time']} ms"
                    if result["response_time"]
                    else "-"
                ),
                result["url"],
            )

        if summary["broken"] > 0:

            scanner.console.print(table)

        else:

            scanner.console.print(
                "[green]No broken links found.[/green]"
            )

        summary_table = Table(
            title="Broken Link Summary"
        )

        summary_table.add_column("Category")
        summary_table.add_column("Count")

        for key, value in summary.items():

            summary_table.add_row(
                key.replace("_", " ").title(),
                str(value),
            )

        scanner.console.print(summary_table)

        score = 20
        max_score = 20

        if summary["broken"] > 0:
            score -= min(summary["broken"], 10)

        rows = []

        for item in results:

            rows.append(
                {
                    "Type": item["type"],
                    "Status": item["status"],
                    "HTTP Code": item["status_code"],
                    "Response Time": (
                        f"{item['response_time']} ms"
                        if item["response_time"]
                        else "-"
                    ),
                    "URL": item["url"],
                }
            )

        scanner.report.add_module(
            self.name,
            Report.table(
                title="Broken Link Scanner",
                columns=[
                    "Type",
                    "Status",
                    "HTTP Code",
                    "Response Time",
                    "URL",
                ],
                rows=rows,
                score=max(score, 0),
                max_score=max_score,
                description="Checks internal, external and static resource links for availability.",
            ),
        )