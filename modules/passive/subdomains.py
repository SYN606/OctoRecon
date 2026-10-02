"""
Passive Subdomain Discovery Module
Author : 0ct0pu3
VERSION : 1.0.0
"""

from __future__ import annotations

import asyncio
import json
import random
import re
import socket
from urllib.parse import urlparse

from rich.table import Table

from core.base_module import BaseModule
from core.report_schema import Report


class Module(BaseModule):

    name = "subdomains"
    category = "Passive"

    description = ("Discover public subdomains.")

    MAX_RESULTS = 500

    # Max concurrent alive-check / DNS-resolve workers.
    # Keeps us from hammering the target (or resolvers) with
    # hundreds of simultaneous connections when a domain has
    # a large number of discovered subdomains.
    MAX_CONCURRENCY = 25

    DNS_TIMEOUT = 5

    # Per-request HTTP timeout (seconds). Kept short so a single
    # slow/unresponsive source can't stall the whole module.
    HTTP_TIMEOUT = 7

    # Small stagger between kicking off each source's first request.
    # Sources still run concurrently overall, but this avoids firing
    # every request in the same instant, which is what tends to
    # trigger rate limiting on free/anonymous API tiers.
    SOURCE_START_DELAY = 1.0

    USER_AGENTS = (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
        "(KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) "
        "AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Safari/605.1.15",
        "Mozilla/5.0 (X11; Linux x86_64; rv:127.0) Gecko/20100101 Firefox/127.0",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:127.0) "
        "Gecko/20100101 Firefox/127.0",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
        "(KHTML, like Gecko) Edg/125.0.0.0 Safari/537.36",
    )

    # Statuses that should be shown to the user as a clean, generic
    # label instead of a raw exception string / HTTP code. Keeping
    # the underlying detail out of the report table (it still gets
    # logged to console) makes the report readable for non-technical
    # reviewers while the console/debug output keeps the specifics.
    STATUS_LABELS = {
        "rate_limited": "Rate Limited",
        "unavailable": "Unavailable",
        "service_unavailable": "Service Unavailable",
        "bad_response": "Unavailable",
    }

    SOURCES = (
        "crt.sh",
        "BufferOver",
        "RapidDNS",
        "AlienVault OTX",
        "HackerTarget",
        "CertSpotter",
        "Anubis",
        "Wayback Machine",
        "URLScan",
        "ThreatMiner",
    )

    def __init__(self):

        super().__init__()

        self.results = {}
        self.domain = ""
        self.source_status = {}
        # Raw (unlabelled) status detail, kept for console/debug logging
        # so troubleshooting a specific source doesn't require re-running.
        self._raw_status = {}

    # =====================================================
    # Helpers
    # =====================================================

    @staticmethod
    def clean(name):

        if not name:
            return None

        name = name.lower().strip()

        if name.startswith("*."):
            name = name[2:]

        if name.endswith("."):
            name = name[:-1]

        return name

    @staticmethod
    def extract_root_domain(target):
        """
        Derive the root domain to enumerate subdomains for.

        Handles targets missing a scheme (e.g. "upjn.co.in" with no
        "https://") and strips a leading "www." so a target entered
        as "https://www.example.com" still matches subdomains of
        "example.com" (e.g. "mail.example.com") instead of only
        matching subdomains of "www.example.com", which would
        otherwise silently filter out every real result.
        """

        target = (target or "").strip()

        hostname = urlparse(target).hostname

        if not hostname:

            # Target likely has no scheme — retry as "//target"
            # so urlparse treats it as a netloc instead of a path.
            hostname = urlparse("//" + target.strip("/")).hostname

        hostname = (hostname or "").lower().strip(".")

        if hostname.startswith("www."):
            hostname = hostname[4:]

        return hostname

    def _headers(self):
        """Fresh header set with a randomly chosen User-Agent."""

        return {
            "User-Agent": random.choice(self.USER_AGENTS),
        }

    def add_result(self, hostname, source):

        hostname = self.clean(hostname)

        if not hostname:
            return

        if hostname == self.domain:
            return

        if not hostname.endswith("." + self.domain):
            return

        if hostname not in self.results:

            self.results[hostname] = {
                "sources": set(),
                "ip": "-",
                "alive": False,
            }

        self.results[hostname]["sources"].add(source)

    def _set_status(self, source_name, label_key, detail=None):
        """
        Record a clean, user-facing status label plus the raw detail
        (exception text / HTTP code) for console logging.
        """

        self.source_status[source_name] = self.STATUS_LABELS.get(
            label_key,
            label_key,
        )

        if detail:
            self._raw_status[source_name] = detail

    # =====================================================
    # Retry Helper (handles rate limiting / transient errors)
    # =====================================================

    async def _get_with_retry(
        self,
        scanner,
        url,
        source_name,
        retries=2,
        backoff=1.5,
    ):
        """
        GET a URL with retries + exponential backoff on 429/503
        (rate limit / temporarily unavailable) responses.

        Returns the response on success, or None if it never
        succeeded — in which case self.source_status[source_name]
        is already set (as a clean, user-facing label) to explain
        why, with the underlying detail kept in self._raw_status.
        """

        delay = backoff

        for attempt in range(retries + 1):

            try:

                response = await self.get(
                    scanner,
                    url,
                    headers=self._headers(),
                    timeout=self.HTTP_TIMEOUT,
                )

            except Exception as e:

                if attempt < retries:

                    await asyncio.sleep(delay)
                    delay *= 2
                    continue

                self._set_status(
                    source_name,
                    "unavailable",
                    detail=f"request failed: {e}",
                )
                return None

            if response.status_code in (429, 503) and attempt < retries:

                await asyncio.sleep(delay)
                delay *= 2
                continue

            if response.status_code == 429:

                self._set_status(
                    source_name,
                    "rate_limited",
                    detail=("rate limited (429) — reduce scan frequency "
                            "or add a delay between runs against this target"),
                )
                return None

            return response

        return None

    # =====================================================
    # crt.sh
    # =====================================================

    async def fetch_crtsh(self, scanner):

        url = (f"https://crt.sh/"
               f"?q=%25.{self.domain}"
               f"&output=json")

        response = await self._get_with_retry(
            scanner,
            url,
            "crt.sh",
        )

        if response is None:

            return

        if response.status_code != 200:

            self._set_status(
                "crt.sh",
                "service_unavailable",
                detail=f"http {response.status_code}",
            )
            return

        try:

            data = json.loads(response.text)

        except Exception:

            self._set_status(
                "crt.sh",
                "bad_response",
                detail="invalid json response",
            )
            return

        for item in data:

            names = item.get(
                "name_value",
                "",
            ).split("\n")

            for host in names:

                self.add_result(
                    host,
                    "crt.sh",
                )

        self.source_status["crt.sh"] = f"ok ({len(data)} certs)"

    # =====================================================
    # BufferOver
    # =====================================================

    async def fetch_bufferover(self, scanner):

        url = ("https://dns.bufferover.run/"
               f"dns?q=.{self.domain}")

        response = await self._get_with_retry(
            scanner,
            url,
            "BufferOver",
        )

        if response is None:

            return

        if response.status_code != 200:

            self._set_status(
                "BufferOver",
                "service_unavailable",
                detail=f"http {response.status_code}",
            )
            return

        try:

            data = response.json()

        except Exception:

            self._set_status(
                "BufferOver",
                "bad_response",
                detail="invalid json response",
            )
            return

        found = 0

        for section in (
                "FDNS_A",
                "RDNS",
        ):

            for item in data.get(
                    section,
                [],
            ):

                try:

                    _, host = item.split(",")

                except ValueError:

                    continue

                found += 1

                self.add_result(
                    host,
                    "BufferOver",
                )

        self.source_status["BufferOver"] = f"ok ({found} records)"

    # =====================================================
    # RapidDNS
    # =====================================================

    async def fetch_rapiddns(self, scanner):

        url = (f"https://rapiddns.io/subdomain/"
               f"{self.domain}"
               "?full=1")

        response = await self._get_with_retry(
            scanner,
            url,
            "RapidDNS",
        )

        if response is None:

            return

        if response.status_code != 200:

            self._set_status(
                "RapidDNS",
                "service_unavailable",
                detail=f"http {response.status_code}",
            )
            return

        pattern = re.compile(
            rf"([A-Za-z0-9_\-\.]+\.{re.escape(self.domain)})",
            re.I,
        )

        matches = set(pattern.findall(response.text))

        for host in matches:

            self.add_result(
                host,
                "RapidDNS",
            )

        self.source_status["RapidDNS"] = f"ok ({len(matches)} matches)"

    # =====================================================
    # AlienVault OTX
    # =====================================================

    async def fetch_otx(self, scanner):

        url = ("https://otx.alienvault.com/api/v1/"
               f"indicators/domain/{self.domain}/passive_dns")

        response = await self._get_with_retry(
            scanner,
            url,
            "AlienVault OTX",
        )

        if response is None:

            return

        if response.status_code != 200:

            self._set_status(
                "AlienVault OTX",
                "service_unavailable",
                detail=f"http {response.status_code}",
            )
            return

        try:

            data = response.json()

        except Exception:

            self._set_status(
                "AlienVault OTX",
                "bad_response",
                detail="invalid json response",
            )
            return

        found = 0

        for record in data.get(
                "passive_dns",
            [],
        ):

            host = record.get("hostname")

            if host:

                found += 1

                self.add_result(
                    host,
                    "AlienVault OTX",
                )

        self.source_status["AlienVault OTX"] = f"ok ({found} records)"

    # =====================================================
    # HackerTarget
    # =====================================================

    async def fetch_hackertarget(self, scanner):

        url = ("https://api.hackertarget.com/hostsearch/"
               f"?q={self.domain}")

        response = await self._get_with_retry(
            scanner,
            url,
            "HackerTarget",
        )

        if response is None:

            return

        if response.status_code != 200:

            self._set_status(
                "HackerTarget",
                "service_unavailable",
                detail=f"http {response.status_code}",
            )
            return

        text = response.text.strip()

        # HackerTarget returns a plain-text error string (no JSON,
        # no distinct HTTP code) once its free daily quota is used up.
        if "API count exceeded" in text or "error" in text.lower():

            self._set_status(
                "HackerTarget",
                "rate_limited",
                detail=text[:120],
            )
            return

        found = 0

        for line in text.splitlines():

            host = line.split(",")[0]

            if host:

                found += 1

                self.add_result(
                    host,
                    "HackerTarget",
                )

        self.source_status["HackerTarget"] = f"ok ({found} records)"

    # =====================================================
    # CertSpotter
    # =====================================================

    async def fetch_certspotter(self, scanner):

        url = ("https://api.certspotter.com/v1/issuances"
               f"?domain={self.domain}"
               "&include_subdomains=true&expand=dns_names")

        response = await self._get_with_retry(
            scanner,
            url,
            "CertSpotter",
        )

        if response is None:

            return

        if response.status_code != 200:

            self._set_status(
                "CertSpotter",
                "service_unavailable",
                detail=f"http {response.status_code}",
            )
            return

        try:

            data = response.json()

        except Exception:

            self._set_status(
                "CertSpotter",
                "bad_response",
                detail="invalid json response",
            )
            return

        found = 0

        for item in data:

            for host in item.get("dns_names", []):

                found += 1

                self.add_result(
                    host,
                    "CertSpotter",
                )

        self.source_status["CertSpotter"] = f"ok ({found} names)"

    # =====================================================
    # Anubis (jonlu.ca)
    # =====================================================

    async def fetch_anubis(self, scanner):

        url = f"https://jonlu.ca/anubis/subdomains/{self.domain}"

        response = await self._get_with_retry(
            scanner,
            url,
            "Anubis",
        )

        if response is None:

            return

        if response.status_code != 200:

            self._set_status(
                "Anubis",
                "service_unavailable",
                detail=f"http {response.status_code}",
            )
            return

        try:

            data = response.json()

        except Exception:

            self._set_status(
                "Anubis",
                "bad_response",
                detail="invalid json response",
            )
            return

        for host in data:

            self.add_result(
                host,
                "Anubis",
            )

        self.source_status["Anubis"] = f"ok ({len(data)} names)"

    # =====================================================
    # Wayback Machine
    # =====================================================

    async def fetch_wayback(self, scanner):

        url = ("https://web.archive.org/cdx/search/cdx"
               f"?url=*.{self.domain}"
               "&output=json&fl=original&collapse=urlkey")

        response = await self._get_with_retry(
            scanner,
            url,
            "Wayback Machine",
        )

        if response is None:

            return

        if response.status_code != 200:

            self._set_status(
                "Wayback Machine",
                "service_unavailable",
                detail=f"http {response.status_code}",
            )
            return

        try:

            rows = response.json()

        except Exception:

            self._set_status(
                "Wayback Machine",
                "bad_response",
                detail="invalid json response",
            )
            return

        found = 0

        # First row is the header (["original"]) — skip it.
        for row in rows[1:] if rows else []:

            try:

                host = urlparse(row[0]).hostname

            except Exception:

                continue

            if host:

                found += 1

                self.add_result(
                    host,
                    "Wayback Machine",
                )

        self.source_status["Wayback Machine"] = f"ok ({found} urls)"

    # =====================================================
    # URLScan
    # =====================================================

    async def fetch_urlscan(self, scanner):

        url = ("https://urlscan.io/api/v1/search/"
               f"?q=domain:{self.domain}")

        response = await self._get_with_retry(
            scanner,
            url,
            "URLScan",
        )

        if response is None:

            return

        if response.status_code != 200:

            self._set_status(
                "URLScan",
                "service_unavailable",
                detail=f"http {response.status_code}",
            )
            return

        try:

            data = response.json()

        except Exception:

            self._set_status(
                "URLScan",
                "bad_response",
                detail="invalid json response",
            )
            return

        found = 0

        for result in data.get("results", []):

            host = (result.get("page", {}).get("domain"))

            if host:

                found += 1

                self.add_result(
                    host,
                    "URLScan",
                )

        self.source_status["URLScan"] = f"ok ({found} pages)"

    # =====================================================
    # ThreatMiner
    # =====================================================

    async def fetch_threatminer(self, scanner):

        url = ("https://api.threatminer.org/v2/domain.php"
               f"?q={self.domain}&rt=5")

        response = await self._get_with_retry(
            scanner,
            url,
            "ThreatMiner",
        )

        if response is None:

            return

        if response.status_code != 200:

            self._set_status(
                "ThreatMiner",
                "service_unavailable",
                detail=f"http {response.status_code}",
            )
            return

        try:

            data = response.json()

        except Exception:

            self._set_status(
                "ThreatMiner",
                "bad_response",
                detail="invalid json response",
            )
            return

        results = data.get("results", []) or []

        for host in results:

            self.add_result(
                host,
                "ThreatMiner",
            )

        self.source_status["ThreatMiner"] = f"ok ({len(results)} names)"

    # =====================================================
    # Fetch All Sources
    # =====================================================

    async def collect(self, scanner):

        self.source_status = {}
        self._raw_status = {}

        fetchers = (
            self.fetch_crtsh,
            self.fetch_bufferover,
            self.fetch_rapiddns,
            self.fetch_otx,
            self.fetch_hackertarget,
            self.fetch_certspotter,
            self.fetch_anubis,
            self.fetch_wayback,
            self.fetch_urlscan,
            self.fetch_threatminer,
        )

        async def staggered(index, fetcher):

            # Space out each source's *first* request instead of
            # firing all ten in the same instant. Sources still run
            # concurrently (no source blocks another), this only
            # delays the starting gun for each one.
            await asyncio.sleep(index * self.SOURCE_START_DELAY)

            return await fetcher(scanner)

        results = await asyncio.gather(
            *(staggered(i, fetcher) for i, fetcher in enumerate(fetchers)),
            return_exceptions=True,
        )

        for source, result in zip(self.SOURCES, results):

            if isinstance(result, Exception):

                self._set_status(
                    source,
                    "unavailable",
                    detail=f"unhandled error: {result}",
                )

                scanner.console.print(
                    f"[yellow][!] {source}: {result}[/yellow]")

    # =====================================================
    # Resolve IP
    # =====================================================

    async def resolve_ip(self, hostname):

        try:

            loop = asyncio.get_running_loop()

            result = await asyncio.wait_for(
                loop.getaddrinfo(
                    hostname,
                    None,
                    family=socket.AF_UNSPEC,
                ),
                timeout=self.DNS_TIMEOUT,
            )

            if result:

                return result[0][4][0]

        except Exception:

            pass

        return "-"

    # =====================================================
    # Check Alive
    # =====================================================

    async def check_alive(self, scanner, hostname):

        for scheme in ("https", "http"):

            url = f"{scheme}://{hostname}"

            headers = self._headers()

            # HEAD Request
            try:

                response = await self.head(
                    scanner,
                    url,
                    follow_redirects=True,
                    headers=headers,
                    timeout=self.HTTP_TIMEOUT,
                )

                if response.status_code < 400:
                    return True

                # Some websites don't allow HEAD
                if response.status_code == 405:

                    response = await self.get(
                        scanner,
                        url,
                        follow_redirects=True,
                        headers=headers,
                        timeout=self.HTTP_TIMEOUT,
                    )

                    if response.status_code < 400:
                        return True

            except Exception:

                try:

                    response = await self.get(
                        scanner,
                        url,
                        follow_redirects=True,
                        headers=headers,
                        timeout=self.HTTP_TIMEOUT,
                    )

                    if response.status_code < 400:
                        return True

                except Exception:
                    pass

        return False

    # =====================================================
    # Resolve & Check All
    # =====================================================

    async def enrich_results(self, scanner):

        semaphore = asyncio.Semaphore(self.MAX_CONCURRENCY)

        async def worker(host):

            async with semaphore:

                ip = await self.resolve_ip(host)

                alive = await self.check_alive(
                    scanner,
                    host,
                )

            self.results[host]["ip"] = ip
            self.results[host]["alive"] = alive

        tasks = [worker(host) for host in self.results]

        await asyncio.gather(
            *tasks,
            return_exceptions=True,
        )

    # =====================================================
    # Build Report Rows
    # =====================================================

    def build_rows(self):

        rows = []

        alive = 0

        dead = 0

        for host in sorted(self.results):

            info = self.results[host]

            if info["alive"]:

                status = "Alive"

                alive += 1

            else:

                status = "Dead"

                dead += 1

            rows.append({
                "Subdomain": host,
                "IP": info["ip"],
                "Status": status,
                "Source": ", ".join(sorted(info["sources"])),
            })

        return rows, alive, dead

    # =====================================================
    # Score
    # =====================================================

    def calculate_score(self):

        total = len(self.results)

        if total > 50:

            self.score = self.max_score

        elif total >= 21:

            self.score = 8

        elif total >= 11:

            self.score = 6

        elif total >= 6:

            self.score = 4

        elif total >= 1:

            self.score = 2

        else:

            self.score = 0

    # =====================================================
    # Prepare Module
    # =====================================================

    async def prepare(self, scanner):

        self.reset_score()

        self.results.clear()

        self.domain = self.extract_root_domain(scanner.target)

        if not self.domain:

            scanner.console.print(
                "[bold red][!] Could not determine root domain "
                "for subdomain enumeration.[/bold red]")
            return

        await self.collect(scanner)

        if len(self.results) > self.MAX_RESULTS:

            # Sort before truncating so the kept subset is
            # deterministic across runs, instead of depending on
            # whichever source happened to respond first.
            sorted_items = sorted(self.results.items())

            self.results = dict(sorted_items[:self.MAX_RESULTS])

        await self.enrich_results(scanner)

        self.calculate_score()

    # =====================================================
    # Run Module
    # =====================================================

    async def run(self, scanner):

        await self.prepare(scanner)

        rows, alive, dead = self.build_rows()

        summary = Table(title="Subdomain Summary")

        summary.add_column("Category", style="cyan")
        summary.add_column("Count", justify="right", style="green")

        summary.add_row("Unique", str(len(self.results)))
        summary.add_row("Alive", str(alive))
        summary.add_row("Dead", str(dead))
        summary.add_row("Sources", str(len(self.SOURCES)))

        scanner.console.print(summary)

        status_table = Table(title="Source Status")

        status_table.add_column("Source", style="cyan")
        status_table.add_column("Status")

        for source in self.SOURCES:

            status_table.add_row(
                source,
                self.source_status.get(source, "No data returned"),
            )

        scanner.console.print(status_table)

        # Raw detail (exception text / HTTP codes) goes to the console
        # only, for troubleshooting — the report table stays clean.
        if self._raw_status:

            for source, detail in self._raw_status.items():

                scanner.console.print(f"[dim]  {source}: {detail}[/dim]")

        if not rows:

            rows.append({
                "Subdomain": "-",
                "IP": "-",
                "Status": "Not Found",
                "Source": "-",
            })

        description = (f"Found {len(self.results)} unique subdomains "
                       f"({alive} Alive, {dead} Dead) "
                       f"using {len(self.SOURCES)} passive sources.")

        failures = [
            f"{source}: {status}"
            for source, status in self.source_status.items()
            if not status.startswith("ok")
        ]

        if failures:

            description += " Issues — " + "; ".join(failures)

        scanner.report.add_module(
            self.name,
            Report.table(
                title="Passive Subdomain Discovery",
                columns=[
                    "Subdomain",
                    "IP",
                    "Status",
                    "Source",
                ],
                rows=rows,
                description=description,
                score=self.score,
                max_score=self.max_score,
            ),
        )
