"""
Email Discovery Module
Author : 0ct0pu3
VERSION : 1.0.0
"""

from __future__ import annotations

import asyncio
import re
from collections import deque
from urllib.parse import urljoin, urlparse

from bs4 import BeautifulSoup
from bs4 import Comment

from core.base_module import BaseModule
from core.models import ModuleResult, Finding, Severity


class Module(BaseModule):

    name = "emails"
    category = "Passive"

    description = ("Extract publicly exposed email addresses.")

    EMAIL_REGEX = re.compile(
        r"(?:[A-Za-z0-9!#$%&'*+/=?^_`{|}~-]+(?:\.[A-Za-z0-9!#$%&'*+/=?^_`{|}~-]+)*)@"
        r"(?:[A-Za-z0-9-]+\.)+[A-Za-z]{2,}",
        re.IGNORECASE,
    )

    OBFUSCATED_PATTERNS = (
        (
            re.compile(
                r"([A-Za-z0-9._%+-]+)\s*\[\s*at\s*\]\s*"
                r"([A-Za-z0-9.-]+)\s*\[\s*dot\s*\]\s*"
                r"([A-Za-z]{2,})",
                re.I,
            ),
            "{}@{}.{}",
        ),
        (
            re.compile(
                r"([A-Za-z0-9._%+-]+)\s*\(\s*at\s*\)\s*"
                r"([A-Za-z0-9.-]+)\s*\(\s*dot\s*\)\s*"
                r"([A-Za-z]{2,})",
                re.I,
            ),
            "{}@{}.{}",
        ),
        (
            re.compile(
                r"([A-Za-z0-9._%+-]+)\s+at\s+"
                r"([A-Za-z0-9.-]+)\s+dot\s+"
                r"([A-Za-z]{2,})",
                re.I,
            ),
            "{}@{}.{}",
        ),
    )

    COMMON_PATHS = [
        "/",
        "/contact",
        "/contact-us",
        "/contacts",
        "/about",
        "/about-us",
        "/support",
        "/help",
        "/privacy",
        "/privacy-policy",
        "/terms",
        "/terms-and-conditions",
        "/company",
        "/team",
        "/staff",
        "/legal",
        "/imprint",
    ]

    GENERIC_PREFIXES = {
        "admin",
        "administrator",
        "support",
        "help",
        "contact",
        "info",
        "security",
        "abuse",
        "soc",
        "noc",
        "billing",
        "sales",
        "marketing",
        "press",
        "media",
        "jobs",
        "career",
        "careers",
        "privacy",
        "legal",
        "webmaster",
        "postmaster",
        "hostmaster",
        "root",
        "hr",
    }

    INVALID_DOMAINS = {
        "example.com",
        "example.org",
        "example.net",
        "localhost",
        "invalid",
        "test.com",
    }

    SEARCH_TAGS = (
        ("a", "href"),
        ("script", "src"),
        ("link", "href"),
    )

    # Safety cap on number of pages crawled per scan.
    MAX_PAGES = 25

    # =====================================================
    # Normalize Email
    # =====================================================

    @staticmethod
    def normalize(email):

        if not email:

            return ""

        email = email.strip()

        email = email.lower()

        email = email.replace("mailto:", "")

        email = email.split("?")[0]

        return email

    # =====================================================
    # Validate Email
    # =====================================================

    def is_valid(self, email):

        email = self.normalize(email)

        if not email:

            return False

        if not self.EMAIL_REGEX.fullmatch(email):

            return False

        local, domain = email.split("@", 1)

        if domain in self.INVALID_DOMAINS:

            return False

        if len(local) < 1:

            return False

        return True

    # =====================================================
    # Decode Cloudflare Email
    # =====================================================

    @staticmethod
    def decode_cfemail(encoded):

        try:

            key = int(encoded[:2], 16)

            output = ""

            for i in range(2, len(encoded), 2):

                output += chr(int(encoded[i:i + 2], 16) ^ key)

            return output

        except Exception:

            return None

    # =====================================================
    # Decode Obfuscated Emails
    # =====================================================

    def extract_obfuscated(self, text):

        emails = set()

        if not text:

            return emails

        for pattern, fmt in self.OBFUSCATED_PATTERNS:

            for match in pattern.findall(text):

                emails.add(fmt.format(*match).lower())

        return emails

    # =====================================================
    # Extract Standard Emails
    # =====================================================

    def extract_normal(self, text):

        if not text:

            return set()

        return {
            self.normalize(email)
            for email in self.EMAIL_REGEX.findall(text)
        }

    # =====================================================
    # Extract mailto:
    # =====================================================

    def extract_mailto(self, soup):

        emails = set()

        for tag in soup.find_all("a", href=True):

            href = tag["href"].strip()

            if not href.lower().startswith("mailto:"):

                continue

            email = self.normalize(href[7:].split("?")[0])

            if self.is_valid(email):

                emails.add(email)

        return emails

    # =====================================================
    # Extract Cloudflare Emails
    # =====================================================

    def extract_cfemails(self, soup):

        emails = set()

        for tag in soup.select(".__cf_email__"):

            encoded = tag.get("data-cfemail")

            if not encoded:

                continue

            decoded = self.decode_cfemail(encoded)

            if decoded and self.is_valid(decoded):

                emails.add(self.normalize(decoded))

        return emails

    # =====================================================
    # Extract HTML Comments
    # =====================================================

    def extract_comments(self, soup):

        emails = set()

        comments = soup.find_all(string=lambda text: isinstance(text, Comment))

        for comment in comments:

            emails.update(self.extract_normal(str(comment)))

            emails.update(self.extract_obfuscated(str(comment)))

        return emails

    # =====================================================
    # Extract Inline JavaScript
    # =====================================================

    def extract_inline_js(self, soup):

        emails = set()

        for script in soup.find_all("script"):

            if script.get("src"):

                continue

            content = script.string or script.text or ""

            emails.update(self.extract_normal(content))

            emails.update(self.extract_obfuscated(content))

        return emails

    # =====================================================
    # Extract External JS URLs
    # =====================================================

    def extract_js_urls(self, soup, base_url):

        urls = set()

        for script in soup.find_all(
                "script",
                src=True,
        ):

            src = script["src"].strip()

            if not src:

                continue

            urls.add(urljoin(
                base_url,
                src,
            ))

        return urls

    # =====================================================
    # Extract Internal Links
    # =====================================================

    def discover_links(self, soup, base_url):

        links = set()

        target = urlparse(base_url).netloc

        keywords = (
            "contact",
            "about",
            "support",
            "help",
            "privacy",
            "terms",
            "company",
            "team",
            "staff",
            "career",
            "legal",
        )

        for tag in soup.find_all(
                "a",
                href=True,
        ):

            href = tag["href"].strip()

            if href.startswith((
                    "mailto:",
                    "tel:",
                    "#",
                    "javascript:",
            )):

                continue

            absolute = urljoin(
                base_url,
                href,
            )

            parsed = urlparse(absolute)

            if parsed.netloc != target:

                continue

            lower = parsed.path.lower()

            if any(key in lower for key in keywords):

                links.add(absolute)

        return links

    # =====================================================
    # Extract Everything From HTML
    # =====================================================

    def extract_html(self, html):

        soup = BeautifulSoup(
            html,
            "html.parser",
        )

        emails = set()

        emails.update(self.extract_normal(html))

        emails.update(self.extract_obfuscated(html))

        emails.update(self.extract_normal(soup.get_text(
            " ",
            strip=True,
        )))

        emails.update(self.extract_obfuscated(soup.get_text(
            " ",
            strip=True,
        )))

        emails.update(self.extract_mailto(soup))

        emails.update(self.extract_comments(soup))

        emails.update(self.extract_cfemails(soup))

        emails.update(self.extract_inline_js(soup))

        return soup, emails

    # =====================================================
    # Module Runner
    # =====================================================

    async def run(self, scanner):

        self.reset_score()

        rows = []

        emails = set()

        visited = set()

        queue = deque()

        # ==============================================
        # Fetch Seed URLs Concurrently (Bounded Concurrency)
        # ==============================================
        sem = asyncio.Semaphore(10)
        seed_urls = [urljoin(scanner.target, path) for path in self.COMMON_PATHS]
        
        async def _fetch_page(u):
            async with sem:
                # Check root cache if available
                if u.rstrip('/') == scanner.target.rstrip('/') and hasattr(scanner, "shared_cache") and "root_html" in scanner.shared_cache:
                    return u, scanner.shared_cache["root_html"]
                try:
                    resp = await self.get(scanner, u, follow_redirects=True, timeout=6)
                    if resp.status_code == 200:
                        return u, resp.text
                except Exception:
                    pass
                return u, None

        fetched_pages = await asyncio.gather(*(_fetch_page(u) for u in seed_urls))
        
        # Analyze fetched seed pages
        js_to_fetch = set()
        for u, html in fetched_pages:
            visited.add(u)
            if not html:
                continue
            soup, found = self.extract_html(html)
            emails.update(found)
            
            # Collect JS files
            for js_url in self.extract_js_urls(soup, u):
                js_to_fetch.add(js_url)

        # Fetch external JS scripts concurrently (Check shared cache first)
        scripts_cache = getattr(scanner, "shared_cache", {}).setdefault("scripts_content", {})

        async def _fetch_js(js_u):
            if js_u in scripts_cache:
                return scripts_cache[js_u]
            async with sem:
                try:
                    js_resp = await self.get(scanner, js_u, follow_redirects=True, timeout=6)
                    if js_resp.status_code == 200:
                        scripts_cache[js_u] = js_resp.text
                        return js_resp.text
                except Exception:
                    pass
                return None

        if js_to_fetch:
            js_results = await asyncio.gather(*(_fetch_js(ju) for ju in list(js_to_fetch)[:20]))
            for js_text in js_results:
                if js_text:
                    emails.update(self.extract_normal(js_text))
                    emails.update(self.extract_obfuscated(js_text))

        # ==============================================
        # Validation
        # ==============================================

        valid = []

        seen = set()

        for email in sorted(emails):

            email = self.normalize(email)

            if email in seen:

                continue

            seen.add(email)

            if not self.is_valid(email):

                continue

            valid.append(email)

        emails = valid

        # ==============================================
        # Classification
        # ==============================================
        target_domain = (urlparse(
            scanner.target).netloc.lower().removeprefix("www."))

        generic = 0

        personal = 0

        for email in emails:

            local, domain = email.split("@", 1)

            domain = domain.lower()

            if domain == target_domain:

                if local in self.GENERIC_PREFIXES:

                    category = "Official (Generic)"
                    generic += 1

                else:

                    category = "Official"

            else:

                category = "Personal"
                personal += 1

            rows.append({
                "Email": email,
                "Category": category,
            })
        # ==============================================
        # Score Calculation
        # ==============================================

        # Zero leaked emails is the ideal security posture (Full score 20/20)
        # Exposure penalties apply based on volume and personal addresses
        if len(emails) == 0:
            self.score = self.max_score
        else:
            deduction = min(len(emails) * 2, 14)
            if personal > 0:
                deduction = min(deduction + 3, 15)
            self.score = max(5, self.max_score - deduction)

        # ==============================================
        # Description
        # ==============================================

        official = len(emails) - personal
        description = (f"Found {len(emails)} email(s) "
                       f"({official} Official, {personal} Personal) "
                       f"across {len(visited)} page(s).")

        # ==============================================
        # Empty Results
        # ==============================================

        if not rows:

            rows.append({
                "Email": "-",
                "Category": "Not Found",
            })

        # ==============================================
        # Report
        # ==============================================

        findings: list[Finding] = []
        if not emails:
            findings.append(Finding(
                title="No Exposed Emails Found",
                severity=Severity.INFO,
                description=f"Scanned {len(visited)} pages, no public email addresses were discovered."
            ))
        else:
            sev = Severity.MEDIUM if personal > 0 or len(emails) >= 8 else Severity.LOW
            findings.append(Finding(
                title="Publicly Exposed Email Addresses",
                severity=sev,
                description=f"Discovered {len(emails)} exposed email(s) ({official} official, {personal} personal), increasing phishing and social engineering risk."
            ))

        return ModuleResult(
            name=self.name,
            category=self.category,
            summary=description,
            findings=findings,
            data={
                "emails": sorted(list(emails)),
                "official": official,
                "personal": personal,
                "visited_pages": len(visited),
                "rows": rows,
                "score": self.score,
                "max_score": self.max_score,
            }
        )
