"""
Wayback Machine Module
Author : 0ct0pu3
VERSION : 1.0.0
"""

from __future__ import annotations

DISPLAY_LIMIT = 10

from urllib.parse import (
    urlparse,
    urlunparse,
)

from core.base_module import BaseModule


class Module(BaseModule):

    name = "wayback"
    category = "Passive"

    description = (
        "Collect archived URLs from Wayback Machine."
    )

    MAX_RESULTS = 5000

    def __init__(self):

        super().__init__()

        self.results = {}
        self.domain = ""

    # =====================================================
    # Helpers
    # =====================================================

    @staticmethod
    def extract_domain(target):

        host = urlparse(target).hostname

        if not host:

            host = urlparse("//" + target).hostname

        if not host:

            return ""

        return host.lower().lstrip("www.")

    @staticmethod
    def normalize_url(url):

        parsed = urlparse(url)

        scheme = parsed.scheme or "https"

        path = parsed.path.rstrip("/")

        return urlunparse(
            (
                scheme,
                parsed.netloc.lower(),
                path,
                "",
                parsed.query,
                "",
            )
        )

    def add_result(
        self,
        url,
        timestamp,
        status,
        mime,
    ):

        url = self.normalize_url(url)

        if not url:

            return

        if url not in self.results:

            self.results[url] = {
                "timestamp": timestamp,
                "status": status,
                "mime": mime,
            }

    # =====================================================
    # Wayback API
    # =====================================================

    async def fetch_wayback(self, scanner):

        api = (
            "https://web.archive.org/cdx/search/cdx"
            f"?url={self.domain}/*"
            "&output=json"
            "&fl=original,timestamp,statuscode,mimetype"
            "&collapse=urlkey"
            "&filter=statuscode:200"
        )

        try:

            response = await self.get(
                scanner,
                api,
            )

        except Exception:

            return

        if response.status_code != 200:

            return

        try:

            data = response.json()

        except Exception:

            return

        if not data:

            return

        # Skip header row
        for row in data[1:]:

            if len(row) < 4:

                continue

            self.add_result(
                row[0],
                row[1],
                row[2],
                row[3],
            )

    # =====================================================
    # Prepare
    # =====================================================

    async def prepare(self, scanner):

        self.reset_score()

        self.results.clear()

        self.domain = self.extract_domain(
            scanner.target
        )

        if not self.domain:

            return

        await self.fetch_wayback(scanner)

        if len(self.results) > self.MAX_RESULTS:

            self.results = dict(
                list(self.results.items())[: self.MAX_RESULTS]
            )

    # =====================================================
    # Categorization
    # =====================================================

    LOGIN_KEYWORDS = (
        "login",
        "signin",
        "auth",
        "account",
    )

    ADMIN_KEYWORDS = (
        "admin",
        "administrator",
        "manage",
        "dashboard",
        "panel",
    )

    API_KEYWORDS = (
        "/api/",
        "/v1/",
        "/v2/",
        "graphql",
        "swagger",
        "openapi",
    )

    ARCHIVE_EXTENSIONS = (
        ".zip",
        ".rar",
        ".7z",
        ".tar",
        ".gz",
        ".bak",
        ".old",
        ".sql",
    )

    DOCUMENT_EXTENSIONS = (
        ".pdf",
        ".doc",
        ".docx",
        ".xls",
        ".xlsx",
        ".ppt",
        ".pptx",
    )

    JS_EXTENSIONS = (
        ".js",
    )

    def categorize_url(self, url):

        lower = url.lower()

        if any(ext in lower for ext in self.ARCHIVE_EXTENSIONS):
            return "Archive"

        if any(ext in lower for ext in self.DOCUMENT_EXTENSIONS):
            return "Document"

        if any(ext in lower for ext in self.JS_EXTENSIONS):
            return "JavaScript"

        if any(word in lower for word in self.API_KEYWORDS):
            return "API"

        if any(word in lower for word in self.ADMIN_KEYWORDS):
            return "Admin"

        if any(word in lower for word in self.LOGIN_KEYWORDS):
            return "Login"

        if "?" in lower:
            return "Parameter"

        return "Other"

    # =====================================================
    # Risk
    # =====================================================

    RISK_PRIORITY = {
        "High": 0,
        "Medium": 1,
        "Low": 2,
        "Info": 3,
    }

    def risk_level(self, category):

        if category == "Archive":
            return "High"

        if category in (
            "Admin",
            "API",
        ):
            return "Medium"

        if category in (
            "Login",
            "Parameter",
        ):
            return "Low"

        return "Info"

    # =====================================================
    # Build Rows
    # =====================================================

    def build_rows(self):

        rows = []

        summary = {
            "Login": 0,
            "Admin": 0,
            "API": 0,
            "Archive": 0,
            "Document": 0,
            "JavaScript": 0,
            "Parameter": 0,
            "Other": 0,
        }

        for url in sorted(self.results):

            info = self.results[url]

            category = self.categorize_url(url)

            risk = self.risk_level(category)

            info["category"] = category
            info["risk"] = risk

            summary[category] += 1

            rows.append(
                {
                    "URL": url,
                    "Category": category,
                    "Risk": risk,
                    "Timestamp": info["timestamp"],
                }
            )

        return rows, summary

    # =====================================================
    # Score
    # =====================================================

    def calculate_score(self):

        self.score = 0

        for info in self.results.values():

            category = info.get("category")

            if category == "Archive":

                self.score += 5

            elif category == "Admin":

                self.score += 3

            elif category == "API":

                self.score += 2

            elif category == "Login":

                self.score += 1

        if self.score > self.max_score:

            self.score = self.max_score

    # =====================================================
    # Console Summary (condensed — full data goes to the report)
    # =====================================================

    def print_console_summary(self, scanner, rows, summary):

        from rich.table import Table

        total = len(self.results)

        labels = (
            ("Historical URLs", total),
            ("Admin Pages", summary["Admin"]),
            ("Login Pages", summary["Login"]),
            ("API Endpoints", summary["API"]),
            ("Archive Files", summary["Archive"]),
            ("Documents", summary["Document"]),
            ("JavaScript", summary["JavaScript"]),
            ("Parameters", summary["Parameter"]),
            ("Other", summary["Other"]),
        )

        width = max(len(label) for label, _ in labels)

        scanner.console.print("[bold]Wayback Machine[/bold]")

        for label, count in labels:

            scanner.console.print(
                f"{label.ljust(width)} : {count}"
            )

        top_rows = sorted(

            rows,

            key=lambda row: (
                self.RISK_PRIORITY.get(row["Risk"], 99),
                row["URL"],
            ),

        )[:DISPLAY_LIMIT]

        shown = len(top_rows)

        scanner.console.print(
            f"\nTop Findings ({shown}/{total})"
        )

        table = Table()

        table.add_column("URL", style="cyan")
        table.add_column("Category", style="green")
        table.add_column("Risk", style="yellow")
        table.add_column("Timestamp", style="magenta")

        for row in top_rows:

            table.add_row(
                row["URL"],
                row["Category"],
                row["Risk"],
                row["Timestamp"],
            )

        scanner.console.print(table)

        scanner.console.print(
            f"\nShowing {shown} of {total} historical URLs."
        )

    # =====================================================
    # Run Module
    # =====================================================

    async def run(self, scanner):

        await self.prepare(scanner)

        rows, summary = self.build_rows()

        from core.report_schema import Report

        self.print_console_summary(scanner, rows, summary)

        self.calculate_score()

        description = (
            f"Collected {len(self.results)} unique historical URLs "
            "from the Internet Archive Wayback Machine."
        )

        scanner.report.add_module(

            self.name,

            Report.table(

                title="Wayback Machine",

                columns=[
                    "URL",
                    "Category",
                    "Risk",
                    "Timestamp",
                ],

                rows=rows,

                description=description,

                score=self.score,

                max_score=self.max_score,

            ),

        )