"""
ROBOTS FINDER Module
Author : 0ct0pu3
VERSION : 1.0.0
"""
from urllib.parse import urljoin

from core.base_module import BaseModule
from core.report_schema import Report


class Module(BaseModule):

    name = "robots"
    category = "Passive"

    description = ("Analyze robots.txt configuration.")

    SENSITIVE_KEYWORDS = [
        "admin",
        "backup",
        "private",
        "config",
        ".git",
        "test",
        "dev",
        "internal",
        "db",
        "database",
        "staging",
        "old",
    ]

    async def run(self, scanner):

        self.reset_score()

        url = urljoin(scanner.target, "/robots.txt")

        try:

            response = await self.get(
                scanner,
                url,
                follow_redirects=True,
            )

        except Exception as e:

            self.error(scanner, str(e))

            self.print_status(
                scanner,
                "robots.txt",
                "Unable to fetch",
            )

            self.add_report(
                scanner,
                Report.text(
                    title="robots.txt",
                    content=f"Unable to fetch robots.txt\n\n{e}",
                    score=0,
                    max_score=self.max_score,
                    description="robots.txt could not be retrieved.",
                ),
            )

            return

        if response.status_code != 200:

            self.print_status(
                scanner,
                "robots.txt",
                f"Not Found (HTTP {response.status_code})",
            )

            self.add_report(
                scanner,
                Report.text(
                    title="robots.txt",
                    content=
                    f"robots.txt not found (HTTP {response.status_code})",
                    score=10,
                    max_score=self.max_score,
                    description="Target does not expose robots.txt.",
                ),
            )

            return

        rows = []

        allow = 0
        disallow = 0
        sitemaps = []

        for line in response.text.splitlines():

            line = line.strip()

            if not line or line.startswith("#"):
                continue

            lower = line.lower()

            if lower.startswith("allow:"):

                value = line.split(":", 1)[1].strip()

                allow += 1

                rows.append({
                    "Directive": "Allow",
                    "Value": value,
                })

            elif lower.startswith("disallow:"):

                value = line.split(":", 1)[1].strip()

                disallow += 1

                rows.append({
                    "Directive": "Disallow",
                    "Value": value,
                })

                for keyword in self.SENSITIVE_KEYWORDS:

                    if keyword in value.lower():

                        self.deduct(1)

            elif lower.startswith("sitemap:"):

                value = line.split(":", 1)[1].strip()

                sitemaps.append(value)

                rows.append({
                    "Directive": "Sitemap",
                    "Value": value,
                })

            elif lower.startswith("host:"):

                rows.append({
                    "Directive": "Host",
                    "Value": line.split(":", 1)[1].strip(),
                })

            elif lower.startswith("crawl-delay:"):

                rows.append({
                    "Directive": "Crawl-delay",
                    "Value": line.split(":", 1)[1].strip(),
                })

        description = (f"{allow} Allow, "
                       f"{disallow} Disallow, "
                       f"{len(sitemaps)} Sitemap(s)")

        self.add_report(
            scanner,
            Report.table(
                title="robots.txt Analysis",
                columns=[
                    "Directive",
                    "Value",
                ],
                rows=rows,
                score=self.score,
                max_score=self.max_score,
                description=description,
            ),
        )

        self.print_table(
            scanner,
            title="robots.txt Analysis",
            columns=[
                "Directive",
                "Value",
            ],
            rows=rows,
        )
