"""
SITEMAP Module
Author : 0ct0pu3
VERSION : 1.0.0
"""

import xml.etree.ElementTree as ET
from urllib.parse import urljoin

from core.base_module import BaseModule
from core.report_schema import Report


class Module(BaseModule):

    name = "sitemap"
    category = "Passive"

    description = (
        "Discover and analyze sitemap.xml."
    )

    LOCATIONS = [
        "/sitemap.xml",
        "/sitemap_index.xml",
        "/sitemap-index.xml",
    ]

    async def run(self, scanner):

        self.reset_score()

        response = None
        location = None

        for path in self.LOCATIONS:

            try:

                r = await self.get(
                    scanner,
                    urljoin(scanner.target, path),
                    follow_redirects=True,
                )

                if r.status_code == 200:
                    response = r
                    location = path
                    break

            except Exception:
                continue

        if response is None:

            self.print_status(
                scanner,
                "Sitemap",
                "Not Found",
            )

            self.add_report(
                scanner,
                Report.text(
                    title="Sitemap Analysis",
                    content="No sitemap.xml found.",
                    score=10,
                    max_score=self.max_score,
                    description="No XML sitemap was detected.",
                ),
            )

            return

        try:

            root = ET.fromstring(response.text)

        except Exception as e:

            self.error(scanner, str(e))

            self.print_status(
                scanner,
                "Sitemap",
                "Invalid XML",
            )

            self.add_report(
                scanner,
                Report.text(
                    title="Sitemap Analysis",
                    content=f"Invalid XML\n\n{e}",
                    score=5,
                    max_score=self.max_score,
                    description="Sitemap exists but XML parsing failed.",
                ),
            )

            return

        ns = {}

        if root.tag.startswith("{"):
            uri = root.tag.split("}")[0].strip("{")
            ns = {"sm": uri}

        rows = []

        url_count = 0
        sitemap_count = 0

        # ---------------- URLSET ----------------

        if root.tag.endswith("urlset"):

            urls = (
                root.findall("sm:url", ns)
                if ns else
                root.findall("url")
            )

            for url in urls:

                loc = url.find("sm:loc", ns) if ns else url.find("loc")
                lastmod = url.find("sm:lastmod", ns) if ns else url.find("lastmod")
                changefreq = (
                    url.find("sm:changefreq", ns)
                    if ns else
                    url.find("changefreq")
                )
                priority = (
                    url.find("sm:priority", ns)
                    if ns else
                    url.find("priority")
                )

                rows.append(
                    {
                        "Type": "URL",
                        "Location": loc.text if loc is not None else "",
                        "Last Modified": lastmod.text if lastmod is not None else "",
                        "Change Frequency": changefreq.text if changefreq is not None else "",
                        "Priority": priority.text if priority is not None else "",
                    }
                )

                url_count += 1

        # ---------------- SITEMAP INDEX ----------------

        elif root.tag.endswith("sitemapindex"):

            maps = (
                root.findall("sm:sitemap", ns)
                if ns else
                root.findall("sitemap")
            )

            for sm in maps:

                loc = sm.find("sm:loc", ns) if ns else sm.find("loc")
                lastmod = (
                    sm.find("sm:lastmod", ns)
                    if ns else
                    sm.find("lastmod")
                )

                rows.append(
                    {
                        "Type": "Sitemap",
                        "Location": loc.text if loc is not None else "",
                        "Last Modified": lastmod.text if lastmod is not None else "",
                        "Change Frequency": "",
                        "Priority": "",
                    }
                )

                sitemap_count += 1

        if url_count == 0 and sitemap_count == 0:
            self.deduct(15)

        description = (
            f"Detected at {location} | "
            f"{url_count} URLs | "
            f"{sitemap_count} Nested Sitemap(s)"
        )

        self.add_report(
            scanner,
            Report.table(
                title="Sitemap Analysis",
                columns=[
                    "Type",
                    "Location",
                    "Last Modified",
                    "Change Frequency",
                ],
                rows=rows,
                score=self.score,
                max_score=self.max_score,
                description=description,
            ),
        )

        self.print_table(
            scanner,
            title="Sitemap Analysis",
            columns=[
                "Type",
                "Location",
                "Last Modified",
                "Change Frequency",
            ],
            rows=rows,
            limit=10,
        )

        return