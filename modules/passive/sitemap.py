"""
SITEMAP Module
Author : 0ct0pu3
VERSION : 2.0.0
"""

from __future__ import annotations

import xml.etree.ElementTree as ET
from urllib.parse import urljoin

from core.base_module import BaseModule
from core.models import ModuleResult, Finding, Severity


class Module(BaseModule):

    name = "sitemap"
    category = "Passive"
    description = "Discover and analyze sitemap.xml."

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

        findings: list[Finding] = []

        if response is None:
            findings.append(Finding(
                title="Sitemap Not Found",
                severity=Severity.INFO,
                description="No XML sitemap was detected at standard locations."
            ))
            return ModuleResult(
                name=self.name,
                category=self.category,
                summary="No sitemap.xml found.",
                findings=findings,
                data={"found": False, "rows": []}
            )

        try:
            root = ET.fromstring(response.text)
        except Exception as e:
            findings.append(Finding(
                title="Invalid Sitemap XML",
                severity=Severity.LOW,
                description=f"Sitemap found at {location} but XML parsing failed: {e}"
            ))
            return ModuleResult(
                name=self.name,
                category=self.category,
                summary="Sitemap exists but XML parsing failed.",
                findings=findings,
                data={"found": True, "location": location, "error": str(e), "rows": []}
            )

        ns = {}
        if root.tag.startswith("{"):
            uri = root.tag.split("}")[0].strip("{")
            ns = {"sm": uri}

        rows = []
        url_count = 0
        sitemap_count = 0

        # ---------------- URLSET ----------------
        if root.tag.endswith("urlset"):
            urls = root.findall("sm:url", ns) if ns else root.findall("url")
            for url in urls:
                loc = url.find("sm:loc", ns) if ns else url.find("loc")
                lastmod = url.find("sm:lastmod", ns) if ns else url.find("lastmod")
                changefreq = url.find("sm:changefreq", ns) if ns else url.find("changefreq")
                priority = url.find("sm:priority", ns) if ns else url.find("priority")

                rows.append({
                    "Type": "URL",
                    "Location": loc.text if loc is not None else "",
                    "Last Modified": lastmod.text if lastmod is not None else "",
                    "Change Frequency": changefreq.text if changefreq is not None else "",
                    "Priority": priority.text if priority is not None else "",
                })
                url_count += 1

        # ---------------- SITEMAP INDEX ----------------
        elif root.tag.endswith("sitemapindex"):
            maps = root.findall("sm:sitemap", ns) if ns else root.findall("sitemap")
            for sm in maps:
                loc = sm.find("sm:loc", ns) if ns else sm.find("loc")
                lastmod = sm.find("sm:lastmod", ns) if ns else sm.find("lastmod")

                rows.append({
                    "Type": "Sitemap",
                    "Location": loc.text if loc is not None else "",
                    "Last Modified": lastmod.text if lastmod is not None else "",
                    "Change Frequency": "",
                    "Priority": "",
                })
                sitemap_count += 1

        if url_count == 0 and sitemap_count == 0:
            self.deduct(15)
            findings.append(Finding(
                title="Empty Sitemap",
                severity=Severity.INFO,
                description="Sitemap XML contained 0 URLs and 0 nested sitemaps."
            ))
        else:
            findings.append(Finding(
                title="Sitemap Discovered",
                severity=Severity.INFO,
                description=f"Discovered {url_count} URL(s) and {sitemap_count} nested sitemap(s)."
            ))

        description = (f"Detected at {location} | "
                       f"{url_count} URLs | "
                       f"{sitemap_count} Nested Sitemap(s)")

        return ModuleResult(
            name=self.name,
            category=self.category,
            summary=description,
            findings=findings,
            data={
                "found": True,
                "location": location,
                "url_count": url_count,
                "sitemap_count": sitemap_count,
                "rows": rows,
                "score": self.score,
                "max_score": self.max_score,
            }
        )
