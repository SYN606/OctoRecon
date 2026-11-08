"""
ROBOTS FINDER Module
Author : 0ct0pu3 / SYN606
VERSION : 2.0.0
"""
from urllib.parse import urljoin
from rich.table import Table

from core.base_module import BaseModule
from core.schemas import ModuleResult

class Module(BaseModule):
    name = "robots"
    category = "Passive"
    description = "Analyze robots.txt configuration and identify sensitive disallow directives."
    max_score = 15

    SENSITIVE_KEYWORDS = [
        "admin", "backup", "private", "config", ".git", "test", "dev",
        "internal", "db", "database", "staging", "old", "secret"
    ]

    async def run(self, scanner) -> ModuleResult:
        result = ModuleResult(module_name=self.name, max_score=self.max_score)
        self.reset_score()

        # Check shared cache first
        text = None
        if hasattr(scanner, "shared_cache") and "robots" in scanner.shared_cache:
            text = scanner.shared_cache["robots"]

        if not text:
            url = urljoin(scanner.target, "/robots.txt")
            try:
                response = await self.get(scanner, url, follow_redirects=True, timeout=8)
                if response.status_code == 200:
                    text = response.text
                    if hasattr(scanner, "shared_cache"):
                        scanner.shared_cache["robots"] = text
                else:
                    result.score = 10
                    result.description = f"robots.txt not found (HTTP {response.status_code})."
                    result.data = [{"Directive": "Status", "Value": f"Not Found (HTTP {response.status_code})"}]
                    return result
            except Exception as e:
                result.score = 0
                result.description = f"Unable to fetch robots.txt: {e}"
                result.data = [{"Directive": "Status", "Value": "Fetch Failed"}]
                return result

        rows = []
        allow = 0
        disallow = 0
        sitemaps = []
        score = self.max_score

        for line in text.splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue

            lower = line.lower()
            if lower.startswith("allow:"):
                val = line.split(":", 1)[1].strip()
                allow += 1
                rows.append({"Directive": "Allow", "Value": val})
            elif lower.startswith("disallow:"):
                val = line.split(":", 1)[1].strip()
                disallow += 1
                rows.append({"Directive": "Disallow", "Value": val})
                if any(kw in val.lower() for kw in self.SENSITIVE_KEYWORDS):
                    score = max(0, score - 1)
            elif lower.startswith("sitemap:"):
                val = line.split(":", 1)[1].strip()
                sitemaps.append(val)
                rows.append({"Directive": "Sitemap", "Value": val})
            elif lower.startswith("crawl-delay:"):
                rows.append({"Directive": "Crawl-delay", "Value": line.split(":", 1)[1].strip()})

        table = Table(title="robots.txt Analysis")
        table.add_column("Directive", style="cyan")
        table.add_column("Value")
        for r in rows[:25]:
            table.add_row(r["Directive"], r["Value"])

        if rows:
            scanner.console.print(table)

        result.score = score
        result.description = f"Found {allow} Allow, {disallow} Disallow, and {len(sitemaps)} Sitemap directive(s)."
        result.data = rows
        return result
