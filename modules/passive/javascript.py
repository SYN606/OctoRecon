"""
JAVASCRIPT Module
Author : 0ct0pu3
VERSION : 1.0.0
"""
import re
import asyncio
from urllib.parse import urljoin

from bs4 import BeautifulSoup

from core.base_module import BaseModule
from core.models import ModuleResult, Finding, Severity
from rich.table import Table


class Module(BaseModule):

    name = "javascript"
    category = "Passive"

    description = ("Discover external JavaScript resources.")

    API_PATTERNS = [
        r"/api/[A-Za-z0-9_\-/]+",
        r"/v1/[A-Za-z0-9_\-/]+",
        r"/v2/[A-Za-z0-9_\-/]+",
        r"/graphql",
        r"/graphql/",
        r"/rest/",
        r"/oauth/",
        r"/auth/",
        r"/login",
        r"/logout",
        r"/register",
    ]

    SECRET_PATTERNS = {
        "AWS Access Key": r"AKIA[0-9A-Z]{16}",
        "Google API Key": r"AIza[0-9A-Za-z\-_]{35}",
        "JWT": r"eyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+",
        "Bearer Token": r"Bearer\s+[A-Za-z0-9\-_\.=]+",
        "Stripe Live": r"sk_live_[0-9A-Za-z]+",
        "Slack Token": r"xox[baprs]-[A-Za-z0-9-]+",
    }

    async def run(self, scanner):

        self.reset_score()

        html_text = ""
        if hasattr(scanner, "shared_cache") and "root_html" in scanner.shared_cache:
            html_text = scanner.shared_cache["root_html"]
        elif getattr(scanner, "response", None) is not None and getattr(scanner.response, "text", None):
            html_text = scanner.response.text
        else:
            try:
                response = await self.get(
                    scanner,
                    scanner.target,
                )
                html_text = response.text
            except Exception as e:
                self.error(scanner, str(e))
                return ModuleResult(
                    name=self.name,
                    category=self.category,
                    summary="Target page could not be downloaded.",
                    findings=[
                        Finding(
                            title="Target Unreachable",
                            severity=Severity.HIGH,
                            description=str(e),
                        )
                    ],
                    data={"error": str(e), "score": 0, "max_score": self.max_score},
                )

        soup = BeautifulSoup(
            html_text,
            "html.parser",
        )

        js_files = []
        api_hits = []
        secret_hits = []
        source_maps = []
        websocket_urls = []
        firebase_hits = []

        rows = []

        # ---------------------------------------
        # Collect JavaScript Files
        # ---------------------------------------

        for script in soup.find_all("script"):

            src = script.get("src")

            if not src:
                continue

            js_files.append(urljoin(
                scanner.target,
                src,
            ))

        js_files = sorted(set(js_files))

        # ---------------------------------------
        # Analyze JavaScript Files Concurrently
        # ---------------------------------------
        sem = asyncio.Semaphore(15)

        async def _analyze_js(js):
            try:
                async with sem:
                    r = await self.get(scanner, js, timeout=8)
            except Exception:
                return None

            text = r.text
            local_sm = []
            local_ws = []
            local_fb = []
            local_api = []
            local_sec = []

            # Source Maps
            if js.endswith(".map") or "sourceMappingURL=" in text:
                local_sm.append(js)

            # WebSocket URLs
            local_ws.extend(re.findall(r"wss?://[^\s\"']+", text))

            # Firebase References
            lower = text.lower()
            for keyword in ["firebase", "firebaseapp.com", "firebaseio.com", "firestore", "googleapis.com"]:
                if keyword in lower:
                    local_fb.append(js)
                    break

            # API Endpoints
            for pattern in self.API_PATTERNS:
                try:
                    matches = re.findall(pattern, text)
                    if matches:
                        local_api.extend(matches)
                except Exception:
                    continue

            # Secrets Detection
            for name, pattern in self.SECRET_PATTERNS.items():
                try:
                    matches = re.findall(pattern, text)
                    for secret in matches:
                        local_sec.append((name, secret[:50]))
                except Exception:
                    continue

            # Email Addresses
            emails = sorted(set(re.findall(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}", text)))

            # IPv4 Addresses
            ips = sorted(set(re.findall(r"(?:\d{1,3}\.){3}\d{1,3}", text)))

            admin_keywords = [
                "admin", "administrator", "root", "password", "passwd",
                "token", "secret", "apikey", "api_key", "accesskey",
                "privatekey", "jwt", "bearer", "authorization",
            ]
            keyword_hits = [kw for kw in admin_keywords if kw in lower]

            return {
                "js": js,
                "sm": local_sm,
                "ws": local_ws,
                "fb": local_fb,
                "api": local_api,
                "sec": local_sec,
                "emails": emails,
                "ips": ips,
                "keyword_hits": keyword_hits
            }

        js_results = await asyncio.gather(*(_analyze_js(js) for js in js_files))

        for res in js_results:
            if not res:
                continue
            js = res["js"]
            source_maps.extend(res["sm"])
            websocket_urls.extend(res["ws"])
            firebase_hits.extend(res["fb"])
            api_hits.extend(res["api"])
            secret_hits.extend(res["sec"])

            if res["sm"]:
                self.deduct(2)
            if res["fb"]:
                self.deduct(2)
            if res["ws"]:
                self.deduct(1)
            if res["api"]:
                self.deduct(min(len(res["api"]), 3))
            if res["keyword_hits"]:
                self.deduct(min(len(res["keyword_hits"]), 3))
            if res["sec"]:
                self.deduct(10)

            rows.append({
                "JavaScript": js,
                "APIs": len(set(res["api"])),
                "Secrets": len(res["sec"]),
                "Emails": len(res["emails"]),
                "IPs": len(res["ips"]),
                "Source Maps": ("Yes" if res["sm"] else "No"),
                "Firebase": ("Yes" if res["fb"] else "No"),
                "WebSocket": ("Yes" if res["ws"] else "No"),
            })

        # ---------------------------------------
        # Cleanup
        # ---------------------------------------

        js_files = sorted(set(js_files))
        api_hits = sorted(set(api_hits))
        source_maps = sorted(set(source_maps))
        websocket_urls = sorted(set(websocket_urls))
        firebase_hits = sorted(set(firebase_hits))

        secret_hits = list(dict.fromkeys(secret_hits))

        # ---------------------------------------
        # Build Summary
        # ---------------------------------------

        summary = [
            f"JavaScript Files : {len(js_files)}",
            f"API Endpoints : {len(api_hits)}",
            f"Secrets Found : {len(secret_hits)}",
            f"Source Maps : {len(source_maps)}",
            f"Firebase References : {len(firebase_hits)}",
            f"WebSocket URLs : {len(websocket_urls)}",
        ]

        description = " | ".join(summary)

        # ---------------------------------------
        # Console Summary
        # ---------------------------------------

        table = Table(title="JavaScript")

        table.add_column("Property", style="cyan")
        table.add_column("Value", style="green")

        # Status

        if not js_files:

            status = "Not Found"

        elif secret_hits:

            status = "Critical"

        elif source_maps or firebase_hits or websocket_urls:

            status = "Warning"

        else:

            status = "Found"

        table.add_row("Status", status)

        if js_files:

            table.add_row(
                "Files",
                str(len(js_files)),
            )

            table.add_row(
                "API Endpoints",
                str(len(api_hits)),
            )

            table.add_row(
                "Secrets",
                str(len(secret_hits)),
            )

            email_count = len({row["Emails"] for row in rows})

            ip_count = len({row["IPs"] for row in rows})

            table.add_row(
                "Emails",
                str(email_count),
            )

            table.add_row(
                "Source Maps",
                str(len(source_maps)),
            )

            table.add_row(
                "Firebase",
                str(len(firebase_hits)),
            )

            table.add_row(
                "WebSockets",
                str(len(websocket_urls)),
            )

        scanner.console.print(table)

        # ---------------------------------------
        # No JavaScript Found
        # ---------------------------------------

        if not rows:

            table = Table(title="JavaScript")

            table.add_column("Property", style="cyan")
            table.add_column("Value", style="green")

            table.add_row("Status", "Not Found")

            return ModuleResult(
                name=self.name,
                category=self.category,
                summary="No JavaScript files were detected.",
                findings=[
                    Finding(
                        title="No External JavaScript Found",
                        severity=Severity.INFO,
                        description="No external JavaScript resources were found on the root page.",
                    )
                ],
                data={"scripts_count": 0, "rows": [], "score": self.max_score, "max_score": self.max_score},
            )

        # ---------------------------------------
        # Structured Findings & Return
        # ---------------------------------------

        findings: list[Finding] = []
        for secret_type, preview in secret_hits:
            findings.append(Finding(
                title=f"Potential Secret in JavaScript: {secret_type}",
                severity=Severity.HIGH,
                description=f"Secret pattern {secret_type} detected: {preview}",
            ))

        if source_maps:
            findings.append(Finding(
                title="JavaScript Source Maps Exposed",
                severity=Severity.LOW,
                description=f"{len(source_maps)} source map reference(s) detected.",
            ))

        if firebase_hits:
            findings.append(Finding(
                title="Firebase Configuration Exposed in JavaScript",
                severity=Severity.MEDIUM,
                description=f"{len(firebase_hits)} Firebase URL(s) detected.",
            ))

        if websocket_urls:
            findings.append(Finding(
                title="WebSocket Endpoints in JavaScript",
                severity=Severity.INFO,
                description=f"{len(websocket_urls)} WebSocket endpoint(s) detected.",
            ))

        if api_hits:
            findings.append(Finding(
                title="Discovered API Endpoints in JavaScript",
                severity=Severity.INFO,
                description=f"{len(api_hits)} API endpoint(s) detected.",
            ))

        return ModuleResult(
            name=self.name,
            category=self.category,
            summary=description,
            findings=findings,
            data={
                "scripts_count": len(scripts),
                "api_hits": api_hits,
                "secret_hits": [{"type": t, "preview": p} for t, p in secret_hits],
                "source_maps": source_maps,
                "firebase_hits": firebase_hits,
                "websocket_urls": websocket_urls,
                "rows": rows,
                "score": self.score,
                "max_score": self.max_score,
            }
        )
