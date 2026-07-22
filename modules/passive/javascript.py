"""
JAVASCRIPT Module
Author : 0ct0pu3
VERSION : 1.0.0
"""
import re
from urllib.parse import urljoin

from bs4 import BeautifulSoup

from core.base_module import BaseModule
from core.report_schema import Report
from rich.table import Table

class Module(BaseModule):

    name = "javascript"
    category = "Passive"

    description = (
        "Discover external JavaScript resources."
    )

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

        try:

            response = await self.get(
                scanner,
                scanner.target,
            )

        except Exception as e:

            self.error(scanner, str(e))

            scanner.report.add_module(
                self.name,
                Report.text(
                    title="JavaScript Analysis",
                    content=f"Unable to fetch target.\n\n{e}",
                    score=0,
                    max_score=self.max_score,
                    description="Target page could not be downloaded.",
                ),
            )
            return

        soup = BeautifulSoup(
            response.text,
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

            js_files.append(
                urljoin(
                    scanner.target,
                    src,
                )
            )

        js_files = sorted(set(js_files))
        
        # ---------------------------------------
        # Analyze JavaScript Files
        # ---------------------------------------

        for js in js_files:

            try:

                r = await self.get(
                    scanner,
                    js,
                )

            except Exception:

                continue

            text = r.text
            
            # ---------------------------------------
            # Source Maps
            # ---------------------------------------

            if js.endswith(".map"):
                source_maps.append(js)

            if "sourceMappingURL=" in text:
                source_maps.append(js)

            if js.endswith(".min.js") and "sourceMappingURL=" in text:
                source_maps.append(js)

            if js.endswith(".bundle.js") and "sourceMappingURL=" in text:
                source_maps.append(js)

            # ---------------------------------------
            # WebSocket URLs
            # ---------------------------------------

            websocket_urls.extend(
                re.findall(
                    r"wss?://[^\s\"']+",
                    text,
                )
            )

            # ---------------------------------------
            # Firebase References
            # ---------------------------------------

            firebase_keywords = [
                "firebase",
                "firebaseapp.com",
                "firebaseio.com",
                "firestore",
                "googleapis.com",
            ]

            lower = text.lower()

            for keyword in firebase_keywords:

                if keyword in lower:
                    firebase_hits.append(js)
                    break

            # ---------------------------------------
            # API Endpoints
            # ---------------------------------------

            for pattern in self.API_PATTERNS:

                try:

                    matches = re.findall(
                        pattern,
                        text,
                    )

                    if matches:
                        api_hits.extend(matches)

                except Exception:
                    continue

            # ---------------------------------------
            # Secrets Detection
            # ---------------------------------------

            for name, pattern in self.SECRET_PATTERNS.items():

                try:

                    matches = re.findall(
                        pattern,
                        text,
                    )

                    for secret in matches:

                        secret_hits.append(
                            (
                                name,
                                secret[:50],
                            )
                        )

                except Exception:
                    continue

            # ---------------------------------------
            # Interesting URLs
            # ---------------------------------------

            interesting_patterns = [
                r"https?://[^\s\"'<>]+",
                r"/admin[^\s\"']*",
                r"/api/[^\s\"']*",
                r"/uploads/[^\s\"']*",
                r"/backup[^\s\"']*",
                r"/private[^\s\"']*",
                r"/internal[^\s\"']*",
                r"/graphql[^\s\"']*",
            ]

            interesting_urls = []

            for pattern in interesting_patterns:

                try:

                    interesting_urls.extend(
                        re.findall(
                            pattern,
                            text,
                        )
                    )

                except Exception:
                    continue

            interesting_urls = sorted(set(interesting_urls))

            # ---------------------------------------
            # Email Addresses
            # ---------------------------------------

            emails = sorted(
                set(
                    re.findall(
                        r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}",
                        text,
                    )
                )
            )

            # ---------------------------------------
            # IPv4 Addresses
            # ---------------------------------------

            ips = sorted(
                set(
                    re.findall(
                        r"(?:\d{1,3}\.){3}\d{1,3}",
                        text,
                    )
                )
            )

            # ---------------------------------------
            # Admin / Sensitive Keywords
            # ---------------------------------------

            admin_keywords = [
                "admin",
                "administrator",
                "root",
                "password",
                "passwd",
                "token",
                "secret",
                "apikey",
                "api_key",
                "accesskey",
                "privatekey",
                "jwt",
                "bearer",
                "authorization",
            ]

            keyword_hits = []

            lower = text.lower()

            for keyword in admin_keywords:

                if keyword in lower:
                    keyword_hits.append(keyword)

            # ---------------------------------------
            # Score Calculation
            # ---------------------------------------

            if source_maps:
                self.deduct(2)

            if firebase_hits:
                self.deduct(2)

            if websocket_urls:
                self.deduct(1)

            if api_hits:
                self.deduct(min(len(api_hits), 3))

            if keyword_hits:
                self.deduct(min(len(keyword_hits), 3))

            if secret_hits:
                self.deduct(10)

            # ---------------------------------------
            # Report Row
            # ---------------------------------------

            rows.append(
                {
                    "JavaScript": js,
                    "APIs": len(set(api_hits)),
                    "Secrets": len(secret_hits),
                    "Emails": len(emails),
                    "IPs": len(ips),
                    "Source Maps": (
                        "Yes"
                        if js in source_maps
                        else "No"
                    ),
                    "Firebase": (
                        "Yes"
                        if js in firebase_hits
                        else "No"
                    ),
                    "WebSocket": (
                        "Yes"
                        if websocket_urls
                        else "No"
                    ),
                }
            )

        # ---------------------------------------
        # Cleanup
        # ---------------------------------------

        js_files = sorted(set(js_files))
        api_hits = sorted(set(api_hits))
        source_maps = sorted(set(source_maps))
        websocket_urls = sorted(set(websocket_urls))
        firebase_hits = sorted(set(firebase_hits))

        secret_hits = list(
            dict.fromkeys(secret_hits)
        )

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

            email_count = len(
                {
                    row["Emails"]
                    for row in rows
                }
            )

            ip_count = len(
                {
                    row["IPs"]
                    for row in rows
                }
            )

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

            scanner.report.add_module(
                self.name,
                Report.text(
                    title="JavaScript Analysis",
                    content="No JavaScript files were detected.",
                    score=self.max_score,
                    max_score=self.max_score,
                    description="No external JavaScript resources were found.",
                ),
            )

            return
        
        # ---------------------------------------
        # JavaScript Intelligence Report
        # ---------------------------------------

        scanner.report.add_module(
            self.name,
            Report.table(
                title="JavaScript Intelligence",
                columns=[
                    "JavaScript",
                    "APIs",
                    "Secrets",
                    "Emails",
                    "IPs",
                    "Source Maps",
                    "Firebase",
                    "WebSocket",
                ],
                rows=rows,
                score=self.score,
                max_score=self.max_score,
                description=description,
            ),
        )

        # ---------------------------------------
        # API Endpoints
        # ---------------------------------------

        if api_hits:

            scanner.report.add_module(
                "javascript_endpoints",
                Report.list(
                    title="Discovered API Endpoints",
                    items=api_hits,
                    score=0,
                    max_score=0,
                    description=f"{len(api_hits)} endpoint(s) discovered.",
                ),
            )

        # ---------------------------------------
        # Potential Secrets
        # ---------------------------------------

        if secret_hits:

            scanner.report.add_module(
                "javascript_secrets",
                Report.table(
                    title="Potential Secrets",
                    columns=[
                        "Type",
                        "Preview",
                    ],
                    rows=[
                        {
                            "Type": secret_type,
                            "Preview": preview,
                        }
                        for secret_type, preview in secret_hits
                    ],
                    score=0,
                    max_score=0,
                    description="Potential secrets detected inside JavaScript resources.",
                ),
            )

        # ---------------------------------------
        # Source Maps
        # ---------------------------------------

        if source_maps:

            scanner.report.add_module(
                "javascript_sourcemaps",
                Report.list(
                    title="Source Maps",
                    items=source_maps,
                    score=0,
                    max_score=0,
                    description=f"{len(source_maps)} source map reference(s) detected.",
                ),
            )

        # ---------------------------------------
        # Firebase References
        # ---------------------------------------

        if firebase_hits:

            scanner.report.add_module(
                "javascript_firebase",
                Report.list(
                    title="Firebase References",
                    items=firebase_hits,
                    score=0,
                    max_score=0,
                    description=f"{len(firebase_hits)} Firebase reference(s) detected.",
                ),
            )

        # ---------------------------------------
        # WebSocket URLs
        # ---------------------------------------

        if websocket_urls:

            scanner.report.add_module(
                "javascript_websocket",
                Report.list(
                    title="WebSocket URLs",
                    items=websocket_urls,
                    score=0,
                    max_score=0,
                    description=f"{len(websocket_urls)} WebSocket endpoint(s) detected.",
                ),
            )