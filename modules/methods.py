"""
HTTP Methods Scanner
Author : 0ct0pu3
VERSION : 1.0.0
"""

import httpx
from rich.table import Table

from core.base_module import BaseModule
from core.report_schema import Report


class MethodScanner(BaseModule):

    name = "HTTP Methods"
    slug = "http-method"
    aliases = [
        "httpmethod",
        "http-method",
        "http",
    ]
    category = "Web"
    description = ("Identify supported HTTP methods.")

    COMMON_METHODS = [
        "GET",
        "POST",
        "HEAD",
        "OPTIONS",
        "PUT",
        "PATCH",
        "DELETE",
        "TRACE",
        "CONNECT",
    ]

    # WebDAV / less-common methods that indicate extra attack surface
    # if they show up unexpectedly.
    WATCH_METHODS = [
        "PROPFIND",
        "PROPPATCH",
        "MKCOL",
        "COPY",
        "MOVE",
        "LOCK",
        "UNLOCK",
        "SEARCH",
    ]

    # Weighted penalty per dangerous method (out of max_score=20)
    DANGEROUS_WEIGHTS = {
        "TRACE": 8,  # Cross-Site Tracing (XST) risk
        "PUT": 5,  # arbitrary file write
        "DELETE": 5,  # arbitrary file delete
        "CONNECT": 4,
    }

    async def run(self, scanner):

        table = Table(title="HTTP Methods")
        table.add_column("Method", style="cyan")
        table.add_column("Status")

        rows = []
        score = 20
        max_score = 20

        methods = []
        request_failed = False

        try:
            response = await scanner.client.options(scanner.target, timeout=10)
        except httpx.TimeoutException:
            request_failed = True
            scanner.console.print(
                "[yellow]HTTP Methods module: OPTIONS request timed out.[/yellow]"
            )
        except httpx.RequestError as e:
            request_failed = True
            scanner.console.print(
                f"[yellow]HTTP Methods module: request failed ({e}).[/yellow]")
        else:
            allow = response.headers.get("Allow", "") if response else ""
            methods = [
                method.strip().upper() for method in allow.split(",")
                if method.strip()
            ]

        if request_failed:
            scanner.report.add_module(
                self.name,
                Report.table(
                    title="HTTP Methods",
                    columns=["Method", "Status"],
                    rows=[],
                    score=0,
                    max_score=max_score,
                    description="Enumerates supported HTTP methods. "
                    "Skipped: OPTIONS request failed.",
                ),
            )
            return

        no_allow_header = not methods

        for method in self.COMMON_METHODS:

            enabled = method in methods
            status = "Enabled" if enabled else "Disabled"

            if enabled and method in self.DANGEROUS_WEIGHTS:
                score -= self.DANGEROUS_WEIGHTS[method]
                if method == "TRACE":
                    status = "Enabled (XST risk)"

            table.add_row(
                method,
                f"[green]{status}[/green]" if enabled and "risk" not in status
                else (f"[red]{status}[/red]"
                      if enabled else f"[dim]{status}[/dim]"),
            )

            rows.append({
                "Method": method,
                "Status": status,
            })

        # --- Unlisted / WebDAV methods that showed up in Allow header ---
        extra_found = [m for m in methods if m not in self.COMMON_METHODS]

        for method in extra_found:
            is_watch = method in self.WATCH_METHODS
            status = "Enabled (WebDAV)" if is_watch else "Enabled (unlisted)"

            if is_watch:
                score -= 3  # WebDAV methods add meaningful attack surface

            table.add_row(method, f"[red]{status}[/red]")
            rows.append({"Method": method, "Status": status})

        score = max(score, 0)

        scanner.console.print(table)

        if no_allow_header:
            scanner.console.print(
                "[#6b6b6b] No 'Allow' header returned by server — results may be incomplete.[/#6b6b6b]"
            )

        scanner.report.add_module(
            self.name,
            Report.table(
                title="HTTP Methods",
                columns=[
                    "Method",
                    "Status",
                ],
                rows=rows,
                score=score,
                max_score=max_score,
                description=
                "Enumerates supported HTTP methods, flags TRACE (XST risk), "
                "and highlights unlisted/WebDAV methods found in the Allow header.",
            ),
        )
