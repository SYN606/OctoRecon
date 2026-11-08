"""
HTTP Methods Scanner
Author : 0ct0pu3 / SYN606
VERSION : 2.0.0
"""

import httpx
from rich.table import Table
from core.base_module import BaseModule
from core.schemas import ModuleResult, Finding, Severity

class MethodScanner(BaseModule):
    name = "HTTP Methods"
    slug = "http-method"
    aliases = [
        "httpmethod",
        "http-method",
        "http",
        "methods",
    ]
    category = "Web"
    description = "Identify supported HTTP methods and detect risky methods (TRACE, WebDAV)."
    max_score = 20

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

    DANGEROUS_WEIGHTS = {
        "TRACE": 8,
        "PUT": 5,
        "DELETE": 5,
        "CONNECT": 4,
    }

    async def run(self, scanner) -> ModuleResult:
        result = ModuleResult(module_name=self.name, max_score=self.max_score)
        table = Table(title="HTTP Methods")
        table.add_column("Method", style="cyan")
        table.add_column("Status")

        score = self.max_score
        methods = []
        request_failed = False

        try:
            response = await scanner.client.options(scanner.target, timeout=10)
        except httpx.TimeoutException:
            request_failed = True
            scanner.console.print("[yellow]HTTP Methods module: OPTIONS request timed out.[/yellow]")
        except httpx.RequestError as e:
            request_failed = True
            scanner.console.print(f"[yellow]HTTP Methods module: request failed ({e}).[/yellow]")
        else:
            allow = response.headers.get("Allow", "") if response else ""
            methods = [
                method.strip().upper() for method in allow.split(",")
                if method.strip()
            ]

        if request_failed:
            result.score = self.max_score
            result.description = "OPTIONS request failed or blocked by firewall; methods check skipped."
            result.findings.append(Finding(
                title="HTTP Methods Probe Blocked",
                severity=Severity.INFO,
                description="OPTIONS request timed out or was blocked by firewall; skipped without security penalty."
            ))
            return result

        no_allow_header = not methods

        for method in self.COMMON_METHODS:
            enabled = method in methods
            status = "Enabled" if enabled else "Disabled"

            if enabled and method in self.DANGEROUS_WEIGHTS:
                score -= self.DANGEROUS_WEIGHTS[method]
                if method == "TRACE":
                    status = "Enabled (XST risk)"
                    result.findings.append(Finding(
                        title="Cross-Site Tracing Enabled (TRACE)",
                        severity=Severity.HIGH,
                        description="HTTP TRACE is enabled on the server, exposing session tokens to Cross-Site Tracing (XST) attacks."
                    ))
                elif method in ("PUT", "DELETE"):
                    result.findings.append(Finding(
                        title=f"Insecure HTTP Method: {method}",
                        severity=Severity.MEDIUM,
                        description=f"HTTP {method} method is advertised as supported, which may allow unauthorized resource modification."
                    ))
                elif method == "CONNECT":
                    result.findings.append(Finding(
                        title="HTTP CONNECT Method Enabled",
                        severity=Severity.LOW,
                        description="HTTP CONNECT proxy tunneling method is enabled."
                    ))

            table.add_row(
                method,
                f"[green]{status}[/green]" if enabled and "risk" not in status
                else (f"[red]{status}[/red]" if enabled else f"[dim]{status}[/dim]"),
            )

            result.data.append({
                "Method": method,
                "Status": status,
            })

        extra_found = [m for m in methods if m not in self.COMMON_METHODS]
        for method in extra_found:
            is_watch = method in self.WATCH_METHODS
            status = "Enabled (WebDAV)" if is_watch else "Enabled (unlisted)"
            if is_watch:
                score -= 3
                result.findings.append(Finding(
                    title=f"WebDAV Method Enabled: {method}",
                    severity=Severity.LOW,
                    description=f"WebDAV method '{method}' is active on the server."
                ))

            table.add_row(method, f"[red]{status}[/red]")
            result.data.append({"Method": method, "Status": status})

        if not result.findings and methods:
            result.findings.append(Finding(
                title="HTTP Methods Hardened",
                severity=Severity.INFO,
                description=f"Supported methods ({', '.join(methods)}) adhere to standard safe operations."
            ))

        result.score = max(score, 0)
        scanner.console.print(table)

        if no_allow_header:
            scanner.console.print(
                "[#6b6b6b] No 'Allow' header returned by server — results may be incomplete.[/#6b6b6b]"
            )

        result.description = "Enumerates supported HTTP methods, flags TRACE (XST risk), and highlights unlisted/WebDAV methods."
        return result
