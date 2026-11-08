"""
Cookie Scanner
Author : 0ct0pu3 / SYN606
VERSION : 2.0.0
"""

from rich.table import Table
from http.cookies import SimpleCookie
from core.base_module import BaseModule
from core.schemas import ModuleResult

class CookieScanner(BaseModule):
    name = "Cookies"
    category = "Web"
    description = "Analyze HTTP cookies for security flags (Secure, HttpOnly, SameSite)."
    max_score = 10

    async def run(self, scanner) -> ModuleResult:
        result = ModuleResult(module_name=self.name, max_score=self.max_score)
        table = Table(title="Cookie Security Attributes")
        table.add_column("Cookie", style="cyan")
        table.add_column("Secure", style="green")
        table.add_column("HttpOnly", style="green")
        table.add_column("SameSite", style="yellow")
        table.add_column("Status")

        if not scanner.response:
            result.description = "No response available to inspect cookies."
            result.score = self.max_score
            return result

        # Extract raw Set-Cookie header strings
        raw_headers = []
        if hasattr(scanner.response.headers, "get_list"):
            raw_headers = scanner.response.headers.get_list("set-cookie")
        else:
            val = scanner.response.headers.get("set-cookie")
            if val:
                raw_headers = [val]

        if not raw_headers and scanner.response.cookies:
            # Fallback to response.cookies if set-cookie header wasn't preserved directly
            raw_headers = [f"{k}={v}" for k, v in scanner.response.cookies.items()]

        if not raw_headers:
            result.description = "No cookies returned by the application (Safe)."
            result.score = self.max_score
            result.data.append({
                "Cookie": "-",
                "Secure": "-",
                "HttpOnly": "-",
                "SameSite": "-",
                "Status": "No Cookies Set"
            })
            table.add_row("-", "-", "-", "-", "[green]No Cookies Set[/green]")
            scanner.console.print(table)
            return result

        score = self.max_score
        parsed_cookies = []

        for header_str in raw_headers:
            try:
                c = SimpleCookie()
                c.load(header_str)
                for name, morsel in c.items():
                    flags = {k.lower(): v for k, v in morsel.items() if v}
                    # Also check raw string for attributes SimpleCookie might miss in some python versions
                    header_lower = header_str.lower()
                    is_secure = "secure" in flags or "secure" in header_lower
                    is_httponly = "httponly" in flags or "httponly" in header_lower
                    samesite = "None"
                    if "samesite=strict" in header_lower:
                        samesite = "Strict"
                    elif "samesite=lax" in header_lower:
                        samesite = "Lax"
                    elif "samesite=none" in header_lower:
                        samesite = "None"
                    else:
                        samesite = "Missing"

                    issues = []
                    if not is_secure and scanner.target.startswith("https"):
                        issues.append("Missing Secure")
                        score = max(0, score - 2)
                    if not is_httponly:
                        issues.append("Missing HttpOnly")
                        score = max(0, score - 2)
                    if samesite in ("Missing", "None"):
                        issues.append(f"SameSite={samesite}")
                        score = max(0, score - 1)

                    status = "[red]" + ", ".join(issues) + "[/red]" if issues else "[green]Secure[/green]"
                    status_clean = ", ".join(issues) if issues else "Secure"

                    table.add_row(
                        name,
                        "[green]Yes[/green]" if is_secure else "[red]No[/red]",
                        "[green]Yes[/green]" if is_httponly else "[red]No[/red]",
                        samesite,
                        status
                    )

                    result.data.append({
                        "Cookie": name,
                        "Secure": "Yes" if is_secure else "No",
                        "HttpOnly": "Yes" if is_httponly else "No",
                        "SameSite": samesite,
                        "Status": status_clean
                    })
            except Exception:
                continue

        result.score = max(0, score)
        result.description = f"Analyzed {len(result.data)} cookie(s) for security hardening."
        scanner.console.print(table)
        return result
