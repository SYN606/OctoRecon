"""
Security Header Scanner
Author : 0ct0pu3
VERSION : 1.0.0
"""

from rich.markup import escape
from rich.table import Table
from config import SECURITY_HEADERS
from core.base_module import BaseModule
from core.schemas import ModuleResult

# Headers that leak information about the tech stack — being present
# is a (minor) negative, not neutral.
INFO_DISCLOSURE_HEADERS = {
    "Server": 2,
    "X-Powered-By": 2,
    "X-AspNet-Version": 2,
    "X-AspNetMvc-Version": 2,
}


def _validate_header_value(header: str, value: str) -> tuple[bool, str]:
    """
    Best-effort check that a present header is actually configured
    sensibly, not just present. Returns (is_ok, note).
    """
    header_lower = header.lower()
    value_lower = value.lower()

    if header_lower == "x-frame-options":
        if value_lower not in ("deny", "sameorigin"):
            return False, "weak/invalid value"

    elif header_lower == "x-content-type-options":
        if value_lower != "nosniff":
            return False, "invalid value"

    elif header_lower == "strict-transport-security":
        if "max-age=0" in value_lower:
            return False, "HSTS disabled (max-age=0)"
        if "max-age" not in value_lower:
            return False, "missing max-age"

    elif header_lower == "content-security-policy":
        if "unsafe-inline" in value_lower or "unsafe-eval" in value_lower:
            return False, "contains unsafe-inline/unsafe-eval"
        if "*" in value_lower:
            return False, "overly permissive (wildcard source)"

    elif header_lower == "referrer-policy":
        weak_values = ("unsafe-url", "no-referrer-when-downgrade")
        if value_lower in weak_values:
            return False, "weak policy"

    return True, ""


class HeaderScanner(BaseModule):

    name = "Headers"

    category = "Core"

    description = ("Analyze HTTP response headers and security headers.")

    async def run(self, scanner) -> ModuleResult:
        result = ModuleResult(module_name=self.name, max_score=sum(SECURITY_HEADERS.values()))

        if scanner.response is None:
            scanner.console.print("[red]Headers module: no response available, skipping.[/red]")
            result.description = "Checks for recommended HTTP security headers. Skipped: no response."
            result.score = 0
            return result

        # Case-insensitive lookup regardless of underlying header container
        headers = {k.lower(): v for k, v in scanner.response.headers.items()}

        table = Table(title="Security Headers")
        table.add_column("Header", style="cyan")
        table.add_column("Status")
        table.add_column("Value", overflow="fold", max_width=60)

        score = 0
        max_score = sum(SECURITY_HEADERS.values())

        for header, points in SECURITY_HEADERS.items():
            raw_value = headers.get(header.lower())
            present = raw_value is not None

            if present:
                is_ok, note = _validate_header_value(header, raw_value)
                if is_ok:
                    score += points
                    status = "Present"
                    status_display = f"[green]{status}[/green]"
                else:
                    score += round(points * 0.3)
                    status = f"Misconfigured ({note})"
                    status_display = f"[yellow]{status}[/yellow]"
            else:
                status = "Missing"
                status_display = f"[red]{status}[/red]"

            value_display = escape(raw_value) if raw_value else "-"
            table.add_row(header, status_display, value_display)

            result.data.append({
                "Header": header,
                "Status": status,
                "Value": raw_value if raw_value else "-",
            })

        score = min(score, max_score)

        disclosure_penalty = 0
        for header, penalty in INFO_DISCLOSURE_HEADERS.items():
            raw_value = headers.get(header.lower())
            if raw_value is not None:
                disclosure_penalty += penalty
                table.add_row(
                    header,
                    "[red]Disclosed[/red]",
                    escape(raw_value),
                )
                result.data.append({
                    "Header": header,
                    "Status": "Disclosed",
                    "Value": raw_value,
                })

        score = max(score - disclosure_penalty, 0)
        scanner.console.print(table)

        result.score = score
        result.description = "Checks for recommended HTTP security headers, validates values, and flags info-disclosure headers (Server, X-Powered-By)."
        return result
