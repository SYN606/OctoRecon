"""
SECURITY CSP Module
Author : 0ct0pu3
VERSION : 1.0.0
"""
from rich.table import Table

from core.base_module import BaseModule
from core.report_schema import Report


class Module(BaseModule):

    name = "Content Security Policy"
    slug = "csp"
    aliases = [
        "content-security-policy",
    ]
    category = "Security"
    description = "Analyze Content-Security-Policy headers."

    REQUIRED_DIRECTIVES = [
        "default-src",
        "script-src",
        "object-src",
        "base-uri",
        "frame-ancestors",
    ]

    ALWAYS_DANGEROUS = [
        "'unsafe-inline'",
        "'unsafe-eval'",
    ]

    CONTEXT_SENSITIVE_DIRECTIVES = ("script-src", "object-src", "default-src")

    MAX_VALUE_DISPLAY_LEN = 120

    async def run(self, scanner):

        self.reset_score()

        try:
            response = await self.get(scanner, scanner.target)
        except Exception as e:
            scanner.report.add_module(
                self.name,
                Report.text(
                    title="Content Security Policy",
                    content=str(e),
                    score=0,
                    max_score=self.max_score,
                    description="Unable to retrieve target.",
                ),
            )
            return

        csp_headers = response.headers.get_list("Content-Security-Policy") \
            if hasattr(response.headers, "get_list") \
            else [response.headers.get("Content-Security-Policy")]

        csp_headers = [h for h in csp_headers if h]
        csp = "; ".join(csp_headers) if csp_headers else None

        report_only = response.headers.get("Content-Security-Policy-Report-Only")

        if not csp:
            table = Table(title="Content Security Policy")
            table.add_column("Property")
            table.add_column("Value")

            table.add_row("Status", "Not Found")
            if report_only:
                table.add_row("Mode", "Report Only")
                table.add_row(
                    "Note",
                    "Policy is monitored via Report-Only, not enforced.",
                )

            scanner.console.print(table)

            content = "Content-Security-Policy header not present."
            if report_only:
                content += (
                    " A Content-Security-Policy-Report-Only header was found "
                    "instead — it reports violations but does not enforce them."
                )

            scanner.report.add_module(
                self.name,
                Report.text(
                    title="Content Security Policy",
                    content=content,
                    score=0,
                    max_score=self.max_score,
                    description="No CSP header detected.",
                ),
            )
            return

        # directive -> set of values (deduplicated, merged across repeated
        # directives / multiple combined headers)
        directives = {}
        rows = []

        # ----------------------------------
        # Parse CSP Directives
        # ----------------------------------

        for item in csp.split(";"):
            item = item.strip()
            if not item:
                continue

            parts = item.split()
            name = parts[0].lower()
            values = parts[1:]

            directives.setdefault(name, set())
            directives[name].update(values)

        # ----------------------------------
        # Required Directives
        # ----------------------------------

        missing = []

        for directive in self.REQUIRED_DIRECTIVES:
            if directive not in directives:
                missing.append(directive)

        # ----------------------------------
        # Dangerous Values (deduplicated)
        # ----------------------------------

        security_findings = set()

        for directive, values in directives.items():

            for dangerous in self.ALWAYS_DANGEROUS:
                if dangerous in values:
                    security_findings.add(f"{directive}: {dangerous}")

            if directive in self.CONTEXT_SENSITIVE_DIRECTIVES:
                if "*" in values:
                    security_findings.add(f"{directive}: wildcard source '*'")
                if "data:" in values:
                    security_findings.add(f"{directive}: allows 'data:' URIs")

        findings = sorted(security_findings)

        # Apply one deduction per unique finding + one per missing directive,
        # instead of stacking deductions per raw occurrence.
        for _ in findings:
            self.deduct(2)
        for _ in missing:
            self.deduct(2)

        final_score = max(min(self.score, self.max_score), 0)

        # ----------------------------------
        # Build Report Rows
        # ----------------------------------

        for directive, values in sorted(directives.items()):
            value_str = " ".join(sorted(values)) if values else "(no value)"
            if len(value_str) > self.MAX_VALUE_DISPLAY_LEN:
                value_str = value_str[: self.MAX_VALUE_DISPLAY_LEN] + "..."

            rows.append(
                {
                    "Directive": directive,
                    "Values": value_str,
                    "Status": "OK",
                }
            )

        for directive in missing:
            rows.append(
                {
                    "Directive": directive,
                    "Values": "-",
                    "Status": "Missing",
                }
            )

        for finding in findings:
            rows.append(
                {
                    "Directive": "Security Finding",
                    "Values": finding,
                    "Status": "Warning",
                }
            )

        # ----------------------------------
        # Build Description
        # ----------------------------------

        description = (
            f"{len(directives)} directive(s), "
            f"{len(findings)} warning(s), "
            f"{len(missing)} missing directive(s)."
        )

        # ----------------------------------
        # Severity Tiering
        # ----------------------------------

        critical_markers = {"'unsafe-inline'", "'unsafe-eval'"}
        has_critical = any(
            any(marker in f for marker in critical_markers) for f in findings
        )

        if has_critical:
            status = "Critical"
        elif findings:
            status = "Warning"
        elif missing:
            status = "Moderate"
        else:
            status = "Secure"

        # ----------------------------------
        # Console Summary
        # ----------------------------------

        table = Table(title="Content Security Policy")
        table.add_column("Property", style="cyan")
        table.add_column("Value", style="green")

        table.add_row("Status", status)
        if report_only:
            table.add_row("Mode", "Report Only")
        table.add_row("Directives", str(len(directives)))
        table.add_row("Warnings", str(len(findings)))
        table.add_row("Missing", str(len(missing)))
        if len(csp_headers) > 1:
            table.add_row("Note", f"{len(csp_headers)} CSP headers combined")

        scanner.console.print(table)

        # ----------------------------------
        # Report
        # ----------------------------------

        scanner.report.add_module(
            self.name,
            Report.table(
                title="Content Security Policy Analysis",
                columns=[
                    "Directive",
                    "Values",
                    "Status",
                ],
                rows=rows,
                score=final_score,
                max_score=self.max_score,
                description=description,
            ),
        )

        # ----------------------------------
        # Findings Summary
        # ----------------------------------

        if findings:
            scanner.report.add_module(
                "csp_findings",
                Report.list(
                    title="CSP Security Findings",
                    items=findings,
                    score=0,
                    max_score=0,
                    description=f"{len(findings)} potentially insecure CSP configuration(s) detected.",
                ),
            )

        # ----------------------------------
        # Missing Directives Summary
        # ----------------------------------

        if missing:
            scanner.report.add_module(
                "csp_missing",
                Report.list(
                    title="Missing Recommended Directives",
                    items=missing,
                    score=0,
                    max_score=0,
                    description="Recommended CSP directives that are not configured.",
                ),
            )