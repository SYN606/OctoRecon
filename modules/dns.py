"""
DNS Scanner
Author : 0ct0pu3
VERSION : 1.0.0
"""

from urllib.parse import urlparse

import dns.asyncresolver
import dns.resolver
from rich.table import Table

from core.base_module import BaseModule
from core.report_schema import Report


class DNSScanner(BaseModule):

    name = "DNS"

    category = "Core"

    description = (
        "Retrieve DNS records and DNS configuration."
    )

    # How many points a "found" record type is worth
    RECORD_TYPES = ["A", "AAAA", "MX", "NS", "TXT", "SOA", "CNAME", "CAA"]

    async def run(self, scanner):

        domain = urlparse(scanner.target).hostname

        if not domain:
            scanner.console.print(
                "[red]DNS module: could not extract hostname from target, skipping.[/red]"
            )
            scanner.report.add_module(
                self.name,
                Report.table(
                    title="DNS Records",
                    columns=["Record Type", "Values"],
                    rows=[],
                    score=0,
                    max_score=30,
                    description="DNS record enumeration for the target domain. "
                                 "Skipped: invalid hostname.",
                ),
            )
            return

        resolver = dns.asyncresolver.Resolver()
        resolver.timeout = 3
        resolver.lifetime = 5

        table = Table(title="DNS Records")
        table.add_column("Record Type", style="cyan")
        table.add_column("Values")

        rows = []
        raw_records = {}  # record_type -> list[str] values, for scoring logic below

        score = 0
        max_score = 30  # base records (5x5=25) + CAA bonus(5) reserved below; see comments

        for record in self.RECORD_TYPES:

            values = []
            status_note = None

            try:
                answers = await resolver.resolve(domain, record)
                for item in answers:
                    values.append(str(item))

            except dns.resolver.NXDOMAIN:
                status_note = "[yellow]Domain does not exist[/yellow]"
            except dns.resolver.NoAnswer:
                status_note = "-"
            except dns.resolver.LifetimeTimeout:
                status_note = "[red]Timeout[/red]"
            except dns.resolver.NoNameservers:
                status_note = "[red]No nameservers responded[/red]"
            except Exception as e:
                status_note = f"[red]Error: {e}[/red]"

            raw_records[record] = values

            display_value = "\n".join(values) if values else (status_note or "-")

            table.add_row(record, display_value)

            rows.append(
                {
                    "Record Type": record,
                    "Values": ", ".join(values) if values else (status_note or "-"),
                }
            )

        # --- Scoring ---
        # Core records: A/AAAA/MX/NS/TXT/SOA/CNAME presence -> up to 3.5 pts each (25 total)
        core_records = ["A", "AAAA", "MX", "NS", "TXT", "SOA", "CNAME"]
        for record in core_records:
            if raw_records.get(record):
                score += round(25 / len(core_records))

        # CAA presence is a genuine security control -> bonus
        if raw_records.get("CAA"):
            score += 5

        score = min(score, max_score)

        # --- SPF / DMARC check (informational, added as extra rows) ---
        txt_values = raw_records.get("TXT", [])
        spf_found = any("v=spf1" in v.lower() for v in txt_values)

        dmarc_values = []
        try:
            dmarc_answers = await resolver.resolve(f"_dmarc.{domain}", "TXT")
            dmarc_values = [str(item) for item in dmarc_answers]
        except Exception:
            pass

        dmarc_found = any("v=dmarc1" in v.lower() for v in dmarc_values)

        spf_status = "[green]Found[/green]" if spf_found else "[red]Missing[/red]"
        dmarc_status = "[green]Found[/green]" if dmarc_found else "[red]Missing[/red]"

        table.add_row("SPF", spf_status)
        table.add_row("DMARC", dmarc_status)

        rows.append({"Record Type": "SPF", "Values": "Found" if spf_found else "Missing"})
        rows.append({"Record Type": "DMARC", "Values": "Found" if dmarc_found else "Missing"})

        scanner.console.print(table)

        scanner.report.add_module(
            self.name,
            Report.table(
                title="DNS Records",
                columns=[
                    "Record Type",
                    "Values",
                ],
                rows=rows,
                score=score,
                max_score=max_score,
                description="DNS record enumeration for the target domain, "
                            "including SPF/DMARC and CAA checks.",
            ),
        )