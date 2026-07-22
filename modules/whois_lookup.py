"""
WHOIS Scanner
Author : 0ct0pu3
VERSION : 1.0.0
"""

import asyncio
import ipaddress
from datetime import datetime
from urllib.parse import urlparse

from rich.table import Table

from core.base_module import BaseModule
from core.report_schema import Report

try:
    import whois
    WHOIS_AVAILABLE = True
except ImportError:
    WHOIS_AVAILABLE = False

try:
    import tldextract
    TLDEXTRACT_AVAILABLE = True
except ImportError:
    TLDEXTRACT_AVAILABLE = False

REGISTRAR_ALIASES = {
    "godaddy.com llc": "GoDaddy",
    "godaddy.com, llc": "GoDaddy",
    "namecheap, inc.": "Namecheap",
    "cloudflare, inc.": "Cloudflare",
    "google llc": "Google Domains",
}


class Module(BaseModule):
    name = "WHOIS"
    category = "Core"
    description = "Collect domain registration and WHOIS information."

    WHOIS_TIMEOUT = 10  # seconds
    EXPIRY_WARN_DAYS = 30

    FIELDS = [
        "registrar", "registrar_url", "whois_server",
        "creation_date", "expiration_date", "updated_date",
        "name", "name_servers", "status", "dnssec",
        "registrant_country", "emails",
    ]

    async def run(self, scanner):
        table = Table(title="WHOIS")
        table.add_column("Field", style="cyan")
        table.add_column("Value")

        data = {}
        score = 15
        max_score = 15

        if not WHOIS_AVAILABLE:
            table.add_row("Status", "python-whois package not installed")
            scanner.console.print(table)
            scanner.report.add_module(
                self.name,
                Report.keyvalue(
                    title="WHOIS",
                    data={"Status": "Unavailable", "Error": "python-whois package not installed"},
                    score=0,
                    max_score=max_score,
                    description="WHOIS lookup could not be performed.",
                ),
            )
            return

        hostname = urlparse(scanner.target).hostname

        if not hostname or self._is_ip_or_local(hostname):
            data = {"Status": "Skipped", "Reason": "Target is an IP address or localhost, not a registrable domain"}
            table.add_row("Status", "Skipped")
            table.add_row("Reason", data["Reason"])
            scanner.console.print(table)
            scanner.report.add_module(
                self.name,
                Report.keyvalue(
                    title="WHOIS Information",
                    data=data,
                    score=max_score,
                    max_score=max_score,
                    description="WHOIS lookup skipped for IP/localhost target.",
                ),
            )
            return

        domain = hostname
        if TLDEXTRACT_AVAILABLE:
            ext = tldextract.extract(hostname)
            if ext.registered_domain:
                domain = ext.registered_domain

        try:
            info = await asyncio.wait_for(
                asyncio.get_event_loop().run_in_executor(None, whois.whois, domain),
                timeout=self.WHOIS_TIMEOUT,
            )

            for field in self.FIELDS:
                raw = getattr(info, field, "-")
                value = self._format_value(field, raw)
                data[field.replace("_", " ").title()] = value
                table.add_row(field.replace("_", " ").title(), value)

            score, note = self._score_expiration(info, score, max_score)
            if note:
                data["Notice"] = note
                table.add_row("Notice", note)

        except asyncio.TimeoutError:
            score = 0
            data = {"Error": f"WHOIS lookup timed out after {self.WHOIS_TIMEOUT}s"}
            table.add_row("Error", data["Error"])

        except Exception as e:
            score = 0
            data = {"Error": str(e)}
            table.add_row("Error", str(e))

        scanner.console.print(table)
        scanner.report.add_module(
            self.name,
            Report.keyvalue(
                title="WHOIS Information",
                data=data,
                score=score,
                max_score=max_score,
                description="Domain registration and ownership information.",
            ),
        )

    def _is_ip_or_local(self, hostname):
        if hostname == "localhost":
            return True
        try:
            ipaddress.ip_address(hostname)
            return True
        except ValueError:
            return False

    def _format_value(self, field, value):
        if value is None:
            return "-"

        if isinstance(value, list):
            seen = []
            for v in value:
                formatted = self._format_scalar(field, v)
                if formatted not in seen:
                    seen.append(formatted)
            return ", ".join(seen) if seen else "-"

        return self._format_scalar(field, value)

    def _format_scalar(self, field, value):
        if isinstance(value, datetime):
            return value.strftime("%Y-%m-%d")

        text = str(value).strip()

        if field == "registrar" and text:
            normalized = REGISTRAR_ALIASES.get(text.lower())
            if normalized:
                return normalized

        return text if text else "-"

    def _score_expiration(self, info, score, max_score):
        """Dock points if the domain is expiring soon or already expired."""
        expiry = getattr(info, "expiration_date", None)
        if isinstance(expiry, list):
            expiry = expiry[0] if expiry else None
        if not isinstance(expiry, datetime):
            return score, None

        days_left = (expiry - datetime.now()).days
        if days_left < 0:
            return 0, f"Domain expiration date has passed ({expiry.date()})"
        if days_left <= self.EXPIRY_WARN_DAYS:
            return max(score - 10, 0), f"Domain expires soon: {days_left} day(s) left"
        return score, None