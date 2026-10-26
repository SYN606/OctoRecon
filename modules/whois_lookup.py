"""
WHOIS Scanner
Author : 0ct0pu3
VERSION : 1.0.0
"""

import asyncio
import ipaddress
import logging
from datetime import datetime, timezone
from urllib.parse import urlparse

from rich.table import Table

from core.base_module import BaseModule
from core.report_schema import Report

# Suppress noisy socket connection errors from python-whois on unsupported modern TLDs
logging.getLogger("whois").setLevel(logging.CRITICAL)
logging.getLogger("whois.whois").setLevel(logging.CRITICAL)

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
        "registrar",
        "registrar_url",
        "whois_server",
        "creation_date",
        "expiration_date",
        "updated_date",
        "name",
        "name_servers",
        "status",
        "dnssec",
        "registrant_country",
        "emails",
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
                    data={
                        "Status": "Unavailable",
                        "Error": "python-whois package not installed"
                    },
                    score=0,
                    max_score=max_score,
                    description="WHOIS lookup could not be performed.",
                ),
            )
            return

        hostname = urlparse(scanner.target).hostname

        if not hostname or self._is_ip_or_local(hostname):
            data = {
                "Status":
                "Skipped",
                "Reason":
                "Target is an IP address or localhost, not a registrable domain"
            }
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

        info_dict = {}

        try:
            info_obj = await asyncio.wait_for(
                asyncio.get_event_loop().run_in_executor(
                    None, whois.whois, domain),
                timeout=self.WHOIS_TIMEOUT,
            )
            # Check if info_obj actually returned valid data
            has_data = any(
                bool(getattr(info_obj, f, None))
                for f in ["registrar", "creation_date", "expiration_date", "name_servers"]
            )
            if has_data:
                for field in self.FIELDS:
                    info_dict[field] = getattr(info_obj, field, None)
        except Exception:
            info_dict = {}

        # Fallback to RDAP if whois returned empty data or failed
        if not info_dict:
            rdap_data = await self._query_rdap(scanner, domain)
            if rdap_data:
                info_dict = rdap_data

        if info_dict:
            for field in self.FIELDS:
                raw = info_dict.get(field)
                value = self._format_value(field, raw)
                data[field.replace("_", " ").title()] = value
                table.add_row(field.replace("_", " ").title(), value)

            expiry_val = info_dict.get("expiration_date")
            score, note = self._score_expiration(expiry_val, score, max_score)
            if note:
                data["Notice"] = note
                table.add_row("Notice", note)
        else:
            score = 0
            data = {"Error": f"Unable to retrieve WHOIS or RDAP records for {domain}"}
            table.add_row("Error", data["Error"])

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

    async def _query_rdap(self, scanner, domain: str) -> dict:
        """Query RDAP when traditional port-43 WHOIS fails or has no data."""
        try:
            url = f"https://rdap.org/domain/{domain}"
            resp = await scanner.client.get(url, follow_redirects=True, timeout=self.WHOIS_TIMEOUT)
            if resp.status_code != 200:
                return {}
            data = resp.json()
            rdap_info = {}
            # Registrar
            for ent in data.get("entities", []):
                roles = ent.get("roles", [])
                if "registrar" in roles:
                    vcard = ent.get("vcardArray", [])
                    if len(vcard) > 1 and isinstance(vcard[1], list):
                        for item in vcard[1]:
                            if isinstance(item, list) and len(item) > 3 and item[0] == "fn":
                                rdap_info["registrar"] = item[3]
                                break
                    if not rdap_info.get("registrar") and ent.get("handle"):
                        rdap_info["registrar"] = ent.get("handle")
            # Events / Dates
            for evt in data.get("events", []):
                action = evt.get("eventAction")
                dt_str = evt.get("eventDate")
                if dt_str:
                    try:
                        dt = datetime.fromisoformat(dt_str.replace("Z", "+00:00"))
                    except Exception:
                        dt = dt_str
                    if action == "registration":
                        rdap_info["creation_date"] = dt
                    elif action == "expiration":
                        rdap_info["expiration_date"] = dt
                    elif action in ("last changed", "last update of RDAP database"):
                        if "updated_date" not in rdap_info:
                            rdap_info["updated_date"] = dt
            # Nameservers
            ns_list = [ns.get("ldhName") for ns in data.get("nameservers", []) if ns.get("ldhName")]
            if ns_list:
                rdap_info["name_servers"] = ns_list
            # Status
            statuses = data.get("status", [])
            if statuses:
                rdap_info["status"] = statuses
            rdap_info["whois_server"] = "RDAP (rdap.org)"
            return rdap_info
        except Exception:
            return {}

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

    def _score_expiration(self, expiry, score, max_score):
        """Dock points if the domain is expiring soon or already expired."""
        if not isinstance(expiry, datetime):
            if isinstance(expiry, list) and expiry:
                expiry = expiry[0]
            elif isinstance(expiry, str):
                try:
                    expiry = datetime.fromisoformat(expiry.replace("Z", "+00:00"))
                except Exception:
                    expiry = None

        if not isinstance(expiry, datetime):
            return score, None

        now = datetime.now(expiry.tzinfo) if expiry.tzinfo else datetime.now()
        days_left = (expiry - now).days
        if days_left < 0:
            return 0, f"Domain expiration date has passed ({expiry.date()})"
        if days_left <= self.EXPIRY_WARN_DAYS:
            return max(score - 10,
                       0), f"Domain expires soon: {days_left} day(s) left"
        return score, None
