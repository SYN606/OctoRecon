"""
Advanced DNS Intelligence & Infrastructure Reconnaissance Module
Inspired by DNSDumpster & Modern Security Standards
Author: SYN606 / 0ct0pu3
Version: 2.0.0
"""

import asyncio
import socket
from urllib.parse import urlparse
from typing import Any, Dict, List, Optional, Set, Tuple

import dns.asyncresolver
import dns.resolver
import dns.reversename
from rich.table import Table

from core.base_module import BaseModule
from core.schemas import ModuleResult

DANGLING_CNAME_TARGETS = [
    "github.io",
    "herokudns.com",
    "herokuapp.com",
    "s3.amazonaws.com",
    "s3-website",
    "azurewebsites.net",
    "trafficmanager.net",
    "cloudapp.net",
    "surge.sh",
    "bitbucket.io",
    "zendesk.com",
    "pantheonsite.io",
    "fastly.net",
    "ghost.io",
    "myshopify.com",
    "readme.io",
    "wordpress.com",
    "tumblr.com",
    "unbouncepages.com",
]

class DNSScanner(BaseModule):
    name = "DNS"
    category = "Core"
    description = "Advanced DNS record enumeration, reverse DNS (PTR), security policy analysis, and infrastructure mapping."
    max_score = 30

    RECORD_TYPES = [
        "A", "AAAA", "MX", "NS", "TXT", "SOA", "CNAME", 
        "CAA", "SRV", "PTR", "DS", "DNSKEY", "TLSA"
    ]

    def __init__(self):
        super().__init__()
        self.resolver = dns.asyncresolver.Resolver()
        # Use reliable public resolvers to avoid local interface DNS timeouts
        self.resolver.nameservers = ["1.1.1.1", "8.8.8.8", "9.9.9.9"]
        self.resolver.timeout = 2.0
        self.resolver.lifetime = 4.0

    async def _resolve_record(self, domain: str, rtype: str) -> Tuple[List[str], Optional[str]]:
        """Safely queries a specific DNS record type with graceful error handling."""
        try:
            answers = await self.resolver.resolve(domain, rtype)
            return [str(r).strip() for r in answers], None
        except dns.resolver.NXDOMAIN:
            return [], "NXDOMAIN (Non-Existent Domain)"
        except dns.resolver.NoAnswer:
            return [], "-"
        except dns.resolver.LifetimeTimeout:
            return [], "Timeout"
        except dns.resolver.NoNameservers:
            return [], "No Nameservers Responded"
        except Exception as e:
            return [], f"Error: {e}"

    async def _resolve_ptr(self, ip: str) -> Optional[str]:
        """Performs asynchronous reverse DNS lookup on an IPv4 or IPv6 address."""
        try:
            rev_name = dns.reversename.from_address(ip)
            answers = await self.resolver.resolve(rev_name, "PTR")
            if answers:
                return str(answers[0]).rstrip(".")
        except Exception:
            pass
        return None

    async def _resolve_host_ips(self, hostname: str) -> List[str]:
        """Resolves IPv4 addresses for a given host."""
        clean_host = hostname.rstrip(".")
        try:
            answers = await self.resolver.resolve(clean_host, "A")
            return [str(r).strip() for r in answers]
        except Exception:
            return []

    async def run(self, scanner) -> ModuleResult:
        result = ModuleResult(module_name=self.name, max_score=self.max_score)
        
        parsed = urlparse(scanner.target)
        domain = parsed.hostname
        if not domain:
            result.description = "Could not extract valid hostname from target."
            result.score = 0
            return result

        domain = domain.lower().strip(".")
        if domain.startswith("www."):
            root_domain = domain[4:]
        else:
            root_domain = domain

        # Initialize Graph Structure if not already present on scanner.report
        if not hasattr(scanner.report, "infrastructure_graph") or not isinstance(scanner.report.infrastructure_graph, dict):
            scanner.report.infrastructure_graph = {"nodes": [], "edges": []}
            
        graph = scanner.report.infrastructure_graph
        graph.setdefault("nodes", [])
        graph.setdefault("edges", [])

        existing_node_ids = {n["id"] for n in graph["nodes"]}
        existing_edge_keys = {f"{e['source']}->{e['target']}:{e.get('relation','')}" for e in graph["edges"]}

        def add_node(node_id: str, label: str, ntype: str, metadata: dict = None):
            if node_id not in existing_node_ids:
                node = {"id": node_id, "label": label, "type": ntype, "metadata": metadata or {}}
                graph["nodes"].append(node)
                existing_node_ids.add(node_id)

        def add_edge(source_id: str, target_id: str, relation: str):
            key = f"{source_id}->{target_id}:{relation}"
            if key not in existing_edge_keys:
                graph["edges"].append({"source": source_id, "target": target_id, "relation": relation})
                existing_edge_keys.add(key)

        # Add root domain node
        root_node_id = f"domain:{domain}"
        add_node(root_node_id, domain, "domain")

        # ---------------------------------------------------------
        # 1. Enumerate Standard Record Types
        # ---------------------------------------------------------
        raw_records: Dict[str, List[str]] = {}
        record_tasks = {rtype: self._resolve_record(domain, rtype) for rtype in self.RECORD_TYPES}
        record_results = await asyncio.gather(*record_tasks.values(), return_exceptions=True)

        for rtype, res in zip(record_tasks.keys(), record_results):
            if isinstance(res, tuple):
                values, status = res
                raw_records[rtype] = values
                if values:
                    result.data.append({
                        "Category": "DNS Record",
                        "Item": rtype,
                        "Value": ", ".join(values[:5]) + (f" (+{len(values)-5} more)" if len(values) > 5 else ""),
                        "Status": "Configured",
                        "Details": f"{len(values)} record(s) resolved"
                    })

        # Check SRV records for common services if direct query yielded nothing
        if not raw_records.get("SRV"):
            for srv_prefix in ["_sip._tcp", "_autodiscover._tcp"]:
                srv_target = f"{srv_prefix}.{domain}"
                srv_vals, _ = await self._resolve_record(srv_target, "SRV")
                if srv_vals:
                    raw_records["SRV"] = srv_vals
                    result.data.append({
                        "Category": "DNS Record",
                        "Item": f"SRV ({srv_prefix})",
                        "Value": ", ".join(srv_vals),
                        "Status": "Configured",
                        "Details": "Service discovery active"
                    })

        # ---------------------------------------------------------
        # 2. Reverse DNS (PTR) Resolution on Direct IP Addresses
        # ---------------------------------------------------------
        ip_addresses = raw_records.get("A", []) + raw_records.get("AAAA", [])
        ptr_tasks = [self._resolve_ptr(ip) for ip in ip_addresses]
        ptr_results = await asyncio.gather(*ptr_tasks, return_exceptions=True)

        for ip, ptr in zip(ip_addresses, ptr_results):
            ptr_val = ptr if isinstance(ptr, str) and ptr else "-"
            ip_node_id = f"ip:{ip}"
            add_node(ip_node_id, ip, "ip", {"ptr": ptr_val})
            add_edge(root_node_id, ip_node_id, "resolves_to")
            
            result.data.append({
                "Category": "Reverse DNS (PTR)",
                "Item": ip,
                "Value": ptr_val,
                "Status": "Resolved" if ptr_val != "-" else "No PTR Record",
                "Details": "Direct IP resolution mapping"
            })

        # ---------------------------------------------------------
        # 3. Mail Infrastructure Intelligence (MX)
        # ---------------------------------------------------------
        mx_records = raw_records.get("MX", [])
        for mx_entry in mx_records:
            parts = mx_entry.split()
            prio = parts[0] if len(parts) > 1 else "10"
            mx_host = (parts[1] if len(parts) > 1 else parts[0]).rstrip(".")
            
            mx_ips = await self._resolve_host_ips(mx_host)
            mx_ptr = await self._resolve_ptr(mx_ips[0]) if mx_ips else None
            
            mx_node_id = f"mx:{mx_host}"
            add_node(mx_node_id, f"{mx_host} (Pri: {prio})", "mailserver", {"priority": prio, "ips": mx_ips, "ptr": mx_ptr})
            add_edge(root_node_id, mx_node_id, "mail_routed_to")
            
            for mx_ip in mx_ips:
                mx_ip_node = f"ip:{mx_ip}"
                add_node(mx_ip_node, mx_ip, "ip", {"ptr": mx_ptr})
                add_edge(mx_node_id, mx_ip_node, "resolves_to")

            result.data.append({
                "Category": "Mail Server (MX)",
                "Item": f"{mx_host} [Priority {prio}]",
                "Value": ", ".join(mx_ips) if mx_ips else "No IP",
                "Status": "Active MX",
                "Details": f"PTR: {mx_ptr or '-'}"
            })

        # ---------------------------------------------------------
        # 4. Nameserver Infrastructure Intelligence (NS)
        # ---------------------------------------------------------
        ns_records = raw_records.get("NS", [])
        for ns_entry in ns_records:
            ns_host = ns_entry.rstrip(".")
            ns_ips = await self._resolve_host_ips(ns_host)
            ns_ptr = await self._resolve_ptr(ns_ips[0]) if ns_ips else None
            
            ns_node_id = f"ns:{ns_host}"
            add_node(ns_node_id, ns_host, "nameserver", {"ips": ns_ips, "ptr": ns_ptr})
            add_edge(root_node_id, ns_node_id, "managed_by")
            
            for ns_ip in ns_ips:
                ns_ip_node = f"ip:{ns_ip}"
                add_node(ns_ip_node, ns_ip, "ip", {"ptr": ns_ptr})
                add_edge(ns_node_id, ns_ip_node, "resolves_to")

            result.data.append({
                "Category": "Nameserver (NS)",
                "Item": ns_host,
                "Value": ", ".join(ns_ips) if ns_ips else "No IP",
                "Status": "Authoritative NS",
                "Details": f"PTR: {ns_ptr or '-'}"
            })

        # ---------------------------------------------------------
        # 5. Advanced DNS Security Analysis (SPF, DMARC, DNSSEC, CAA, Dangling DNS)
        # ---------------------------------------------------------
        score = 0

        # --- A. SPF Analysis ---
        txt_records = raw_records.get("TXT", [])
        spf_record = next((t for t in txt_records if "v=spf1" in t.lower()), None)
        if spf_record:
            score += 6
            if "-all" in spf_record:
                spf_rating = "Strict (Hard Fail -all)"
                spf_details = "Secure policy preventing unauthorized email spoofing."
            elif "~all" in spf_record:
                spf_rating = "Acceptable (Soft Fail ~all)"
                spf_details = "Soft fail configured; acceptable during rollout."
            elif "+all" in spf_record:
                spf_rating = "Insecure (+all Allowed)"
                spf_details = "DANGEROUS: Permits any IP to send mail on behalf of domain."
                score -= 4
            else:
                spf_rating = "Neutral (?all)"
                spf_details = "Neutral qualifier configured."
            result.data.append({
                "Category": "DNS Security",
                "Item": "SPF Policy",
                "Value": spf_rating,
                "Status": "Pass",
                "Details": f"Record: {spf_record[:60]}... | {spf_details}"
            })
        else:
            result.data.append({
                "Category": "DNS Security",
                "Item": "SPF Policy",
                "Value": "Missing",
                "Status": "Warning",
                "Details": "No SPF TXT record found. Domain vulnerable to email spoofing."
            })

        # --- B. DMARC Analysis ---
        dmarc_records, _ = await self._resolve_record(f"_dmarc.{domain}", "TXT")
        dmarc_record = next((d for d in dmarc_records if "v=dmarc1" in d.lower()), None)
        if dmarc_record:
            score += 8
            d_policy = "None (Monitoring Only)"
            if "p=reject" in dmarc_record.lower():
                d_policy = "Reject (Enforced - Maximum Security)"
                score += 2
            elif "p=quarantine" in dmarc_record.lower():
                d_policy = "Quarantine (Spam Folder Enforcement)"
                score += 1
                
            rua_match = [part for part in dmarc_record.split(";") if "rua=" in part.lower()]
            rua_status = "Aggregate Reports Active" if rua_match else "No Reporting Configured"
            
            result.data.append({
                "Category": "DNS Security",
                "Item": "DMARC Policy",
                "Value": d_policy,
                "Status": "Pass",
                "Details": f"Policy: {d_policy} | {rua_status}"
            })
        else:
            result.data.append({
                "Category": "DNS Security",
                "Item": "DMARC Policy",
                "Value": "Missing",
                "Status": "Warning",
                "Details": "No _dmarc record detected. Spoofed emails cannot be rejected by receivers."
            })

        # --- C. DNSSEC Validation ---
        has_ds = bool(raw_records.get("DS"))
        has_dnskey = bool(raw_records.get("DNSKEY"))
        if has_ds or has_dnskey:
            score += 6
            dnssec_status = "Signed & Enabled"
            dnssec_detail = f"DS: {'Yes' if has_ds else 'No'} | DNSKEY: {'Yes' if has_dnskey else 'No'}"
            dnssec_eval = "Pass"
        else:
            dnssec_status = "Unsigned (Disabled)"
            dnssec_detail = "Zone is not cryptographically signed with DNSSEC."
            dnssec_eval = "Info"

        result.data.append({
            "Category": "DNS Security",
            "Item": "DNSSEC Status",
            "Value": dnssec_status,
            "Status": dnssec_eval,
            "Details": dnssec_detail
        })

        # --- D. CAA Validation ---
        caa_records = raw_records.get("CAA", [])
        if caa_records:
            score += 4
            result.data.append({
                "Category": "DNS Security",
                "Item": "CAA Policy",
                "Value": "Configured",
                "Status": "Pass",
                "Details": f"{len(caa_records)} CAA rule(s) restricting certificate issuance."
            })
        else:
            result.data.append({
                "Category": "DNS Security",
                "Item": "CAA Policy",
                "Value": "Not Configured",
                "Status": "Info",
                "Details": "No CAA records found. Any CA can issue certificates for this domain."
            })

        # --- E. Dangling DNS / Subdomain Takeover Analysis ---
        cname_records = raw_records.get("CNAME", [])
        for cname in cname_records:
            cname_target = cname.rstrip(".").lower()
            matching_provider = next((p for p in DANGLING_CNAME_TARGETS if cname_target.endswith(p)), None)
            if matching_provider:
                # Test if target actually resolves or returns NXDOMAIN
                target_ips = await self._resolve_host_ips(cname_target)
                if not target_ips:
                    score = max(0, score - 8)
                    result.data.append({
                        "Category": "DNS Security",
                        "Item": "Potential Dangling DNS / Takeover",
                        "Value": f"Dangling pointer to {matching_provider}",
                        "Status": "Critical Warning",
                        "Details": f"CNAME {cname_target} does not resolve! Potential unclaimed cloud resource."
                    })
                else:
                    result.data.append({
                        "Category": "DNS Security",
                        "Item": "Cloud Alias (CNAME)",
                        "Value": matching_provider,
                        "Status": "Info",
                        "Details": f"CNAME points to active {matching_provider} ({cname_target})"
                    })

        # Base presence score
        base_records_count = sum(1 for r in ["A", "AAAA", "MX", "NS", "SOA"] if raw_records.get(r))
        score += min(base_records_count * 2, 8)
        
        result.score = min(score, self.max_score)
        result.description = (
            f"Enumerated {len(raw_records)} record types, {len(mx_records)} MX servers, "
            f"{len(ns_records)} NS servers, and verified SPF/DMARC/DNSSEC posture. "
            f"Mapped {len(graph['nodes'])} infrastructure graph nodes."
        )

        # Output to Rich table in CLI mode
        if not getattr(scanner, "quiet", False):
            summary_table = Table(title=f"DNS Intelligence: {domain}", header_style="bold cyan")
            summary_table.add_column("Category", style="cyan")
            summary_table.add_column("Item", style="white")
            summary_table.add_column("Value", style="green")
            summary_table.add_column("Status", style="yellow")
            for row in result.data[:15]:
                summary_table.add_row(row["Category"], row["Item"], row["Value"][:40], row["Status"])
            scanner.console.print(summary_table)

        return result
