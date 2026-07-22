"""
SSL Scanner
Author : 0ct0pu3
VERSION : 1.0.0
"""

import asyncio
import socket
import ssl
from datetime import datetime, timezone
from urllib.parse import urlparse

from rich.table import Table

from core.base_module import BaseModule
from core.report_schema import Report


WEAK_CIPHER_MARKERS = (
    "RC4",
    "3DES",
    "DES",
    "NULL",
    "EXPORT",
    "MD5",
    "PSK",
    "ANON",
)


class SSLScanner(BaseModule):

    name = "SSL"

    category = "Core"

    description = (
        "Inspect SSL/TLS certificates and supported protocols."
    )

    def _fetch_cert_sync(
        self,
        hostname,
        port=443,
        timeout=10,
    ):

        context = ssl.create_default_context()

        with socket.create_connection(
            (hostname, port),
            timeout=timeout,
        ) as sock:

            with context.wrap_socket(
                sock,
                server_hostname=hostname,
            ) as secure_sock:

                cert = secure_sock.getpeercert()

                tls_version = secure_sock.version()

                cipher = secure_sock.cipher()

                return (
                    cert,
                    tls_version,
                    cipher,
                )

    async def run(self, scanner):

        parsed = urlparse(scanner.target)

        hostname = parsed.hostname

        table = Table(title="SSL Certificate")

        table.add_column(
            "Property",
            style="cyan",
        )

        table.add_column("Value")

        data = {}

        score = 0

        max_score = 30

        if not hostname:

            data = {
                "Status": "Invalid",
                "Error": "Could not extract hostname from target.",
            }

            for key, value in data.items():
                table.add_row(key, str(value))

            scanner.console.print(table)

            scanner.report.add_module(
                self.name,
                Report.keyvalue(
                    title="SSL Certificate",
                    data=data,
                    score=0,
                    max_score=max_score,
                    description="Unable to inspect SSL certificate.",
                ),
            )

            return

        loop = asyncio.get_running_loop()

        try:

            cert, tls_version, cipher_info = (
                await loop.run_in_executor(
                    None,
                    self._fetch_cert_sync,
                    hostname,
                )
            )

        except ssl.SSLCertVerificationError as e:

            reason = getattr(
                e,
                "verify_message",
                str(e),
            ).lower()

            if "expired" in reason:

                error = "Certificate has expired."

            elif (
                "self-signed" in reason
                or "self signed" in reason
            ):

                error = (
                    "Self-signed certificate."
                )

            elif (
                "hostname mismatch" in reason
                or "does not match" in reason
            ):

                error = (
                    "Hostname does not match certificate."
                )

            elif "unable to get local issuer" in reason:

                error = (
                    "Incomplete certificate chain."
                )

            else:

                error = str(e)

            data = {
                "Status": "Invalid",
                "Error": error,
            }

        except socket.timeout:

            data = {
                "Status": "Invalid",
                "Error": "Connection timed out.",
            }

        except ConnectionRefusedError:

            data = {
                "Status": "Invalid",
                "Error": "Connection refused.",
            }

        except ssl.SSLError as e:

            data = {
                "Status": "Invalid",
                "Error": f"SSL handshake failed: {e}",
            }

        except socket.gaierror:

            data = {
                "Status": "Invalid",
                "Error": "Hostname could not be resolved.",
            }

        except Exception as e:

            data = {
                "Status": "Invalid",
                "Error": f"Unexpected error: {e}",
            }

        else:

            issuer = dict(
                x[0]
                for x in cert.get(
                    "issuer",
                    (),
                )
            )

            not_after = cert.get("notAfter")

            not_before = cert.get("notBefore")

            if not not_after or not not_before:

                raise ValueError(
                    "Certificate validity period missing."
                )

            expiry = datetime.strptime(
                not_after,
                "%b %d %H:%M:%S %Y %Z",
            ).replace(
                tzinfo=timezone.utc,
            )

            not_before = datetime.strptime(
                not_before,
                "%b %d %H:%M:%S %Y %Z",
            ).replace(
                tzinfo=timezone.utc,
            )
            
            now = datetime.now(timezone.utc)

            days_remaining = (
                expiry - now
            ).days

            san_entries = sorted(
                {
                    value
                    for key, value in cert.get(
                        "subjectAltName",
                        (),
                    )
                    if key == "DNS"
                }
            )

            common_name = dict(
                x[0]
                for x in cert.get(
                    "subject",
                    (),
                )
            ).get(
                "commonName",
                "-"
            )

            issuer_name = issuer.get(
                "organizationName",
                issuer.get(
                    "commonName",
                    "-"
                ),
            )

            cipher_name = (
                cipher_info[0]
                if cipher_info
                else "-"
            )

            cipher_bits = (
                cipher_info[2]
                if cipher_info
                else "-"
            )

            findings = []

            if days_remaining > 90:
                score += 10
            elif days_remaining > 30:
                score += 7
            elif days_remaining > 7:
                score += 4
                findings.append(
                    "Certificate expires soon."
                )
            else:
                findings.append(
                    "Certificate is about to expire."
                )

            if tls_version in (
                "TLSv1.3",
                "TLSv1.2",
            ):
                score += 10
            else:
                findings.append(
                    f"Outdated TLS version ({tls_version})."
                )

            weak_cipher = any(
                marker in cipher_name.upper()
                for marker in WEAK_CIPHER_MARKERS
            )

            if weak_cipher:
                findings.append(
                    f"Weak cipher detected ({cipher_name})."
                )
            else:
                score += 10

            score = max(
                0,
                min(score, max_score),
            )

            if score >= 27:
                status = "Excellent"
            elif score >= 21:
                status = "Good"
            elif score >= 15:
                status = "Fair"
            else:
                status = "Poor"

            data = {
                "Status": status,
                "Common Name": common_name,
                "Issuer": issuer_name,
                "TLS Version": tls_version,
                "Cipher": cipher_name,
                "Cipher Bits": cipher_bits,
                "Valid From": not_before.strftime(
                    "%Y-%m-%d"
                ),
                "Valid Until": expiry.strftime(
                    "%Y-%m-%d"
                ),
                "Days Remaining": days_remaining,
                "Subject Alternative Names": (
                    ", ".join(san_entries)
                    if san_entries
                    else "-"
                ),
                "Findings": (
                    findings
                    if findings
                    else ["No issues detected."]
                ),
            }

        for key, value in data.items():

            if isinstance(value, list):
                value = "\n".join(value)

            table.add_row(
                key,
                str(value),
            )

        scanner.console.print(table)

        description = (
            f"TLS {data.get('TLS Version', '-')} "
            f"using {data.get('Cipher', '-')}. "
            f"Status: {data.get('Status', '-')}"
        )

        scanner.report.add_module(
            self.name,
            Report.keyvalue(
                title="SSL Certificate",
                data=data,
                score=score,
                max_score=max_score,
                description=description,
            ),
        )