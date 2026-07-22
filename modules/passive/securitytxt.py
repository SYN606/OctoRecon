"""
SECURITY TEXT Module
Author : 0ct0pu3
VERSION : 1.0.0
"""

from urllib.parse import urljoin

from core.base_module import BaseModule
from core.report_schema import Report


class Module(BaseModule):

    name = "securitytxt"
    category = "Passive"

    description = (
        "Analyze RFC 9116 security.txt policy."
    )

    LOCATIONS = [
        "/.well-known/security.txt",
        "/security.txt",
    ]

    REQUIRED_FIELDS = [
        "contact",
        "expires",
    ]

    OPTIONAL_FIELDS = [
        "encryption",
        "acknowledgments",
        "policy",
        "hiring",
        "preferred-languages",
        "canonical",
    ]

    async def run(self, scanner):

        self.reset_score()

        response = None
        location = None

        for path in self.LOCATIONS:

            url = urljoin(scanner.target, path)

            try:

                r = await self.get(
                    scanner,
                    url,
                    follow_redirects=True,
                )

                if r.status_code != 200:
                    continue

                content_type = r.headers.get(
                    "Content-Type",
                    "",
                ).lower()

                # Accept only plain text
                if "text/plain" not in content_type:
                    continue

                text = r.text.strip()

                # Reject HTML pages
                if (
                    "<html" in text.lower()
                    or "<!doctype html" in text.lower()
                ):
                    continue

                response = r
                location = path
                break

            except Exception:
                continue

        if response is None:

            self.print_status(
                scanner,
                "security.txt",
                "Not Found",
            )

            self.add_report(
                scanner,
                Report.text(
                    title="security.txt",
                    content="security.txt not found.",
                    score=10,
                    max_score=self.max_score,
                    description="RFC 9116 security policy file was not detected.",
                ),
            )

            return

        fields = {}
        rows = []

        for line in response.text.splitlines():

            line = line.strip()

            if not line:
                continue

            if line.startswith("#"):
                continue

            if ":" not in line:
                continue

            key, value = line.split(":", 1)

            key = key.strip()
            value = value.strip()

            lower = key.lower()

            fields.setdefault(lower, []).append(value)

            rows.append(
                {
                    "Field": key,
                    "Value": value,
                }
            )

        for field in self.REQUIRED_FIELDS:

            if field not in fields:
                self.deduct(4)

        for field in self.OPTIONAL_FIELDS:

            if field not in fields:
                self.deduct(1)

        description = (
            f"Detected at {location} "
            f"with {len(fields)} field(s)."
        )

        self.add_report(
            scanner,
            Report.table(
                title="security.txt Analysis",
                columns=[
                    "Field",
                    "Value",
                ],
                rows=rows,
                score=self.score,
                max_score=self.max_score,
                description=description,
            ),
        )

        self.print_table(
            scanner,
            title="security.txt Analysis",
            columns=[
                "Field",
                "Value",
            ],
            rows=rows,
            limit=10,
            footer=(
                f"Showing {min(len(rows), 10)} of {len(rows)} entries.\n"
                "See HTML/JSON report for complete security.txt."
            ),
        )

        return