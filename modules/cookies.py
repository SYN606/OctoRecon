"""
Cookie Scanner
Author : 0ct0pu3
VERSION : 1.0.0
"""

from rich.table import Table

from core.base_module import BaseModule
from core.report_schema import Report


class CookieScanner(BaseModule):

    name = "Cookies"
    category = "Web"

    description = (
        "Analyze cookies and security attributes."
    )

    async def run(self, scanner):

        table = Table(title="Cookies")

        table.add_column("Cookie", style="cyan")
        table.add_column("Value")

        cookies = scanner.response.cookies

        rows = []

        score = 10
        max_score = 10

        if not cookies:

            table.add_row("-", "-")

            rows.append(
                {
                    "Cookie": "-",
                    "Value": "-",
                }
            )

        else:

            for name, value in cookies.items():

                display = (
                    value[:40] + "..."
                    if len(value) > 40
                    else value
                )

                table.add_row(
                    name,
                    display,
                )

                rows.append(
                    {
                        "Cookie": name,
                        "Value": display,
                    }
                )

            # Presence of cookies reduces the score slightly.
            score = max(0, score - min(len(rows), 5))

        scanner.console.print(table)

        scanner.report.add_module(
            self.name,
            Report.table(
                title="Cookies",
                columns=[
                    "Cookie",
                    "Value",
                ],
                rows=rows,
                score=score,
                max_score=max_score,
                description="Cookies returned by the target application.",
            ),
        )
