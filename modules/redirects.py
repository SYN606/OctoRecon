"""
Redirect Scanner
Author : 0ct0pu3
VERSION : 1.0.0
"""

from rich.table import Table

from core.base_module import BaseModule
from core.report_schema import Report


class RedirectScanner(BaseModule):

    name = "Redirects"
    category = "Web"

    description = (
        "Analyze HTTP redirects and redirect chains."
    )

    async def run(self, scanner):

        history = scanner.response.history

        table = Table(title="Redirect Chain")

        table.add_column("Status", style="cyan")
        table.add_column("URL")

        rows = []

        score = 10
        max_score = 10

        if not history:

            table.add_row(
                "No Redirect",
                scanner.target,
            )

            rows.append(
                {
                    "Status": "No Redirect",
                    "URL": scanner.target,
                }
            )

        else:

            for item in history:

                table.add_row(
                    str(item.status_code),
                    str(item.url),
                )

                rows.append(
                    {
                        "Status": str(item.status_code),
                        "URL": str(item.url),
                    }
                )

            # Multiple redirects reduce score slightly
            score = max(0, score - len(history))

        # Final destination
        table.add_row(
            str(scanner.response.status_code),
            str(scanner.response.url),
        )

        rows.append(
            {
                "Status": str(scanner.response.status_code),
                "URL": str(scanner.response.url),
            }
        )

        scanner.console.print(table)

        scanner.report.add_module(
            self.name,
            Report.table(
                title="Redirect Chain",
                columns=[
                    "Status",
                    "URL",
                ],
                rows=rows,
                score=score,
                max_score=max_score,
                description="HTTP redirect chain followed before reaching the final response.",
            ),
        )
