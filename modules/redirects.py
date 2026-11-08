"""
Redirect Scanner
Author : 0ct0pu3 / SYN606
VERSION : 2.0.0
"""

from rich.table import Table
from core.base_module import BaseModule
from core.schemas import ModuleResult

class RedirectScanner(BaseModule):
    name = "Redirects"
    category = "Web"
    description = "Analyze HTTP redirects and redirect chains."
    max_score = 10

    async def run(self, scanner) -> ModuleResult:
        result = ModuleResult(module_name=self.name, max_score=self.max_score)
        table = Table(title="Redirect Chain")
        table.add_column("Status", style="cyan")
        table.add_column("URL")

        if not scanner.response:
            result.description = "No response available to inspect redirects."
            result.score = self.max_score
            return result

        history = scanner.response.history
        score = self.max_score

        if not history:
            table.add_row("No Redirect", scanner.target)
            result.data.append({
                "Status": "No Redirect",
                "URL": scanner.target,
            })
        else:
            for item in history:
                table.add_row(str(item.status_code), str(item.url))
                result.data.append({
                    "Status": str(item.status_code),
                    "URL": str(item.url),
                })
            score = max(0, score - len(history))

        # Final destination
        table.add_row(
            str(scanner.response.status_code),
            str(scanner.response.url),
        )
        result.data.append({
            "Status": str(scanner.response.status_code),
            "URL": str(scanner.response.url),
        })

        result.score = score
        result.description = "HTTP redirect chain followed before reaching the final response."
        scanner.console.print(table)
        return result
