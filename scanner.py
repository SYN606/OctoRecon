"""
Main Scan Engine
Author : 0ct0pu3
VERSION : 1.0.0
"""

from datetime import datetime
from rich.console import Console
from rich.progress import (
    Progress,
    SpinnerColumn,
    TextColumn,
    BarColumn,
    TaskProgressColumn,
)

from core.http_client import HTTPClient
from core.report_manager import ReportManager
from urllib.parse import urlparse
import socket

from modules import MODULES

console = Console()


class Scanner:

    def __init__(
        self,
        target: str,
        selected_modules=None,
    ):

        self.console = console
        self.target = target
        self.selected_modules = selected_modules

        self.client = HTTPClient()

        self.report = ReportManager()
        self.report.set_target(target)

        self.response = None

        self.started_at = None
        self.finished_at = None

    # ==========================================================
    # Connect
    # ==========================================================

    async def connect(self):

        self.started_at = datetime.now()

        self.console.print(
            "[cyan][*][/cyan] Connecting to target..."
        )

        try:
            parsed = urlparse(self.target)
            hostname = parsed.hostname or ""

            self.response = await self.client.get(self.target)

            # ------------------------------------------------------
            # Retry without www if HTTP 404
            # ------------------------------------------------------
            if (
                self.response.status_code == 404
                and hostname.startswith("www.")
            ):

                new_hostname = hostname.removeprefix("www.")

                self.target = (
                    f"{parsed.scheme}://{new_hostname}"
                )

                self.report.set_target(self.target)

                self.response = await self.client.get(
                    self.target
                )

        except Exception as e:

            self.console.print(
                f"[red][X] Connection Error : {e}[/red]"
            )

            return False

        parsed = urlparse(self.target)

        hostname = parsed.hostname or "Unknown"

        protocol = parsed.scheme.upper()

        try:
            server_ip = socket.gethostbyname(hostname)
        except Exception:
            server_ip = "N/A"

        self.console.print(
            f"[bold cyan]Target     :[/bold cyan] {self.target}"
        )

        self.console.print(
            f"[bold cyan]Hostname   :[/bold cyan] {hostname}"
        )

        self.console.print(
            f"[bold cyan]Protocol   :[/bold cyan] {protocol}"
        )

        self.console.print(
            f"[bold cyan]Server IP  :[/bold cyan] {server_ip}"
        )

        if self.response is None:

            self.console.print(
                "[red][X] Unable to connect.[/red]"
            )

            return False

        status = self.response.status_code

        if 200 <= status < 300:

            self.console.print(
                f"[green][✓][/green] Connected (HTTP {status})"
            )

        elif 300 <= status < 400:

            self.console.print(
                f"[yellow][→][/yellow] Redirect (HTTP {status})"
            )

        elif 400 <= status < 500:

            self.console.print(
                f"[yellow][!][/yellow] Server Responded (HTTP {status})"
            )

        else:

            self.console.print(
                f"[red][X][/red] Server Error (HTTP {status})"
            )

        return True

    # ==========================================================
    # Run Modules
    # ==========================================================

    async def run_modules(self):

        self.console.rule(
            "[bold cyan]Running Modules[/bold cyan]"
        )

        modules = MODULES

        # ------------------------------------------
        # Run only selected modules
        # ------------------------------------------

        if self.selected_modules:

            available = {}

            for module in MODULES:

                # Display Name
                available[module.name.lower()] = module

                # Slug (optional)
                if hasattr(module, "slug"):
                    available[module.slug.lower()] = module

                # Aliases (optional)
                if hasattr(module, "aliases"):
                    for alias in module.aliases:
                        available[alias.lower()] = module

            invalid = sorted(
                set(self.selected_modules) - set(available.keys())
            )

            if invalid:

                self.console.print(
                    f"[bold red][X] Unknown module(s): {', '.join(invalid)}[/bold red]"
                )

                self.console.print()

                self.console.print(
                    "[bold cyan]Available Modules:[/bold cyan]"
                )

                for module in MODULES:
                    self.console.print(
                        f"  • {module.name}"
                    )

                return

            modules = []

            loaded = set()

            for name in self.selected_modules:

                module = available[name]

                if module not in loaded:
                    modules.append(module)
                    loaded.add(module)

        total = len(modules)

        with self.console.status(
            "[cyan]Initializing...[/cyan]",
            spinner="dots",
        ) as status:

            for index, module in enumerate(
                modules,
                start=1,
            ):

                percent = ((index - 1) / total) * 100

                status.update(
                    f"[bold cyan][{percent:>3.0f}%][/bold cyan] "
                    f"({index:02}/{total:02}) "
                    f"[bold white]{module.name}[/bold white]"
                )

                try:
                    self.console.print()

                    self.console.rule(
                        f"[bold cyan][{index:02}/{total:02}][/bold cyan] "
                        f"[bold white]{module.name}[/bold white]",
                        style="cyan",
                    )

                    self.console.print()
                    await module.run(self)

                except Exception as e:

                    self.console.print(
                        f"[red][{module.name}] {e}[/red]"
                    )

            status.update(
                f"[bold green][100%][/bold green] "
                f"({total:02}/{total:02}) "
                f"[bold green]Completed[/bold green]"
            )

        self.console.print()

        self.console.print(
            "[bold green]✓ Scan Completed Successfully[/bold green]"
        )
    # ==========================================================
    # Finish
    # ==========================================================

    async def finish(self):

        self.finished_at = datetime.now()

        json_report = self.report.save_json()

        html_report = None

        try:

            html_report = self.report.save_html()

        except Exception as e:

            self.console.print(
                f"[yellow][!] HTML Report Error : {e}[/yellow]"
            )

        self.console.rule(
            "[bold green]Scan Complete[/bold green]"
        )

        duration = (
            self.finished_at - self.started_at
        ).total_seconds()

        self.console.print(
            f"[bold magenta]Duration   :[/bold magenta] "
            f"{duration:.2f} sec"
        )
            
        self.console.print(
                "[bold cyan]! Full scan details are available in the HTML/JSON report..[/bold cyan]"
            )
        
        self.console.print()

        self.console.print(
            f"[green]JSON Report Saved[/green] : {json_report}"
        )

        if html_report:

            self.console.print(
                f"[cyan]HTML Report Saved[/cyan] : {html_report}"
            )
            

        await self.client.close()
