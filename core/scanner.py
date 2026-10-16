import asyncio
import json
from datetime import datetime
from urllib.parse import urlparse
import socket
from rich.console import Console

from core.http_client import HTTPClient
from core.schemas import FinalReport, ModuleResult
from core.module_loader import load_modules
from core.base_module import BaseModule
from config import REPORT_DIR

import io
console = Console()

class Scanner:
    def __init__(self, target: str, selected_modules: list[str] = None, quiet: bool = False):
        self.quiet = quiet
        if self.quiet:
            self.console = Console(file=io.StringIO(), quiet=True)
        else:
            self.console = console
            
        self.response = None
        self.target = target.strip() if target else ""
        self.selected_modules = selected_modules
        self.client = HTTPClient()
        self.report = FinalReport(target=self.target)
        self.modules = load_modules()
        self.started_at = None
        self.finished_at = None

    async def connect(self) -> bool:
        self.started_at = datetime.now()
        raw = self.target
        if not raw:
            if not self.quiet:
                self.console.print("[red][X] No target URL provided.[/red]")
            return False

        # Support target without http/https by checking HTTPS first, then HTTP fallback
        if not raw.startswith(("http://", "https://")):
            candidates = [f"https://{raw}", f"http://{raw}"]
        else:
            candidates = [raw]

        last_error = None
        for candidate in candidates:
            parsed = urlparse(candidate)
            hostname = parsed.hostname or "Unknown"
            try:
                server_ip = socket.gethostbyname(hostname)
            except Exception:
                server_ip = "N/A"

            if not self.quiet:
                self.console.print(f"[cyan][*][/cyan] Connecting to [bold]{candidate}[/bold]...")
                self.console.print(f"[bold cyan]Target     :[/bold cyan] {candidate}")
                self.console.print(f"[bold cyan]Hostname   :[/bold cyan] {hostname}")
                self.console.print(f"[bold cyan]Server IP  :[/bold cyan] {server_ip}")

            try:
                self.response = await self.client.get(candidate)
                self.target = candidate
                self.report.target = candidate
                status = self.response.status_code
                if not self.quiet:
                    if 200 <= status < 300:
                        self.console.print(f"[green][OK][/green] Connected (HTTP {status})")
                    elif 300 <= status < 400:
                        self.console.print(f"[yellow][->][/yellow] Redirect (HTTP {status})")
                    else:
                        self.console.print(f"[yellow][!][/yellow] Server Responded (HTTP {status})")
                return True
            except Exception as e:
                last_error = e
                if not self.quiet:
                    self.console.print(f"[yellow][!] Could not connect to {candidate}: {e}[/yellow]")

        if not self.quiet:
            self.console.print(f"[red][X] Connection Error : {last_error}[/red]")
        return False

    async def run_modules(self):
        if not self.quiet:
            self.console.rule("[bold cyan]Running Modules Concurrently (V2 Engine)[/bold cyan]")
        
        to_run = self.modules
        if self.selected_modules:
            to_run = [m for m in self.modules if m.name.lower() in [s.lower() for s in self.selected_modules]]

        if not to_run:
            if not self.quiet:
                self.console.print("[red][!] No valid modules found to run.[/red]")
            return

        # Python 3.11+ TaskGroup for safe, highly concurrent execution
        if self.quiet:
            async with asyncio.TaskGroup() as tg:
                tasks = {
                    module.name: tg.create_task(self._safe_run(module)) 
                    for module in to_run
                }
        else:
            with self.console.status(f"[cyan]Executing {len(to_run)} modules concurrently...[/cyan]", spinner="bouncingBar"):
                async with asyncio.TaskGroup() as tg:
                    tasks = {
                        module.name: tg.create_task(self._safe_run(module)) 
                        for module in to_run
                    }

        # Collect results
        for name, task in tasks.items():
            res = task.result()
            if res:
                self.report.modules[name] = res
                if not self.quiet:
                    self.console.print(f"[green]  [OK] {name}[/green] completed (Score: {res.score}/{res.max_score})")
            elif name in self.report.modules:
                # V1 modules populate self.report.modules via self.add_report()
                legacy_res = self.report.modules[name]
                if not self.quiet:
                    self.console.print(f"[green]  [OK] {name}[/green] completed (Legacy V1)")
            else:
                if not self.quiet:
                    self.console.print(f"[yellow]  [!] {name}[/yellow] returned no data.")

    async def _safe_run(self, module: BaseModule) -> ModuleResult | None:
        """Wrapper to catch individual module crashes."""
        try:
            return await module.run(self)
        except Exception as e:
            if not self.quiet:
                self.console.print(f"[red][!] Module {module.name} crashed: {e}[/red]")
            return ModuleResult(module_name=module.name, score=0, max_score=module.max_score, description=f"Crashed: {e}")

    async def finish(self):
        self.finished_at = datetime.now()
        duration = (self.finished_at - self.started_at).total_seconds()
        await self.client.close()
        
        self.report.calculate_grade()
        if not self.quiet:
            self.console.rule(f"[bold green]Scan Complete - Grade: {self.report.grade}[/bold green]")
            self.console.print(f"[bold magenta]Duration   :[/bold magenta] {duration:.2f} sec")
        
        # Save JSON
        REPORT_DIR.mkdir(parents=True, exist_ok=True)
        filename = f"{self.target.replace('https://','').replace('http://','').replace('/','_')}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        path = REPORT_DIR / filename
        
        with open(path, "w") as f:
            f.write(self.report.model_dump_json(indent=4))
            
        if not self.quiet:
            self.console.print(f"[cyan]JSON Report saved to {path}[/cyan]")
