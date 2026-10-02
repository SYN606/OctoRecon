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

console = Console()

class Scanner:
    def __init__(self, target: str, selected_modules: list[str] = None):
        self.console = console
        self.response = None
        self.target = target
        self.selected_modules = selected_modules
        self.client = HTTPClient()
        self.report = FinalReport(target=target)
        self.modules = load_modules()
        self.started_at = None
        self.finished_at = None

    async def connect(self) -> bool:
        self.started_at = datetime.now()
        console.print(f"[cyan][*][/cyan] Connecting to [bold]{self.target}[/bold]...")
        
        parsed = urlparse(self.target)
        hostname = parsed.hostname or "Unknown"
        protocol = parsed.scheme.upper()
        try:
            server_ip = socket.gethostbyname(hostname)
        except Exception:
            server_ip = "N/A"
            
        console.print(f"[bold cyan]Target     :[/bold cyan] {self.target}")
        console.print(f"[bold cyan]Hostname   :[/bold cyan] {hostname}")
        console.print(f"[bold cyan]Server IP  :[/bold cyan] {server_ip}")

        try:
            self.response = await self.client.get(self.target)
            status = self.response.status_code
            if 200 <= status < 300:
                console.print(f"[green][OK][/green] Connected (HTTP {status})")
            elif 300 <= status < 400:
                console.print(f"[yellow][->][/yellow] Redirect (HTTP {status})")
            else:
                console.print(f"[yellow][!][/yellow] Server Responded (HTTP {status})")
            return True
        except Exception as e:
            console.print(f"[red][X] Connection Error : {e}[/red]")
            return False

    async def run_modules(self):
        console.rule("[bold cyan]Running Modules Concurrently (V2 Engine)[/bold cyan]")
        
        to_run = self.modules
        if self.selected_modules:
            to_run = [m for m in self.modules if m.name.lower() in [s.lower() for s in self.selected_modules]]

        if not to_run:
            console.print("[red][!] No valid modules found to run.[/red]")
            return

        # Python 3.11+ TaskGroup for safe, highly concurrent execution
        with console.status(f"[cyan]Executing {len(to_run)} modules concurrently...[/cyan]", spinner="bouncingBar"):
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
                console.print(f"[green]  [OK] {name}[/green] completed (Score: {res.score}/{res.max_score})")
            elif name in self.report.modules:
                # V1 modules populate self.report.modules via self.add_report()
                legacy_res = self.report.modules[name]
                console.print(f"[green]  [OK] {name}[/green] completed (Legacy V1)")
            else:
                console.print(f"[yellow]  [!] {name}[/yellow] returned no data.")

    async def _safe_run(self, module: BaseModule) -> ModuleResult | None:
        """Wrapper to catch individual module crashes."""
        try:
            return await module.run(self)
        except Exception as e:
            console.print(f"[red][!] Module {module.name} crashed: {e}[/red]")
            return ModuleResult(module_name=module.name, score=0, max_score=module.max_score, description=f"Crashed: {e}")

    async def finish(self):
        self.finished_at = datetime.now()
        duration = (self.finished_at - self.started_at).total_seconds()
        await self.client.close()
        
        self.report.calculate_grade()
        console.rule(f"[bold green]Scan Complete - Grade: {self.report.grade}[/bold green]")
        console.print(f"[bold magenta]Duration   :[/bold magenta] {duration:.2f} sec")
        
        # Save JSON
        REPORT_DIR.mkdir(parents=True, exist_ok=True)
        filename = f"{self.target.replace('https://','').replace('http://','').replace('/','_')}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        path = REPORT_DIR / filename
        
        with open(path, "w") as f:
            f.write(self.report.model_dump_json(indent=4))
        console.print(f"[cyan]JSON Report saved to {path}[/cyan]")
