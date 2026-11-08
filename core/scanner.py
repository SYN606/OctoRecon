import asyncio
import json
from datetime import datetime
from urllib.parse import urlparse
import socket
from typing import Any, Callable, Dict, List, Optional
from rich.console import Console

from core.http_client import HTTPClient
from core.schemas import FinalReport, ModuleResult
from core.module_loader import load_modules
from core.base_module import BaseModule
from config import REPORT_DIR
import database

import io
console = Console()

async def async_resolve_ip(hostname: str) -> str:
    """Non-blocking DNS resolution on the asyncio event loop."""
    try:
        loop = asyncio.get_running_loop()
        addr_info = await loop.getaddrinfo(hostname, None, family=socket.AF_INET)
        if addr_info and addr_info[0] and addr_info[0][4]:
            return addr_info[0][4][0]
    except Exception:
        pass
    return "N/A"

class Scanner:
    def __init__(
        self,
        target: str,
        selected_modules: Optional[List[str]] = None,
        quiet: bool = False,
        active_mode: bool = False,
        on_progress: Optional[Callable[[Dict[str, Any]], Any]] = None
    ):
        self.quiet = quiet
        if self.quiet:
            self.console = Console(file=io.StringIO(), quiet=True)
        else:
            self.console = console
            
        self.response = None
        self.target = target.strip() if target else ""
        self.selected_modules = selected_modules
        self.active_mode = active_mode
        self.on_progress = on_progress
        self.shared_cache: Dict[str, Any] = {}
        self.client = HTTPClient()
        self.report = FinalReport(target=self.target)
        self.modules = load_modules()
        self.started_at = None
        self.finished_at = None
        self.scan_id = None

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
            
            # Non-blocking async DNS resolution
            server_ip = await async_resolve_ip(hostname)

            if not self.quiet:
                self.console.print(f"[cyan][*][/cyan] Connecting to [bold]{candidate}[/bold]...")
                self.console.print(f"[bold cyan]Target     :[/bold cyan] {candidate}")
                self.console.print(f"[bold cyan]Hostname   :[/bold cyan] {hostname}")
                self.console.print(f"[bold cyan]Server IP  :[/bold cyan] {server_ip}")

            try:
                self.response = await self.client.get(candidate)
                self.target = candidate
                self.report.target = candidate
                # Populate shared cache with the baseline response
                self.shared_cache["root_response"] = self.response
                self.shared_cache["root_html"] = self.response.text
                self.shared_cache["server_ip"] = server_ip
                
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
        
        def _normalize(text: str) -> str:
            return "".join(c for c in text.lower() if c.isalnum())

        to_run = self.modules
        if self.selected_modules:
            targets = []
            for s in self.selected_modules:
                for sub in str(s).split(","):
                    sub_clean = sub.strip()
                    if sub_clean:
                        targets.append(_normalize(sub_clean))

            def _matches(mod):
                names = [mod.name, getattr(mod, "slug", ""), getattr(mod, "category", "")]
                names.extend(getattr(mod, "aliases", []))
                norm_names = [_normalize(n) for n in names if n]
                return any(t in norm_names or any(t == nn or t in nn for nn in norm_names) for t in targets)

            to_run = [m for m in self.modules if _matches(m)]

        if not to_run:
            if not self.quiet:
                self.console.print("[red][!] No valid modules found to run.[/red]")
            return

        total_modules = len(to_run)
        completed_count = 0

        async def _run_and_notify(mod):
            nonlocal completed_count
            res = await self._safe_run(mod)
            completed_count += 1
            if self.on_progress:
                try:
                    prog_data = {
                        "module": mod.name,
                        "status": "completed",
                        "completed": completed_count,
                        "total": total_modules,
                        "percent": int((completed_count / total_modules) * 100)
                    }
                    if asyncio.iscoroutinefunction(self.on_progress):
                        await self.on_progress(prog_data)
                    else:
                        self.on_progress(prog_data)
                except Exception:
                    pass
            return res

        # Python 3.11+ TaskGroup for safe, highly concurrent execution
        if self.quiet:
            async with asyncio.TaskGroup() as tg:
                tasks = {
                    module.name: tg.create_task(_run_and_notify(module)) 
                    for module in to_run
                }
        else:
            with self.console.status(f"[cyan]Executing {len(to_run)} modules concurrently...[/cyan]", spinner="bouncingBar"):
                async with asyncio.TaskGroup() as tg:
                    tasks = {
                        module.name: tg.create_task(_run_and_notify(module)) 
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
        
        # Save JSON file
        REPORT_DIR.mkdir(parents=True, exist_ok=True)
        filename = f"{self.target.replace('https://','').replace('http://','').replace('/','_')}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        path = REPORT_DIR / filename
        
        with open(path, "w", encoding="utf-8") as f:
            f.write(self.report.model_dump_json(indent=4))
            
        if not self.quiet:
            self.console.print(f"[cyan]JSON Report saved to {path}[/cyan]")

        # Save to SQLite Database
        try:
            self.scan_id = await database.save_scan(
                target=self.target,
                report_dict=self.report.model_dump(mode="json"),
                duration=duration,
                grade=self.report.grade
            )
            if not self.quiet:
                self.console.print(f"[green]Report indexed in SQLite database (ID: {self.scan_id})[/green]")
        except Exception as e:
            if not self.quiet:
                self.console.print(f"[yellow][!] Could not save to database: {e}[/yellow]")
