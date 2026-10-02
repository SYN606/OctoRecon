import typer
import asyncio
from typing import List, Optional
from rich.console import Console
from core.scanner import Scanner
from core.module_loader import load_modules

app = typer.Typer(
    help="OctoRecon V2: Modern, High-Performance Passive Web Reconnaissance.",
    rich_markup_mode="rich"
)
console = Console()

@app.command()
def scan(
    url: str = typer.Argument(..., help="The target URL to scan (e.g., https://example.com)"),
    modules: Optional[List[str]] = typer.Option(None, "--module", "-m", help="Specific modules to run")
):
    """
    Run a highly concurrent passive web scan against a target.
    """
    async def _run():
        scanner = Scanner(target=url, selected_modules=modules)
        connected = await scanner.connect()
        if not connected:
            return
        try:
            await scanner.run_modules()
        finally:
            await scanner.finish()

    try:
        asyncio.run(_run())
    except KeyboardInterrupt:
        console.print("\n[bold red][!][/bold red] Scan aborted by user.")

@app.command()
def list_modules():
    """
    List all dynamically loaded scanning modules.
    """
    from rich.table import Table
    table = Table(title="Available Modules", header_style="bold cyan")
    table.add_column("Module Name", style="cyan")
    table.add_column("Category", style="green")
    
    loaded = load_modules()
    for m in loaded:
        table.add_row(m.name, m.category)
        
    console.print(table)
    console.print(f"\n[bold green]Total Modules Loaded: {len(loaded)}[/bold green]")

@app.command()
def web(
    port: int = typer.Option(8000, help="Port to run the web server on"),
    host: str = typer.Option("127.0.0.1", help="Host IP")
):
    """
    Start the OctoRecon Web Dashboard.
    """
    import uvicorn
    console.print(f"[bold green]Starting Web Dashboard on http://{host}:{port}[/bold green]")
    uvicorn.run("web.server:app", host=host, port=port, reload=True)

if __name__ == "__main__":
    app()
