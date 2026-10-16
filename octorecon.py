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
def dns(
    target: str = typer.Argument(..., help="Target domain or host (e.g., example.com)"),
    records: bool = typer.Option(True, "--records/--no-records", help="Resolve comprehensive DNS records"),
    subdomains: bool = typer.Option(False, "--subdomains", "-s", help="Include passive subdomain discovery & PTR resolution"),
    security: bool = typer.Option(True, "--security/--no-security", help="Audit SPF, DMARC, DNSSEC, and dangling CNAMEs"),
    graph: bool = typer.Option(False, "--graph", "-g", help="Display infrastructure graph relationship summary"),
    export: Optional[str] = typer.Option(None, "--export", "-o", help="Export full report and graph to JSON file")
):
    """
    DNS Intelligence & Infrastructure Mapping (DNSDumpster-inspired).
    """
    import json
    from rich.tree import Tree
    from rich.table import Table

    selected_modules = ["DNS"]
    if subdomains:
        selected_modules.append("subdomains")
    selected_modules.append("Server Location (IPInfo)")

    async def _run_dns():
        scanner = Scanner(target=target, selected_modules=selected_modules, quiet=False)
        connected = await scanner.connect()
        if not connected:
            raise typer.Exit(code=1)

        try:
            await scanner.run_modules()
        finally:
            await scanner.finish()

        # Display Infrastructure Graph Tree if requested
        if graph and hasattr(scanner.report, "infrastructure_graph"):
            ig = scanner.report.infrastructure_graph
            nodes = ig.get("nodes", [])
            edges = ig.get("edges", [])
            
            tree = Tree(f"[bold cyan][Infrastructure Graph: {target}][/bold cyan]")
            domain_node = next((n for n in nodes if n["type"] == "domain"), None)
            
            ns_branch = tree.add("[bold magenta]Nameservers (NS)[/bold magenta]")
            mx_branch = tree.add("[bold blue]Mail Exchangers (MX)[/bold blue]")
            sub_branch = tree.add("[bold green]Subdomains[/bold green]")
            ip_branch = tree.add("[bold yellow]IP Addresses & ASNs[/bold yellow]")

            for n in nodes:
                ntype = n.get("type")
                lbl = n.get("label", "")
                if ntype == "nameserver":
                    ns_branch.add(f"[cyan]{lbl}[/cyan]")
                elif ntype == "mailserver":
                    mx_branch.add(f"[cyan]{lbl}[/cyan]")
                elif ntype == "subdomain":
                    sub_branch.add(f"[green]{lbl}[/green]")
                elif ntype == "ip":
                    ptr = n.get("metadata", {}).get("ptr", "-")
                    ip_branch.add(f"[yellow]{lbl}[/yellow] (PTR: {ptr})")
                elif ntype == "asn":
                    ip_branch.add(f"[bold red]-> {lbl}[/bold red]")

            console.print("\n")
            console.print(tree)

        # Export if requested
        if export:
            with open(export, "w", encoding="utf-8") as f:
                f.write(scanner.report.model_dump_json(indent=4))
            console.print(f"\n[bold green][✓] DNS intelligence report exported to: {export}[/bold green]")

    try:
        asyncio.run(_run_dns())
    except KeyboardInterrupt:
        console.print("\n[bold red][!][/bold red] Scan aborted by user.")
        raise typer.Exit(code=130)

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
