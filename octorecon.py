"""
OctoRecon V2: Modern, High-Performance Passive Web Reconnaissance Framework
Command-Line Interface (CLI) & Web Server Controller
"""

import typer
import asyncio
from typing import List, Optional
from rich.console import Console
from rich.table import Table

from core.scanner import Scanner
from core.module_loader import load_modules
from core.exporter import export_to_csv, export_to_pdf
import database
from config import WEB_HOST, WEB_PORT

app = typer.Typer(
    help="🐙 OctoRecon V2: High-Performance Passive Intelligence & Web Reconnaissance Framework.",
    rich_markup_mode="rich"
)
console = Console()

def _run_scan_sync(
    target: str,
    modules: Optional[List[str]] = None,
    active_mode: bool = False,
    export_json: Optional[str] = None,
    export_pdf: Optional[str] = None,
    export_csv: Optional[str] = None
):
    """Internal runner to execute scan and handle exports cleanly."""
    async def _run():
        scanner = Scanner(
            target=target,
            selected_modules=modules,
            quiet=False,
            active_mode=active_mode
        )
        connected = await scanner.connect()
        if not connected:
            raise typer.Exit(code=1)

        try:
            await scanner.run_modules()
        finally:
            await scanner.finish()

        report_dict = scanner.report.model_dump()

        # Handle file exports
        if export_json:
            with open(export_json, "w", encoding="utf-8") as f:
                f.write(scanner.report.model_dump_json(indent=4))
            console.print(f"[bold green][✓] JSON report exported to: {export_json}[/bold green]")

        if export_csv:
            export_to_csv(report_dict, export_csv)
            console.print(f"[bold green][✓] CSV report exported to: {export_csv}[/bold green]")

        if export_pdf:
            success = export_to_pdf(report_dict, export_pdf)
            if success:
                console.print(f"[bold green][✓] PDF executive report exported to: {export_pdf}[/bold green]")
            else:
                console.print(f"[bold red][!] PDF export failed (check ReportLab installation).[/bold red]")

    try:
        asyncio.run(_run())
    except KeyboardInterrupt:
        console.print("\n[bold red][!][/bold red] Scan aborted by user.")
        raise typer.Exit(code=130)

# ==========================================================
# Core Scanning Commands
# ==========================================================

@app.command()
def scan(
    url: str = typer.Argument(..., help="The target URL or domain to scan (e.g., https://example.com)"),
    modules: Optional[List[str]] = typer.Option(None, "--module", "-m", help="Specific module(s) to run (e.g., -m ssl -m dns or -m 'dns,ssl')"),
    active: bool = typer.Option(False, "--active", "-a", help="Enable active probing (WAF trigger probe & path exposure checks)"),
    export: Optional[str] = typer.Option(None, "--export", "-o", help="Export report to JSON file"),
    pdf: Optional[str] = typer.Option(None, "--pdf", help="Export executive report to PDF file"),
    csv: Optional[str] = typer.Option(None, "--csv", help="Export findings to CSV file")
):
    """
    Run full concurrent reconnaissance scan against a target.
    """
    _run_scan_sync(
        target=url,
        modules=modules,
        active_mode=active,
        export_json=export,
        export_pdf=pdf,
        export_csv=csv
    )

@app.command()
def module(
    module_name: str = typer.Argument(..., help="Module name, slug, or alias (e.g., ssl, dns, whois, tech, cookies)"),
    target: str = typer.Argument(..., help="Target URL or domain (e.g., https://example.com)"),
    active: bool = typer.Option(False, "--active", "-a", help="Enable active probing mode"),
    export: Optional[str] = typer.Option(None, "--export", "-o", help="Export report to JSON file"),
    pdf: Optional[str] = typer.Option(None, "--pdf", help="Export report to PDF file"),
    csv: Optional[str] = typer.Option(None, "--csv", help="Export findings to CSV file")
):
    """
    Execute any single module dynamically against a target.
    """
    _run_scan_sync(
        target=target,
        modules=[module_name],
        active_mode=active,
        export_json=export,
        export_pdf=pdf,
        export_csv=csv
    )

# ==========================================================
# Dedicated Module CLI Shortcuts
# ==========================================================

@app.command()
def dns(
    target: str = typer.Argument(..., help="Target domain or host (e.g., example.com)"),
    subdomains: bool = typer.Option(False, "--subdomains", "-s", help="Include passive subdomain discovery"),
    graph: bool = typer.Option(False, "--graph", "-g", help="Display infrastructure relationship tree"),
    export: Optional[str] = typer.Option(None, "--export", "-o", help="Export to JSON"),
    pdf: Optional[str] = typer.Option(None, "--pdf", help="Export to PDF"),
    csv: Optional[str] = typer.Option(None, "--csv", help="Export to CSV")
):
    """DNS Intelligence & Infrastructure Mapping (DNSDumpster-inspired)."""
    mods = ["DNS", "Server Location (IPInfo)"]
    if subdomains:
        mods.append("subdomains")
    _run_scan_sync(target, modules=mods, export_json=export, export_pdf=pdf, export_csv=csv)

@app.command()
def ssl(target: str = typer.Argument(..., help="Target host (e.g., example.com)"), export: Optional[str] = typer.Option(None, "-o")):
    """Inspect SSL/TLS certificates, cipher suites, and protocol versions."""
    _run_scan_sync(target, modules=["SSL"], export_json=export)

@app.command()
def headers(target: str = typer.Argument(..., help="Target URL"), export: Optional[str] = typer.Option(None, "-o")):
    """Audit HTTP security headers (HSTS, CSP, X-Frame-Options, etc.)."""
    _run_scan_sync(target, modules=["Headers"], export_json=export)

@app.command()
def cookies(target: str = typer.Argument(..., help="Target URL"), export: Optional[str] = typer.Option(None, "-o")):
    """Audit cookies for Secure, HttpOnly, and SameSite hardening flags."""
    _run_scan_sync(target, modules=["Cookies"], export_json=export)

@app.command()
def tech(
    target: str = typer.Argument(..., help="Target URL"),
    active: bool = typer.Option(False, "--active", "-a", help="Enable path exposure and admin panel checks"),
    export: Optional[str] = typer.Option(None, "-o")
):
    """Detect web technologies, CMS, frameworks, web servers, and exposed files."""
    _run_scan_sync(target, modules=["Technology"], active_mode=active, export_json=export)

@app.command()
def whois(target: str = typer.Argument(..., help="Target domain"), export: Optional[str] = typer.Option(None, "-o")):
    """Perform WHOIS and RDAP domain registration intelligence lookup."""
    _run_scan_sync(target, modules=["WHOIS"], export_json=export)

@app.command()
def subdomains(target: str = typer.Argument(..., help="Target domain"), export: Optional[str] = typer.Option(None, "-o")):
    """Enumerate public subdomains across 10+ passive OSINT sources."""
    _run_scan_sync(target, modules=["subdomains"], export_json=export)

@app.command()
def firewall(
    target: str = typer.Argument(..., help="Target URL"),
    active: bool = typer.Option(False, "--active", "-a", help="Send non-destructive active trigger probe"),
    export: Optional[str] = typer.Option(None, "-o")
):
    """Fingerprint Web Application Firewalls (Cloudflare, AWS WAF, Akamai, Imperva, etc.)."""
    _run_scan_sync(target, modules=["Firewall / WAF Detection"], active_mode=active, export_json=export)

@app.command("broken-links")
def broken_links(target: str = typer.Argument(..., help="Target URL"), export: Optional[str] = typer.Option(None, "-o")):
    """High-speed concurrent broken link and resource scanner."""
    _run_scan_sync(target, modules=["Broken Links"], export_json=export)

@app.command()
def emails(target: str = typer.Argument(..., help="Target URL"), export: Optional[str] = typer.Option(None, "-o")):
    """Extract public email addresses and contact information from website assets."""
    _run_scan_sync(target, modules=["emails"], export_json=export)

@app.command()
def javascript(target: str = typer.Argument(..., help="Target URL"), export: Optional[str] = typer.Option(None, "-o")):
    """Analyze JavaScript bundles for exposed APIs, hardcoded secrets, and source maps."""
    _run_scan_sync(target, modules=["javascript"], export_json=export)

@app.command()
def robots(target: str = typer.Argument(..., help="Target URL"), export: Optional[str] = typer.Option(None, "-o")):
    """Parse and audit robots.txt for sensitive hidden directories."""
    _run_scan_sync(target, modules=["robots"], export_json=export)

@app.command()
def sitemap(target: str = typer.Argument(..., help="Target URL"), export: Optional[str] = typer.Option(None, "-o")):
    """Discover and parse sitemap.xml endpoints."""
    _run_scan_sync(target, modules=["sitemap"], export_json=export)

@app.command()
def securitytxt(target: str = typer.Argument(..., help="Target URL"), export: Optional[str] = typer.Option(None, "-o")):
    """Audit RFC 9116 security.txt policy file."""
    _run_scan_sync(target, modules=["securitytxt"], export_json=export)

@app.command()
def shodan(target: str = typer.Argument(..., help="Target host or domain"), export: Optional[str] = typer.Option(None, "-o")):
    """Query Shodan OSINT for open ports, banners, and known CVEs."""
    _run_scan_sync(target, modules=["Shodan Intelligence"], export_json=export)

@app.command()
def ipinfo(target: str = typer.Argument(..., help="Target host or IP"), export: Optional[str] = typer.Option(None, "-o")):
    """Gather IP geolocation, ASN, and hosting provider metadata."""
    _run_scan_sync(target, modules=["Server Location (IPInfo)"], export_json=export)

@app.command()
def csp(target: str = typer.Argument(..., help="Target URL"), export: Optional[str] = typer.Option(None, "-o")):
    """Deep audit of Content-Security-Policy rules and directives."""
    _run_scan_sync(target, modules=["Content Security Policy"], export_json=export)

@app.command()
def methods(target: str = typer.Argument(..., help="Target URL"), export: Optional[str] = typer.Option(None, "-o")):
    """Discover enabled HTTP methods (OPTIONS, TRACE, WebDAV)."""
    _run_scan_sync(target, modules=["HTTP Methods"], export_json=export)

@app.command()
def redirects(target: str = typer.Argument(..., help="Target URL"), export: Optional[str] = typer.Option(None, "-o")):
    """Inspect HTTP redirect chains and final destination status."""
    _run_scan_sync(target, modules=["Redirects"], export_json=export)

@app.command()
def wayback(target: str = typer.Argument(..., help="Target domain"), export: Optional[str] = typer.Option(None, "-o")):
    """Retrieve historical archived URLs from Wayback Machine CDX API."""
    _run_scan_sync(target, modules=["wayback"], export_json=export)

# ==========================================================
# Database & History Commands
# ==========================================================

@app.command()
def history(limit: int = typer.Option(25, "--limit", "-n", help="Number of past scans to display")):
    """
    List past scan reports indexed in the SQLite database.
    """
    scans = asyncio.run(database.list_scans(limit=limit))
    if not scans:
        console.print("[yellow]No past scans found in database.[/yellow]")
        return

    table = Table(title="Past Scan History", header_style="bold cyan")
    table.add_column("ID", justify="right", style="cyan")
    table.add_column("Target", style="bold white")
    table.add_column("Grade", justify="center")
    table.add_column("Score", justify="right")
    table.add_column("Duration", justify="right")
    table.add_column("Timestamp", style="dim")

    for s in scans:
        grade = s.get("grade") or "N/A"
        grade_style = "bold green" if "A" in grade else ("bold yellow" if "B" in grade or "C" in grade else "bold red")
        table.add_row(
            str(s.get("id")),
            s.get("target"),
            f"[{grade_style}]{grade}[/{grade_style}]",
            f"{s.get('total_score', 0)}/{s.get('max_score', 0)}",
            f"{s.get('duration', 0.0):.1f}s",
            s.get("timestamp", "")[:19].replace("T", " ")
        )

    console.print(table)
    console.print(f"[dim]Total records shown: {len(scans)}[/dim]")

@app.command("show-scan")
def show_scan(scan_id: int = typer.Argument(..., help="Scan ID from database history")):
    """
    Display summary findings of a past scan from the SQLite database.
    """
    scan_entry = asyncio.run(database.get_scan(scan_id))
    if not scan_entry:
        console.print(f"[red][!] Scan ID {scan_id} not found in database.[/red]")
        raise typer.Exit(code=1)

    rep = scan_entry.get("report", {})
    console.rule(f"[bold cyan]Scan #{scan_id}: {scan_entry.get('target')}[/bold cyan]")
    console.print(f"[bold]Grade    :[/bold] {rep.get('grade', 'N/A')}")
    console.print(f"[bold]Score    :[/bold] {rep.get('total_score')}/{rep.get('max_potential_score')}")
    console.print(f"[bold]Timestamp:[/bold] {scan_entry.get('timestamp')}")
    
    table = Table(title="Module Scores", header_style="bold green")
    table.add_column("Module")
    table.add_column("Score", justify="right")
    table.add_column("Description")

    for m_name, m_data in rep.get("modules", {}).items():
        table.add_row(m_name, f"{m_data.get('score')}/{m_data.get('max_score')}", m_data.get("description", ""))

    console.print(table)

@app.command()
def export(
    scan_id: int = typer.Argument(..., help="Scan ID from database to export"),
    json_file: Optional[str] = typer.Option(None, "--json", "-j", help="Output JSON path"),
    pdf_file: Optional[str] = typer.Option(None, "--pdf", "-p", help="Output PDF path"),
    csv_file: Optional[str] = typer.Option(None, "--csv", "-c", help="Output CSV path")
):
    """
    Export a past scan from database to JSON, PDF, or CSV.
    """
    scan_entry = asyncio.run(database.get_scan(scan_id))
    if not scan_entry:
        console.print(f"[red][!] Scan ID {scan_id} not found.[/red]")
        raise typer.Exit(code=1)

    report_dict = scan_entry.get("report", {})
    if json_file:
        import json
        with open(json_file, "w", encoding="utf-8") as f:
            f.write(json.dumps(report_dict, indent=4))
        console.print(f"[green][✓] JSON exported to {json_file}[/green]")

    if csv_file:
        export_to_csv(report_dict, csv_file)
        console.print(f"[green][✓] CSV exported to {csv_file}[/green]")

    if pdf_file:
        success = export_to_pdf(report_dict, pdf_file)
        if success:
            console.print(f"[green][✓] PDF exported to {pdf_file}[/green]")
        else:
            console.print(f"[red][!] PDF generation failed.[/red]")

@app.command()
def list_modules():
    """
    List all dynamically loaded scanning modules and their CLI shortcuts.
    """
    table = Table(title="Available Recon Modules & CLI Commands", header_style="bold cyan")
    table.add_column("Module Name", style="cyan")
    table.add_column("Category", style="green")
    table.add_column("CLI Command", style="bold white")
    
    loaded = load_modules()
    
    # Map module name to CLI shortcut
    cli_map = {
        "DNS": "octorecon dns <target>",
        "SSL": "octorecon ssl <target>",
        "Headers": "octorecon headers <target>",
        "Cookies": "octorecon cookies <target>",
        "Technology": "octorecon tech <target>",
        "WHOIS": "octorecon whois <target>",
        "subdomains": "octorecon subdomains <target>",
        "Firewall / WAF Detection": "octorecon firewall <target>",
        "Broken Links": "octorecon broken-links <target>",
        "emails": "octorecon emails <target>",
        "javascript": "octorecon javascript <target>",
        "robots": "octorecon robots <target>",
        "sitemap": "octorecon sitemap <target>",
        "securitytxt": "octorecon securitytxt <target>",
        "Shodan Intelligence": "octorecon shodan <target>",
        "Server Location (IPInfo)": "octorecon ipinfo <target>",
        "Content Security Policy": "octorecon csp <target>",
        "HTTP Methods": "octorecon methods <target>",
        "Redirects": "octorecon redirects <target>",
        "wayback": "octorecon wayback <target>",
    }

    for m in loaded:
        cmd_hint = cli_map.get(m.name, f"octorecon module '{m.name}' <target>")
        table.add_row(m.name, m.category, cmd_hint)
        
    console.print(table)
    console.print(f"\n[bold green]Total Modules Loaded: {len(loaded)}[/bold green]")
    console.print("[dim]Tip: You can run any module via [bold]octorecon module <name> <target>[/bold] or its dedicated CLI shortcut.[/dim]")

@app.command()
def web(
    port: int = typer.Option(WEB_PORT, help="Port to run the web server on"),
    host: str = typer.Option(WEB_HOST, help="Host IP")
):
    """
    Start the OctoRecon Web Dashboard.
    """
    import uvicorn
    console.print(f"[bold green]Starting Web Dashboard on http://{host}:{port}[/bold green]")
    uvicorn.run("web.server:app", host=host, port=port, reload=True)

if __name__ == "__main__":
    app()
