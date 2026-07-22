"""
OctoRecon
Passive Web Reconnaissance Framework

Author  : 0ct0pu3
Version : 1.0.0
"""

import argparse
import asyncio
import sys

from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from banner import show_banner
from core.validator import URLValidator
from scanner import Scanner
from modules import MODULES

VERSION = "1.0.0"

console = Console()


# ==========================================================
# CLI Scan
# ==========================================================

async def run_scan(
    url: str,
    modules=None,
) -> None:

    show_banner()

    try:
        target = URLValidator.validate(url)

    except Exception as e:

        console.print(
            f"[bold red][!] Invalid URL:[/bold red] {e}"
        )

        sys.exit(1)

    scanner = Scanner(
        target,
        selected_modules=modules,
    )

    connected = await scanner.connect()

    if not connected:

        console.print(
            "[bold red][!] Failed to connect to target.[/bold red]"
        )

        return

    try:

        await scanner.run_modules()

    finally:

        await scanner.finish()


# ==========================================================
# Web Dashboard
# ==========================================================

def start_web() -> None:

    show_banner()

    console.print(
        Panel.fit(
            """[bold yellow]Status      :[/bold yellow] [green]Coming Soon[/green]
[bold yellow]Development :[/bold yellow] [cyan]Under Production[/cyan]
[bold yellow]Current     :[/bold yellow] Please use the CLI version.

[bold green]Example:[/bold green]

  python main.py -u https://example.com
""",
            title="[bold cyan]OctoRecon Web Dashboard[/bold cyan]",
            border_style="cyan",
        )
    )
# ==========================================================
# List Module
# ==========================================================
def list_modules():

    show_banner()

    table = Table(
        title="Available Modules",
        header_style="bold cyan",
    )

    table.add_column("Module", style="cyan", no_wrap=True)
    table.add_column("Slug", style="yellow")
    table.add_column("Category", style="green")
    table.add_column("Description", style="white")

    for module in MODULES:

        slug = getattr(
            module,
            "slug",
            module.name.lower().replace(" ", "-"),
        )

        table.add_row(
            module.name,
            slug,
            getattr(module, "category", "General"),
            getattr(
                module,
                "description",
                "No description available.",
            ),
        )

    console.print(table)

    console.print(
        f"\n[bold green]Total Modules : {len(MODULES)}[/bold green]"
    )
# ==========================================================
# Main
# ==========================================================
 
def build_parser() -> argparse.ArgumentParser:

    parser = argparse.ArgumentParser(
    prog="octorecon",
    add_help=False,
    usage="%(prog)s [-h] [-u URL] [-m MODULE] [--list-modules] [--web] [--version]",
    description=(
        "OctoRecon v1.0.0\n"
        "Passive Web Reconnaissance Framework"
        ),
    formatter_class=argparse.RawDescriptionHelpFormatter,
    epilog="""
Examples:
  octorecon -u https://example.com
  octorecon -u https://example.com -m http-method
  octorecon -u https://example.com -m broken-links,dns
  octorecon --list-modules
""",
)
    parser.add_argument(
        "-h",
        "--help",
        action="help",
        default=argparse.SUPPRESS,
        help="Show help",
    )

    group = parser.add_mutually_exclusive_group()
    group = parser.add_mutually_exclusive_group()

    group.add_argument(
        "-u",
        "--url",
        help="Target URL",
    )

    group.add_argument(
        "-w",
        "--web",
        action="store_true",
        help="Start Web Dashboard (Coming Soon)",
    )

    parser.add_argument(
        "-m",
        "--module",
        action="append",
        metavar="MODULE",
        help="Run specific module(s)",
    )
    parser.add_argument(
        "-l",
        "--list-modules",
        action="store_true",
        help="List available modules",
    )

    parser.add_argument(
        "-v",
        "--version",
        action="version",
        version=f"OctoRecon v{VERSION}",
        help="Show version",
    )

    return parser


def main() -> None:

    parser = build_parser()
    args = parser.parse_args()

    if (
        not args.url
        and not args.web
        and not args.list_modules
    ):
        parser.print_help()
        sys.exit(0)

    if args.web:
        start_web()
        return
    
    if args.list_modules:
        list_modules()
        return

    selected_modules = None

    if args.module:

        selected_modules = []

        for item in args.module:

            for module in item.split(","):

                module = module.strip().lower()

                if module:

                    selected_modules.append(module)

        # Remove duplicates while preserving order
        selected_modules = list(
            dict.fromkeys(selected_modules)
        )

    asyncio.run(
        run_scan(
            args.url,
            selected_modules,
        )
    )


# ==========================================================
# Entry Point
# ==========================================================

if __name__ == "__main__":

    try:

        main()

    except KeyboardInterrupt:

        console.print(
            "\n[bold red][!][/bold red] Scan aborted by user."
        )

        sys.exit(0)

    except Exception as e:

        console.print(
            f"\n[bold red][!] Error:[/bold red] {e}"
        )

        sys.exit(1)