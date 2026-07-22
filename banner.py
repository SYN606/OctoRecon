"""
BANNER
Author : 0ct0pu3
VERSION : 1.0.0
"""
from rich.console import Console

console = Console()

BANNER = r"""

 ██████╗  ██████╗████████╗ ██████╗ ██████╗ ███████╗ ██████╗ ██████╗ ███╗   ██╗
██╔═══██╗██╔════╝╚══██╔══╝██╔═══██╗██╔══██╗██╔════╝██╔════╝██╔═══██╗████╗  ██║
██║   ██║██║        ██║   ██║   ██║██████╔╝█████╗  ██║     ██║   ██║██╔██╗ ██║
██║   ██║██║        ██║   ██║   ██║██╔══██╗██╔══╝  ██║     ██║   ██║██║╚██╗██║
╚██████╔╝╚██████╗   ██║   ╚██████╔╝██║  ██║███████╗╚██████╗╚██████╔╝██║ ╚████║
 ╚═════╝  ╚═════╝   ╚═╝    ╚═════╝ ╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚═════╝ ╚═╝  ╚═══╝

                 Passive Web Reconnaissance Framework

"""

def show_banner():

    console.print(BANNER, style="bold cyan")

    console.print(
        "[bold green]Version[/] : 1.0.0"
    )

    console.print(
        "[bold green]Author[/]  : 0ct0pu3"
    )

    console.rule()