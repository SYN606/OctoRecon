"""
Base Module
All scanner modules inherit from this class.
AUTHOR : 0ctopu3
VERSION : 1.0.0
"""

from abc import ABC, abstractmethod
from urllib.parse import urljoin
import asyncio

from rich.table import Table


class BaseModule(ABC):

    name = "Base Module"
    description = ""
    version = "1.0.0"

    max_score = 20
    timeout = 15
    retries = 2

    def __init__(self):
        self.score = self.max_score

    # --------------------------------------------------
    # Logging Helpers
    # --------------------------------------------------

    def info(self, scanner, message):

        if hasattr(scanner, "logger"):
            scanner.logger.info(f"[{self.name}] {message}")

    def warning(self, scanner, message):

        if hasattr(scanner, "logger"):
            scanner.logger.warning(f"[{self.name}] {message}")

    def error(self, scanner, message):

        if hasattr(scanner, "logger"):
            scanner.logger.error(f"[{self.name}] {message}")

    # --------------------------------------------------
    # URL Helper
    # --------------------------------------------------

    def make_url(self, scanner, path):

        return urljoin(scanner.target, path)

    # --------------------------------------------------
    # HTTP Helpers
    # --------------------------------------------------

    async def get(self, scanner, url, **kwargs):

        kwargs.setdefault("timeout", self.timeout)

        last_error = None

        for _ in range(self.retries):

            try:
                return await scanner.client.get(url, **kwargs)

            except Exception as e:

                last_error = e
                await asyncio.sleep(0.5)

        raise last_error

    async def head(self, scanner, url, **kwargs):

        kwargs.setdefault("timeout", self.timeout)

        return await scanner.client.head(
            url,
            **kwargs
        )

    # --------------------------------------------------
    # Score
    # --------------------------------------------------

    def deduct(self, value):

        self.score -= value

        if self.score < 0:
            self.score = 0

    def reset_score(self):

        self.score = self.max_score

    # --------------------------------------------------
    # Report Helper
    # --------------------------------------------------

    def add_report(self, scanner, report):

        scanner.report.add_module(
            self.name,
            report
        )

    # --------------------------------------------------
    # Console Helpers
    # --------------------------------------------------

    def print_table(
        self,
        scanner,
        title,
        columns,
        rows,
        limit=None,
        footer=None,
    ):

        total_rows = len(rows)

        if limit is not None:
            display_rows = rows[:limit]
        else:
            display_rows = rows

        table = Table(title=title)

        for column in columns:

            table.add_column(
                str(column),
                style="cyan",
                overflow="fold",
            )

        if not display_rows:

            table.add_row(
                *["-" for _ in columns]
            )

        else:

            for row in display_rows:

                if isinstance(row, dict):

                    table.add_row(
                        *[
                            str(row.get(col, "-"))
                            for col in columns
                        ]
                    )

                else:

                    table.add_row(
                        *[
                            str(value)
                            for value in row
                        ]
                    )

        scanner.console.print(table)

        if limit is not None and total_rows > limit:

            scanner.console.print(
                f"[yellow]Showing {min(limit, total_rows)} of {total_rows} results.[/yellow]"
            )

        if footer:

            scanner.console.print(
                f"[cyan]{footer}[/cyan]"
            )

    def print_kv_table(
        self,
        scanner,
        title,
        data,
    ):

        table = Table(title=title)

        table.add_column(
            "Property",
            style="cyan",
        )

        table.add_column(
            "Value",
            style="green",
            overflow="fold",
        )

        for key, value in data.items():

            table.add_row(
                str(key),
                str(value),
            )

        scanner.console.print(table)

    def print_status(
        self,
        scanner,
        title,
        value,
    ):

        self.print_kv_table(
            scanner,
            title,
            {
                "Status": value,
            },
        )

    def print_empty(
        self,
        scanner,
        title,
        message="No data found.",
    ):

        scanner.console.print(
            f"[yellow]{title}[/yellow]"
        )

        scanner.console.print(
            message
        )

    # --------------------------------------------------
    # Execute
    # --------------------------------------------------

    @abstractmethod
    async def run(self, scanner):
        """
        Execute module.
        """
        raise NotImplementedError