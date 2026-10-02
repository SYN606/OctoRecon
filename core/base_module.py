from abc import ABC, abstractmethod
from typing import TYPE_CHECKING, Any, Dict, Optional
from urllib.parse import urljoin
import asyncio
from rich.table import Table

from core.schemas import ModuleResult

if TYPE_CHECKING:
    from core.scanner import Scanner

class BaseModule(ABC):
    name: str = "Base Module"
    description: str = ""
    category: str = "General"
    version: str = "1.0.0"
    max_score: int = 20
    timeout: int = 15
    retries: int = 2

    def __init__(self):
        self.score = self.max_score

    # --------------------------------------------------
    # V1 Backward Compatibility Layer
    # --------------------------------------------------
    
    def info(self, scanner: 'Scanner', message: str):
        if hasattr(scanner, "logger"):
            scanner.logger.info(f"[{self.name}] {message}")

    def warning(self, scanner: 'Scanner', message: str):
        if hasattr(scanner, "logger"):
            scanner.logger.warning(f"[{self.name}] {message}")

    def error(self, scanner: 'Scanner', message: str):
        if hasattr(scanner, "logger"):
            scanner.logger.error(f"[{self.name}] {message}")

    def make_url(self, scanner: 'Scanner', path: str) -> str:
        return urljoin(scanner.target, path)

    async def get(self, scanner: 'Scanner', url: str, **kwargs) -> Any:
        kwargs.setdefault("timeout", self.timeout)
        last_error = None
        for _ in range(self.retries):
            try:
                return await scanner.client.get(url, **kwargs)
            except Exception as e:
                last_error = e
                await asyncio.sleep(0.5)
        raise last_error

    async def head(self, scanner: 'Scanner', url: str, **kwargs) -> Any:
        kwargs.setdefault("timeout", self.timeout)
        return await scanner.client.head(url, **kwargs)

    def deduct(self, value: int):
        self.score = max(0, self.score - value)

    def reset_score(self):
        self.score = self.max_score

    def add_report(self, scanner: 'Scanner', report: Dict[str, Any]):
        """Legacy V1 Method: Converts V1 dict reports into V2 Pydantic ModuleResults."""
        res = ModuleResult(
            module_name=self.name,
            score=report.get("score", self.score),
            max_score=report.get("max_score", self.max_score),
            description=report.get("description", ""),
            data=report.get("rows", []) or ([{"Content": report.get("content")}] if "content" in report else [])
        )
        scanner.report.modules[self.name] = res

    def print_table(self, scanner: 'Scanner', title: str, columns: list, rows: list, limit=None, footer=None):
        pass # UI handled completely by scanner V2 now

    def print_kv_table(self, scanner: 'Scanner', title: str, data: dict):
        pass # UI handled completely by scanner V2 now

    def print_status(self, scanner: 'Scanner', title: str, value: str):
        pass # UI handled completely by scanner V2 now

    def print_empty(self, scanner: 'Scanner', title: str, message: str = "No data found."):
        pass # UI handled completely by scanner V2 now

    # --------------------------------------------------
    # Module Execution
    # --------------------------------------------------

    @abstractmethod
    async def run(self, scanner: 'Scanner') -> Optional[ModuleResult]:
        """
        Execute module. 
        V2 modules should return a ModuleResult directly.
        V1 modules can continue calling self.add_report() and returning None.
        """
        raise NotImplementedError