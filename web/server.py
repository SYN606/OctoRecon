from fastapi import FastAPI, HTTPException
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel
import os
from typing import List, Optional

from core.scanner import Scanner
from core.module_loader import load_modules

app = FastAPI(title="OctoRecon Web Dashboard")


class ScanRequest(BaseModel):
    target: str
    modules: Optional[List[str]] = None


@app.get("/", response_class=HTMLResponse)
async def index():
    """Serves the main web dashboard."""
    html_path = os.path.join(os.path.dirname(__file__), "templates",
                             "index.html")
    with open(html_path, "r", encoding="utf-8") as f:
        return f.read()


@app.get("/api/modules")
async def get_modules():
    """Returns the list of dynamically loaded modules."""
    modules = load_modules()
    return [{"name": m.name, "category": m.category} for m in modules]


@app.post("/api/scan")
async def start_scan(request: ScanRequest):
    """Executes the OctoRecon scanner and returns the JSON report."""
    target_clean = request.target.strip()
    print(
        f"[*] [Web] Scan requested for: {target_clean} (Modules: {len(request.modules) if request.modules else 'all'})"
    )

    scanner = Scanner(target=target_clean,
                      selected_modules=request.modules, # type: ignore
                      quiet=True)

    connected = await scanner.connect()
    if not connected:
        print(f"[!] [Web] Connection failed for target: {target_clean}")
        raise HTTPException(
            status_code=400,
            detail=
            f"Failed to connect to '{request.target}'. Please check if the host is valid and reachable."
        )

    await scanner.run_modules()
    await scanner.finish()

    print(
        f"[+] [Web] Scan completed for: {scanner.target} (Grade: {scanner.report.grade})"
    )

    # Return the Pydantic FinalReport dumped to a native dictionary
    return scanner.report.model_dump()
