from fastapi import FastAPI, HTTPException, Response, BackgroundTasks
from fastapi.responses import HTMLResponse, StreamingResponse
from pydantic import BaseModel
import os
import io
import json
import asyncio
from typing import List, Optional, Dict, Any

from core.scanner import Scanner
from core.module_loader import load_modules
from core.exporter import export_to_csv, export_to_pdf
import database

app = FastAPI(title="OctoRecon Web Dashboard")

# In-memory progress tracker for live scans
active_scans_progress: Dict[str, Dict[str, Any]] = {}

class ScanRequest(BaseModel):
    target: str
    modules: Optional[List[str]] = None
    active_mode: bool = False

@app.on_event("startup")
async def startup_event():
    await database.init_db()

@app.get("/", response_class=HTMLResponse)
async def index():
    """Serves the main web dashboard."""
    html_path = os.path.join(os.path.dirname(__file__), "templates", "index.html")
    with open(html_path, "r", encoding="utf-8") as f:
        return f.read()

@app.get("/api/modules")
async def get_modules():
    """Returns the list of dynamically loaded modules."""
    modules = load_modules()
    return [{"name": m.name, "category": m.category} for m in modules]

@app.get("/api/scans")
async def get_scans(limit: int = 50, offset: int = 0):
    """Returns past scans from the SQLite database."""
    scans = await database.list_scans(limit=limit, offset=offset)
    return scans

@app.get("/api/scans/{scan_id}")
async def get_scan_report(scan_id: int):
    """Retrieves a specific scan report from the SQLite database."""
    scan = await database.get_scan(scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    return scan.get("report", {})

@app.delete("/api/scans/{scan_id}")
async def delete_scan_entry(scan_id: int):
    """Deletes a scan entry from the SQLite database."""
    deleted = await database.delete_scan(scan_id)
    if not deleted:
        raise HTTPException(status_code=404, detail="Scan not found or already deleted")
    return {"status": "success", "message": f"Scan {scan_id} deleted."}

@app.get("/api/export/{scan_id}/csv")
async def export_scan_csv(scan_id: int):
    """Exports a past scan report to CSV format."""
    scan = await database.get_scan(scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    report = scan.get("report", {})
    csv_text = export_to_csv(report)
    target_clean = scan.get("target", "scan").replace("https://", "").replace("http://", "").replace("/", "_")
    return Response(
        content=csv_text,
        media_type="text/csv",
        headers={"Content-Disposition": f"attachment; filename=octorecon_{target_clean}_{scan_id}.csv"}
    )

@app.get("/api/export/{scan_id}/pdf")
async def export_scan_pdf(scan_id: int):
    """Exports a past scan report to a PDF document."""
    scan = await database.get_scan(scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    report = scan.get("report", {})
    
    # Generate in-memory PDF
    pdf_buffer = io.BytesIO()
    success = export_to_pdf(report, pdf_buffer)
    if not success:
        raise HTTPException(status_code=500, detail="Failed to generate PDF report")
    
    target_clean = scan.get("target", "scan").replace("https://", "").replace("http://", "").replace("/", "_")
    return Response(
        content=pdf_buffer.getvalue(),
        media_type="application/pdf",
        headers={"Content-Disposition": f"attachment; filename=octorecon_{target_clean}_{scan_id}.pdf"}
    )

@app.post("/api/scan")
async def start_scan(request: ScanRequest):
    """Executes the OctoRecon scanner and returns the JSON report with database indexing."""
    target_clean = request.target.strip()
    scan_key = target_clean
    active_scans_progress[scan_key] = {"percent": 0, "status": "Connecting...", "module": ""}

    def progress_callback(prog_data):
        active_scans_progress[scan_key] = {
            "percent": prog_data.get("percent", 0),
            "module": prog_data.get("module", ""),
            "status": f"Scanned {prog_data.get('completed', 0)}/{prog_data.get('total', 0)} modules"
        }

    scanner = Scanner(
        target=target_clean,
        selected_modules=request.modules,
        quiet=True,
        active_mode=request.active_mode,
        on_progress=progress_callback
    )

    connected = await scanner.connect()
    if not connected:
        active_scans_progress.pop(scan_key, None)
        raise HTTPException(
            status_code=400,
            detail=f"Failed to connect to '{request.target}'. Please check if the host is valid and reachable."
        )

    await scanner.run_modules()
    await scanner.finish()
    active_scans_progress.pop(scan_key, None)

    report_dict = scanner.report.model_dump()
    report_dict["scan_id"] = scanner.scan_id
    return report_dict

@app.get("/api/scan/progress")
async def scan_progress_stream():
    """SSE endpoint to stream current scan progress."""
    async def event_generator():
        while True:
            if active_scans_progress:
                data = json.dumps(active_scans_progress)
                yield f"data: {data}\n\n"
            else:
                yield "data: {}\n\n"
            await asyncio.sleep(0.5)
            
    return StreamingResponse(event_generator(), media_type="text/event-stream")
