"""FastAPI application entrypoint for the HTTP Security Header Scanner."""

import json
import logging
from typing import List
from fastapi import FastAPI, Depends, HTTPException, Request, Response
from fastapi.responses import HTMLResponse, JSONResponse, FileResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy.orm import Session

from .database import get_db, init_db
from .models import ScanRecord
from .schemas import ScanRequest, ScanResponse, ScanSummary
from .scanner import perform_scan, ScannerError

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(name)s: %(message)s")
logger = logging.getLogger("scanner")

app = FastAPI(
    title="HTTP Security Header Scanner",
    description="Defensive cybersecurity tool to analyze, evaluate, and score HTTP security headers and cookies.",
    version="1.0.0"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Initialize database tables on startup
init_db()

# Mount static and template directories if they exist
try:
    app.mount("/static", StaticFiles(directory="static"), name="static")
except Exception:
    logger.warning("Static directory not mounted or missing.")

templates = Jinja2Templates(directory="templates")


@app.get("/", response_class=HTMLResponse)
async def serve_dashboard(request: Request):
    """Renders the cybersecurity SOC dashboard interface."""
    try:
        return templates.TemplateResponse("index.html", {"request": request})
    except Exception:
        return HTMLResponse("<h1>HTTP Security Header Scanner</h1><p>Dashboard template loading...</p>")


@app.post("/api/scan", response_model=ScanResponse)
async def scan_endpoint(payload: ScanRequest, db: Session = Depends(get_db)):
    """
    Scans a user-authorized website URL for HTTP security headers and cookie flags.
    Stores the result in the local SQLite database.
    """
    logger.info(f"Initiating security scan for target: {payload.url}")
    try:
        scan_result = perform_scan(payload.url, db=db)
        return scan_result
    except ValueError as ve:
        logger.warning(f"URL validation error: {ve}")
        raise HTTPException(status_code=400, detail=str(ve))
    except ScannerError as se:
        logger.warning(f"Scanner error during execution: {se}")
        raise HTTPException(status_code=502, detail=str(se))
    except Exception as exc:
        logger.error(f"Unexpected server error during scan: {exc}", exc_info=True)
        raise HTTPException(status_code=500, detail="Internal scanning failure. Please check the target URL.")


@app.get("/api/scans", response_model=List[ScanSummary])
async def list_scans(limit: int = 50, db: Session = Depends(get_db)):
    """Retrieves previous scan history stored in SQLite."""
    records = db.query(ScanRecord).order_by(ScanRecord.timestamp.desc()).limit(limit).all()
    summaries = []
    for r in records:
        summaries.append(ScanSummary(
            id=r.id,
            original_url=r.original_url,
            final_url=r.final_url,
            timestamp=r.timestamp.isoformat() if r.timestamp else "",
            status_code=r.status_code,
            score=r.score,
            max_score=r.max_score,
            is_https=r.final_url.lower().startswith("https://")
        ))
    return summaries


@app.get("/api/scans/{scan_id}", response_model=ScanResponse)
async def get_scan_details(scan_id: str, db: Session = Depends(get_db)):
    """Retrieves full scan results for a specific scan ID."""
    record = db.query(ScanRecord).filter(ScanRecord.id == scan_id).first()
    if not record:
        raise HTTPException(status_code=404, detail=f"Scan record '{scan_id}' was not found.")
    try:
        data = json.loads(record.result_json)
        return data
    except Exception as e:
        logger.error(f"Failed to deserialize scan record {scan_id}: {e}")
        raise HTTPException(status_code=500, detail="Corrupted scan record data.")


@app.get("/api/scans/{scan_id}/json")
async def download_scan_json(scan_id: str, db: Session = Depends(get_db)):
    """Exports raw scan results as an attachment JSON download."""
    record = db.query(ScanRecord).filter(ScanRecord.id == scan_id).first()
    if not record:
        raise HTTPException(status_code=404, detail=f"Scan record '{scan_id}' was not found.")

    headers = {
        "Content-Disposition": f"attachment; filename=security_scan_{scan_id[:8]}.json"
    }
    return Response(
        content=record.result_json,
        media_type="application/json",
        headers=headers
    )
