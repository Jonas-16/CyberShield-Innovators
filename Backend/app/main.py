from __future__ import annotations

import json
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from uuid import uuid4

from fastapi import FastAPI, File, HTTPException, Query, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from app.scanner import SCAN_LOG_FILE, ml_stack_status, scan_file

STAGING_DIR = Path(os.environ.get("SANDBOX_STAGING_DIR", r"D:\\Download"))
MAX_FILE_SIZE_BYTES = 1024 * 1024 * 1024  # 1 GB
SCAN_RESULTS: dict[str, dict[str, Any]] = {}
APP_STARTED_AT = datetime.now(timezone.utc)

app = FastAPI(title="Sandbox Upload API", version="1.0.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


def ensure_staging_dir() -> None:
    STAGING_DIR.mkdir(parents=True, exist_ok=True)


def safe_unique_path(original_name: str) -> Path:
    file_name = Path(original_name).name or "upload.bin"
    target = STAGING_DIR / file_name
    if not target.exists():
        return target

    stem = Path(file_name).stem
    suffix = Path(file_name).suffix
    return STAGING_DIR / f"{stem}_{uuid4().hex[:8]}{suffix}"


def staging_path_for(file_name: str) -> Path:
    safe_name = Path(file_name).name
    if not safe_name:
        raise HTTPException(status_code=400, detail="Invalid file name")
    return STAGING_DIR / safe_name


def decision_to_result(decision: str) -> str:
    if decision == "BLOCKED":
        return "Malicious"
    if decision == "UNCERTAIN":
        return "Suspicious"
    return "Safe"


def parse_event_ts(value: Any) -> datetime | None:
    if not value:
        return None
    try:
        return datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except Exception:
        return None


def process_staged_file(target_path: Path) -> dict[str, Any]:
    try:
        scan_result = scan_file(target_path)
    except Exception as exc:
        scan_result = {
            "decision": "UNCERTAIN",
            "engine": "none",
            "fused_risk": 0.5,
            "reasons": [],
            "scanner_warning": str(exc),
        }

    overall_result = decision_to_result(scan_result.get("decision", "UNCERTAIN"))
    payload = {
        "status": "queued",
        "file_name": target_path.name,
        "staging_path": str(target_path),
        "size_bytes": target_path.stat().st_size if target_path.exists() else 0,
        "scan_result": scan_result,
        "overall_result": overall_result,
    }
    SCAN_RESULTS[target_path.name] = payload
    return payload


def read_scan_logs(limit: int) -> list[dict[str, Any]]:
    if not SCAN_LOG_FILE.exists():
        return []

    events: list[dict[str, Any]] = []
    with SCAN_LOG_FILE.open("r", encoding="utf-8") as handle:
        for line in handle:
            line = line.strip()
            if not line:
                continue
            try:
                event = dict(json.loads(line))
            except Exception:
                continue
            event["overall_result"] = decision_to_result(str(event.get("decision", "UNCERTAIN")))
            events.append(event)

    events.sort(key=lambda item: str(item.get("ts", "")), reverse=True)
    return events[:limit]


def get_latest_log_event(current_session_only: bool = False) -> dict[str, Any] | None:
    items = read_scan_logs(limit=500)
    if current_session_only:
        items = [item for item in items if (parse_event_ts(item.get("ts")) or datetime.min.replace(tzinfo=timezone.utc)) >= APP_STARTED_AT]
    if not items:
        return None
    return items[0]


def find_logged_event(file_name: str) -> dict[str, Any] | None:
    safe_name = Path(file_name).name
    if not safe_name or not SCAN_LOG_FILE.exists():
        return None

    latest_match: dict[str, Any] | None = None
    with SCAN_LOG_FILE.open("r", encoding="utf-8") as handle:
        for line in handle:
            line = line.strip()
            if not line:
                continue
            try:
                event = dict(json.loads(line))
            except Exception:
                continue
            if Path(str(event.get("file_name", ""))).name != safe_name:
                continue
            latest_match = event
    if latest_match:
        latest_match["overall_result"] = decision_to_result(str(latest_match.get("decision", "UNCERTAIN")))
    return latest_match


def resolve_managed_file(file_name: str) -> Path:
    safe_name = Path(file_name).name
    if not safe_name:
        raise HTTPException(status_code=400, detail="Invalid file name")

    candidates: list[Path] = []

    staging_candidate = STAGING_DIR / safe_name
    candidates.append(staging_candidate)

    record = SCAN_RESULTS.get(safe_name)
    if record:
        staging_path = record.get("staging_path")
        if staging_path:
            candidates.append(Path(str(staging_path)))
        scan_result = record.get("scan_result") or {}
        scan_path = scan_result.get("path")
        if scan_path:
            candidates.append(Path(str(scan_path)))

    logged_event = find_logged_event(safe_name)
    if logged_event:
        logged_path = logged_event.get("path")
        if logged_path:
            candidates.append(Path(str(logged_path)))

    seen: set[str] = set()
    for candidate in candidates:
        candidate_key = str(candidate).lower()
        if candidate_key in seen:
            continue
        seen.add(candidate_key)
        if candidate.exists() and candidate.is_file():
            return candidate

    raise HTTPException(status_code=404, detail="File not found in sandbox")


@app.on_event("startup")
def on_startup() -> None:
    ensure_staging_dir()


@app.get("/api/health")
def health() -> dict[str, str]:
    return {"status": "ok"}


@app.get("/api/scan/ml-status")
def get_ml_status() -> dict[str, Any]:
    return ml_stack_status()


@app.get("/api/scan/config")
def get_scan_config() -> dict[str, Any]:
    return {
        "mode": "staging-folder",
        "staging_dir": str(STAGING_DIR),
        "auto_scan_requires_downloads_to_target_staging": True,
        "message": (
            "Automatic sandboxing only happens when the browser or app downloads directly "
            f"into {STAGING_DIR}."
        ),
    }


@app.post("/api/scan/upload")
async def upload_to_sandbox(file: UploadFile = File(...)) -> dict[str, Any]:
    ensure_staging_dir()

    if not file.filename:
        raise HTTPException(status_code=400, detail="Missing filename")

    target_path = safe_unique_path(file.filename)
    total = 0

    try:
        with target_path.open("wb") as out:
            while True:
                chunk = await file.read(1024 * 1024)
                if not chunk:
                    break
                total += len(chunk)
                if total > MAX_FILE_SIZE_BYTES:
                    raise HTTPException(status_code=413, detail="File too large")
                out.write(chunk)
    except HTTPException:
        if target_path.exists():
            target_path.unlink(missing_ok=True)
        raise
    except Exception as exc:
        if target_path.exists():
            target_path.unlink(missing_ok=True)
        raise HTTPException(status_code=500, detail=f"Upload failed: {exc}")
    finally:
        await file.close()

    payload = process_staged_file(target_path)
    payload["size_bytes"] = total
    SCAN_RESULTS[target_path.name] = payload
    return payload


@app.get("/api/scan/results/{file_name}")
def get_scan_result(file_name: str) -> dict[str, Any]:
    safe_name = Path(file_name).name
    record = SCAN_RESULTS.get(safe_name)
    if not record:
        raise HTTPException(status_code=404, detail="No active scan result found for this file")
    return record


@app.get("/api/scan/logs")
def get_scan_logs(limit: int = Query(default=50, ge=1, le=500)) -> dict[str, Any]:
    items = read_scan_logs(limit)
    return {"count": len(items), "items": items}


@app.get("/api/scan/latest")
def get_latest_scan_result() -> dict[str, Any]:
    latest = get_latest_log_event(current_session_only=True)
    if not latest:
        raise HTTPException(status_code=404, detail="No scan results available in this session")
    return latest


@app.get("/api/scan/files/{file_name}")
def download_file(file_name: str) -> FileResponse:
    file_path = resolve_managed_file(file_name)
    return FileResponse(path=file_path, filename=file_path.name, media_type="application/octet-stream")


@app.delete("/api/scan/files/{file_name}")
def delete_file(file_name: str) -> dict[str, str]:
    file_path = resolve_managed_file(file_name)

    try:
        file_path.unlink()
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Delete failed: {exc}")

    SCAN_RESULTS.pop(file_path.name, None)
    return {"status": "deleted", "file_name": file_path.name}
