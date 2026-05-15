from __future__ import annotations

import json
import os
import shutil
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from uuid import uuid4

from fastapi import FastAPI, File, HTTPException, Query, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from app.scanner import SCAN_LOG_FILE, is_supported_file, ml_stack_status, scan_file, write_scan_event

CLOUD_UPLOAD_DIR = Path(os.environ.get("CLOUD_UPLOAD_DIR", Path(__file__).resolve().parent / "uploads"))
STAGING_DIR = CLOUD_UPLOAD_DIR
MAX_FILE_SIZE_BYTES = 1024 * 1024 * 1024  # 1 GB
SCAN_RESULTS: dict[str, dict[str, Any]] = {}
APP_STARTED_AT = datetime.now(timezone.utc)
SESSION_APPROVE_MARKER = ".approved"
SESSION_REJECT_MARKER = ".rejected"
TERMINAL_POST_ACTIONS = {"approved_via_result_page", "rejected_via_result_page", "deleted"}

app = FastAPI(title="CyberShield Cloud Scanner API", version="1.0.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


def ensure_staging_dir() -> None:
    CLOUD_UPLOAD_DIR.mkdir(parents=True, exist_ok=True)


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


def overall_result_for(payload: dict[str, Any] | None) -> str:
    data = payload or {}
    suffix = Path(str(data.get("file_name") or data.get("path") or "")).suffix.lower()
    explicit = str(data.get("overall_result", "") or "")
    predicted_label = str(data.get("predicted_label", "") or "").strip().lower()
    decision = str(data.get("decision", "") or "").upper()
    engine = str(data.get("engine", "") or "").strip().lower()
    scanner_warning = str(data.get("scanner_warning", "") or "")
    fused_risk = data.get("fused_risk")
    stego_threshold = data.get("stego_threshold")
    stego_threshold = stego_threshold if isinstance(stego_threshold, (int, float)) else 0.70
    reasons = [str(reason).lower() for reason in data.get("reasons", []) if reason]

    if decision == "BLOCKED":
        return "Malicious"
    if isinstance(fused_risk, (int, float)) and fused_risk >= stego_threshold:
        return "Suspicious"
    if predicted_label == "stego":
        return "Suspicious"
    if decision in {"STEGO", "PENDING", "IGNORED"}:
        return "Suspicious"
    if predicted_label == "cover":
        return "Safe"
    if suffix in {".jpg", ".jpeg", ".jfif", ".png", ".bmp", ".gif", ".tif", ".tiff", ".webp"} and engine != "stg-ml":
        return "Suspicious"
    if scanner_warning or (engine == "heuristic" and any("could not inspect" in reason for reason in reasons)):
        return "Suspicious"
    if explicit in {"Safe", "Suspicious", "Malicious"}:
        return explicit
    return "Safe"


def decision_to_result(decision: str) -> str:
    return overall_result_for({"decision": decision})


def parse_event_ts(value: Any) -> datetime | None:
    if not value:
        return None
    try:
        return datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except Exception:
        return None


def process_staged_file(target_path: Path) -> dict[str, Any]:
    try:
        scan_result = scan_file(target_path, log_event=False)
        scan_result["source"] = "cloud-upload"
        write_scan_event(scan_result)
    except Exception as exc:
        scan_result = {
            "decision": "UNCERTAIN",
            "engine": "none",
            "fused_risk": 0.5,
            "reasons": [],
            "scanner_warning": str(exc),
            "source": "cloud-upload",
        }

    overall_result = overall_result_for(scan_result)
    payload = {
        "status": "completed",
        "file_name": target_path.name,
        "staging_path": str(target_path),
        "size_bytes": target_path.stat().st_size if target_path.exists() else 0,
        "scan_result": scan_result,
        "overall_result": overall_result,
        "source": "cloud-upload",
        "ts": str(scan_result.get("ts") or datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")),
    }
    SCAN_RESULTS[target_path.name] = payload
    return payload


def start_background_scan(target_path: Path, size_bytes: int) -> dict[str, Any]:
    submitted_at = datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")
    payload = {
        "status": "processing",
        "file_name": target_path.name,
        "staging_path": str(target_path),
        "size_bytes": size_bytes,
        "scan_result": None,
        "overall_result": None,
        "source": "cloud-upload",
        "message": "Upload received by backend. Cloud scanner is processing the file.",
        "ts": submitted_at,
    }
    SCAN_RESULTS[target_path.name] = payload

    def _worker() -> None:
        try:
            process_staged_file(target_path)
        except Exception as exc:
            SCAN_RESULTS[target_path.name] = {
                "status": "failed",
                "file_name": target_path.name,
                "staging_path": str(target_path),
                "size_bytes": size_bytes,
                "scan_result": {
                    "decision": "UNCERTAIN",
                    "engine": "none",
                    "fused_risk": 0.5,
                    "reasons": [],
                    "scanner_warning": str(exc),
                },
                "overall_result": "Suspicious",
                "source": "cloud-upload",
                "ts": datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z"),
            }

    threading.Thread(target=_worker, name=f"cloud-scan-{target_path.name}", daemon=True).start()
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
            event["overall_result"] = overall_result_for(event)
            events.append(event)

    events.sort(key=lambda item: str(item.get("ts", "")), reverse=True)
    return events[:limit]


def event_scan_key(event: dict[str, Any]) -> str:
    file_name = Path(str(event.get("file_name") or event.get("path") or "")).name
    path = str(event.get("path") or "").lower()
    return f"{file_name.lower()}|{path}"


def result_payload_from_log(event: dict[str, Any]) -> dict[str, Any]:
    safe_name = Path(str(event.get("file_name", ""))).name
    return {
        "status": "completed",
        "file_name": safe_name,
        "staging_path": str(STAGING_DIR / safe_name),
        "size_bytes": 0,
        "scan_result": event,
        "overall_result": overall_result_for(event),
        "source": event.get("source") or "download-monitor",
        "ts": str(event.get("ts") or datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")),
    }


def get_latest_active_result() -> dict[str, Any] | None:
    if not SCAN_RESULTS:
        return None
    items = [dict(item) for item in SCAN_RESULTS.values()]
    items.sort(key=lambda item: str(item.get("ts", "")), reverse=True)
    return items[0] if items else None


def get_latest_log_event(current_session_only: bool = False) -> dict[str, Any] | None:
    items = read_scan_logs(limit=500)
    if current_session_only:
        items = [item for item in items if (parse_event_ts(item.get("ts")) or datetime.min.replace(tzinfo=timezone.utc)) >= APP_STARTED_AT]
    terminal_keys: set[str] = set()
    for item in items:
        key = event_scan_key(item)
        if key in terminal_keys:
            continue
        if str(item.get("post_action", "")) in TERMINAL_POST_ACTIONS:
            terminal_keys.add(key)
            continue
        return item
    return None


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
        latest_match["overall_result"] = overall_result_for(latest_match)
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

    raise HTTPException(status_code=404, detail="File not found in backend storage")


def resolve_session_dir(file_path: Path | None) -> Path | None:
    if file_path is None:
        return None
    normalized = file_path.resolve()
    parent = normalized.parent
    if parent.name in {"in", "out"} and parent.parent.exists():
        session_dir = parent.parent
        if (session_dir / "sandbox.wsb").exists():
            return session_dir
    return None


def resolve_logged_session_dir(file_name: str) -> Path | None:
    logged_event = find_logged_event(file_name)
    logged_path = logged_event.get("path") if logged_event else None
    if not logged_path:
        return None
    return resolve_session_dir(Path(str(logged_path)))


def log_follow_up_event(file_name: str, action: str, message: str) -> None:
    latest = find_logged_event(file_name)
    if not latest:
        return

    payload = dict(latest)
    payload["post_action"] = action
    payload["message"] = message
    payload["ts"] = datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")
    write_scan_event(payload)


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
        "mode": "cloud-upload",
        "upload_dir": str(CLOUD_UPLOAD_DIR),
        "auto_scan_requires_downloads_to_target_staging": False,
        "message": (
            "Frontend uploads are sent to this backend. The backend stores each file, "
            "runs the scanner, and returns results through the API."
        ),
    }


@app.post("/api/scan/upload")
async def upload_to_sandbox(file: UploadFile = File(...)) -> dict[str, Any]:
    ensure_staging_dir()

    if not file.filename:
        raise HTTPException(status_code=400, detail="Missing filename")

    if not is_supported_file(file.filename):
        await file.close()
        return {
            "status": "ignored",
            "file_name": Path(file.filename).name,
            "source": "cloud-upload",
            "message": "Unsupported file type. Only image files and .exe files are processed.",
            "ts": datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z"),
        }

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

    return start_background_scan(target_path, total)


@app.get("/api/scan/results/{file_name}")
def get_scan_result(file_name: str) -> dict[str, Any]:
    safe_name = Path(file_name).name
    record = SCAN_RESULTS.get(safe_name)
    logged_event = find_logged_event(safe_name)

    if logged_event and str(logged_event.get("post_action", "")) not in TERMINAL_POST_ACTIONS:
        logged_ts = parse_event_ts(logged_event.get("ts"))
        record_ts = parse_event_ts(record.get("ts")) if record else None
        if not record or str(record.get("status") or "") in {"queued", "processing"} or not record_ts or (logged_ts and logged_ts >= record_ts):
            return result_payload_from_log(logged_event)

    if record:
        return record

    raise HTTPException(status_code=404, detail="No active scan result found for this file")


@app.get("/api/scan/logs")
def get_scan_logs(limit: int = Query(default=50, ge=1, le=500)) -> dict[str, Any]:
    items = read_scan_logs(limit)
    return {"count": len(items), "items": items}


@app.get("/api/scan/latest")
def get_latest_scan_result() -> dict[str, Any]:
    latest_log = get_latest_log_event(current_session_only=True)
    latest_active = get_latest_active_result()

    candidates: list[dict[str, Any]] = []
    if latest_log:
        candidates.append(result_payload_from_log(latest_log))
    if latest_active:
        candidates.append(latest_active)

    if not candidates:
        raise HTTPException(status_code=404, detail="No scan results available in this session")

    candidates.sort(key=lambda item: str(item.get("ts", "")), reverse=True)
    return candidates[0]


@app.get("/api/scan/files/{file_name}")
def download_file(file_name: str) -> FileResponse:
    file_path = resolve_managed_file(file_name)
    return FileResponse(path=file_path, filename=file_path.name, media_type="application/octet-stream")


@app.post("/api/scan/files/{file_name}/approve")
def approve_file(file_name: str, restore_to_downloads: bool = Query(default=True)) -> dict[str, str]:
    safe_name = Path(file_name).name
    file_path = resolve_managed_file(safe_name)
    session_dir = resolve_session_dir(file_path)
    if not session_dir:
        raise HTTPException(status_code=400, detail="This file is not in an active sandbox session")

    try:
        if restore_to_downloads:
            out_dir = session_dir / "out"
            out_dir.mkdir(parents=True, exist_ok=True)
            approved_path = out_dir / safe_name
            if file_path.resolve() != approved_path.resolve():
                if approved_path.exists():
                    approved_path.unlink()
                shutil.move(str(file_path), str(approved_path))
        elif file_path.exists():
            file_path.unlink()
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Approve failed: {exc}")

    (session_dir / SESSION_APPROVE_MARKER).write_text("approved\n", encoding="utf-8")
    message = (
        "File was approved and queued to be restored to Downloads."
        if restore_to_downloads
        else "File was saved locally, removed from sandbox, and approved."
    )
    log_follow_up_event(safe_name, "approved_via_result_page", message)
    SCAN_RESULTS.pop(safe_name, None)
    return {"status": "approved", "file_name": safe_name}


@app.post("/api/scan/files/{file_name}/reject")
def reject_file(file_name: str) -> dict[str, str]:
    safe_name = Path(file_name).name
    file_path: Path | None = None
    try:
        file_path = resolve_managed_file(safe_name)
    except HTTPException as exc:
        if exc.status_code != 404:
            raise

    session_dir = resolve_session_dir(file_path) or resolve_logged_session_dir(safe_name)
    if not session_dir:
        raise HTTPException(status_code=400, detail="This file is not in an active sandbox session")

    try:
        (session_dir / SESSION_REJECT_MARKER).write_text("rejected\n", encoding="utf-8")
        if file_path and file_path.exists():
            file_path.unlink()
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Reject failed: {exc}")

    log_follow_up_event(safe_name, "rejected_via_result_page", "File was rejected from the Result page and removed from the sandbox.")
    SCAN_RESULTS.pop(safe_name, None)
    return {"status": "rejected", "file_name": safe_name}


@app.delete("/api/scan/files/{file_name}")
def delete_file(file_name: str) -> dict[str, str]:
    safe_name = Path(file_name).name
    file_path = resolve_managed_file(safe_name)
    session_dir = resolve_session_dir(file_path) or resolve_logged_session_dir(safe_name)

    try:
        if session_dir:
            (session_dir / SESSION_REJECT_MARKER).write_text("rejected\n", encoding="utf-8")
        file_path.unlink()
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Delete failed: {exc}")

    SCAN_RESULTS.pop(file_path.name, None)
    message = (
        "File was deleted from the Result page and the sandbox session was closed."
        if session_dir
        else "Backend copy was deleted from the Result page."
    )
    log_follow_up_event(safe_name, "deleted", message)
    return {"status": "deleted", "file_name": file_path.name}
