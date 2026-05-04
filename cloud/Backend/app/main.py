from __future__ import annotations

import json
import os
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from uuid import uuid4

from fastapi import FastAPI, File, HTTPException, Query, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from starlette.concurrency import run_in_threadpool
from app.scanner import SCAN_LOG_FILE, is_supported_file, ml_stack_status, preload_ml_stacks, scan_file, write_scan_event
from app import stg_scanner

DOWNLOAD_WATCH_DIR = Path(os.environ.get("SANDBOX_STAGING_DIR", r"D:\\Download"))
MANUAL_UPLOAD_DIR = Path(os.environ.get("MANUAL_UPLOAD_DIR", r"C:\\Sandbox_ManualUploads"))
MAX_FILE_SIZE_BYTES = 1024 * 1024 * 1024  # 1 GB
SCAN_RESULTS: dict[str, dict[str, Any]] = {}
SCAN_JOBS: dict[str, dict[str, Any]] = {}
LATEST_SCAN_JOB_ID: str | None = None
APP_STARTED_AT = datetime.now(timezone.utc)
SESSION_APPROVE_MARKER = ".approved"
SESSION_REJECT_MARKER = ".rejected"
TERMINAL_POST_ACTIONS = {"approved_via_result_page", "rejected_via_result_page", "deleted"}
PRELOAD_ML_ON_STARTUP = os.environ.get("PRELOAD_ML_ON_STARTUP", "0").strip().lower() in {"1", "true", "yes", "on"}

app = FastAPI(title="Sandbox Upload API", version="1.0.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


def ensure_staging_dir() -> None:
    MANUAL_UPLOAD_DIR.mkdir(parents=True, exist_ok=True)
    DOWNLOAD_WATCH_DIR.mkdir(parents=True, exist_ok=True)


def iso_utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def safe_unique_path(original_name: str) -> Path:
    file_name = Path(original_name).name or "upload.bin"
    target = DOWNLOAD_WATCH_DIR / file_name
    if not target.exists():
        return target

    stem = Path(file_name).stem
    suffix = Path(file_name).suffix
    return DOWNLOAD_WATCH_DIR / f"{stem}_{uuid4().hex[:8]}{suffix}"


def staging_path_for(file_name: str) -> Path:
    safe_name = Path(file_name).name
    if not safe_name:
        raise HTTPException(status_code=400, detail="Invalid file name")
    return MANUAL_UPLOAD_DIR / safe_name


KNOWN_RESULTS = {"Safe", "Suspicious", "Malicious"}


def decision_to_result(decision: str) -> str:
    normalized = str(decision or "").upper()
    if normalized == "BLOCKED":
        return "Malicious"
    if normalized in {"UNCERTAIN", "STEGO"}:
        return "Suspicious"
    if normalized in {"ALLOWED", "COVER"}:
        return "Safe"
    return "Safe"


def overall_result_for(payload: dict[str, Any] | None) -> str:
    data = payload or {}
    explicit = str(data.get("overall_result", "") or "")

    predicted_label = str(data.get("predicted_label", "") or "").strip().lower()
    if predicted_label == "stego":
        return "Suspicious"

    decision = str(data.get("decision", "") or "")
    if decision:
        return decision_to_result(decision)

    engine = str(data.get("engine", "") or "").strip().lower()
    risk = data.get("fused_risk")
    if isinstance(risk, (int, float)):
        if engine == "stg-ml":
            return "Suspicious" if float(risk) >= 0.5 else "Safe"
        if float(risk) >= 0.8:
            return "Malicious"
        if float(risk) >= 0.2:
            return "Suspicious"
        return "Safe"

    if explicit in KNOWN_RESULTS:
        return explicit

    return "Suspicious"


def parse_event_ts(value: Any) -> datetime | None:
    if not value:
        return None
    try:
        return datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except Exception:
        return None


def _iter_scan_events() -> list[dict[str, Any]]:
    if not SCAN_LOG_FILE.exists():
        return []

    decoder = json.JSONDecoder()
    events: list[dict[str, Any]] = []
    with SCAN_LOG_FILE.open("r", encoding="utf-8") as handle:
        for raw_line in handle:
            line = raw_line.strip()
            if not line:
                continue
            index = 0
            while index < len(line):
                while index < len(line) and line[index].isspace():
                    index += 1
                if index >= len(line):
                    break
                try:
                    payload, next_index = decoder.raw_decode(line, index)
                except json.JSONDecodeError:
                    break
                if isinstance(payload, dict):
                    events.append(dict(payload))
                index = next_index
    return events


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

    overall_result = overall_result_for(scan_result)
    payload = {
        "status": "completed",
        "file_name": target_path.name,
        "staging_path": str(target_path),
        "size_bytes": target_path.stat().st_size if target_path.exists() else 0,
        "scan_result": scan_result,
        "overall_result": overall_result,
        "source": "manual-upload",
        "ts": str(scan_result.get("ts") or iso_utc_now()),
    }
    SCAN_RESULTS[target_path.name] = payload
    return payload


def build_job_payload(
    scan_id: str,
    file_name: str,
    staging_path: Path,
    size_bytes: int,
    *,
    status: str,
    source: str = "remote-upload",
    scan_result: dict[str, Any] | None = None,
    overall_result: str | None = None,
    message: str | None = None,
    ts: str | None = None,
) -> dict[str, Any]:
    return {
        "scan_id": scan_id,
        "status": status,
        "file_name": file_name,
        "staging_path": str(staging_path),
        "size_bytes": size_bytes,
        "scan_result": scan_result,
        "overall_result": overall_result,
        "source": source,
        "message": message,
        "ts": ts or iso_utc_now(),
    }


def build_scan_report(job: dict[str, Any]) -> dict[str, Any]:
    scan_result = dict(job.get("scan_result") or {})
    reasons = scan_result.get("reasons")
    if not isinstance(reasons, list):
        reasons = []

    return {
        "scan_id": job.get("scan_id"),
        "file_name": job.get("file_name"),
        "status": job.get("status"),
        "verdict": job.get("overall_result"),
        "summary": ", ".join(str(item) for item in reasons if item) or (
            "Scan still in progress." if job.get("status") in {"queued", "processing"} else "No additional details available."
        ),
        "file_hash": scan_result.get("sha256"),
        "scan_time": job.get("ts"),
        "events": reasons,
        "scan_result": scan_result,
        "size_bytes": job.get("size_bytes"),
        "source": job.get("source"),
    }


def _log_view_from_active_result(payload: dict[str, Any]) -> dict[str, Any]:
    scan_result = dict(payload.get("scan_result") or {})
    if not scan_result:
        return {
            "file_name": payload.get("file_name"),
            "decision": "PENDING",
            "engine": "pending",
            "fused_risk": None,
            "reasons": ["scan in progress"],
            "ts": payload.get("ts") or iso_utc_now(),
            "overall_result": "Suspicious",
        }

    event = dict(scan_result)
    event.setdefault("file_name", payload.get("file_name"))
    event.setdefault("ts", payload.get("ts") or scan_result.get("ts") or iso_utc_now())
    event["overall_result"] = overall_result_for(event)
    return event


def start_background_scan(target_path: Path, size_bytes: int) -> dict[str, Any]:
    submitted_at = iso_utc_now()
    payload = {
        "status": "processing",
        "file_name": target_path.name,
        "staging_path": str(target_path),
        "size_bytes": size_bytes,
        "scan_result": None,
        "overall_result": None,
        "source": "manual-upload",
        "ts": submitted_at,
    }
    SCAN_RESULTS[target_path.name] = payload

    def _worker() -> None:
        try:
            final_payload = process_staged_file(target_path)
            final_payload["size_bytes"] = size_bytes
            final_payload["ts"] = str(final_payload.get("ts") or submitted_at)
            SCAN_RESULTS[target_path.name] = final_payload
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
                "source": "manual-upload",
                "ts": iso_utc_now(),
            }

    threading.Thread(target=_worker, name=f"scan-{target_path.name}", daemon=True).start()
    return payload


def start_background_job(scan_id: str, target_path: Path, size_bytes: int) -> dict[str, Any]:
    global LATEST_SCAN_JOB_ID

    submitted_at = iso_utc_now()
    payload = build_job_payload(
        scan_id,
        target_path.name,
        target_path,
        size_bytes,
        status="queued",
        message=f"Queued {target_path.name} for remote scan.",
        ts=submitted_at,
    )
    SCAN_JOBS[scan_id] = payload
    SCAN_RESULTS[target_path.name] = payload
    LATEST_SCAN_JOB_ID = scan_id

    def _worker() -> None:
        processing_payload = dict(SCAN_JOBS.get(scan_id) or payload)
        processing_payload["status"] = "processing"
        processing_payload["message"] = f"Scanning {target_path.name} on the remote worker..."
        SCAN_JOBS[scan_id] = processing_payload
        SCAN_RESULTS[target_path.name] = processing_payload
        try:
            final_payload = process_staged_file(target_path)
            final_job = build_job_payload(
                scan_id,
                target_path.name,
                target_path,
                size_bytes,
                status="completed",
                scan_result=final_payload.get("scan_result"),
                overall_result=final_payload.get("overall_result"),
                message=f"Remote scan completed for {target_path.name}.",
                ts=str(final_payload.get("ts") or submitted_at),
            )
            SCAN_JOBS[scan_id] = final_job
            SCAN_RESULTS[target_path.name] = final_job
        except Exception as exc:
            failed_job = build_job_payload(
                scan_id,
                target_path.name,
                target_path,
                size_bytes,
                status="failed",
                scan_result={
                    "decision": "UNCERTAIN",
                    "engine": "none",
                    "fused_risk": 0.5,
                    "reasons": [],
                    "scanner_warning": str(exc),
                },
                overall_result="Suspicious",
                message=f"Remote scan failed for {target_path.name}.",
            )
            SCAN_JOBS[scan_id] = failed_job
            SCAN_RESULTS[target_path.name] = failed_job

    threading.Thread(target=_worker, name=f"job-{scan_id}", daemon=True).start()
    return payload


def read_scan_logs(
    limit: int,
    *,
    current_session_only: bool = True,
    include_follow_up: bool = False,
) -> list[dict[str, Any]]:
    events = _iter_scan_events()
    active_items = []
    for payload in SCAN_RESULTS.values():
        status = str(payload.get("status") or "")
        if status in {"processing", "queued", "completed", "failed"}:
            active_items.append(_log_view_from_active_result(payload))
    events.extend(active_items)
    if current_session_only:
        events = [
            event
            for event in events
            if (parse_event_ts(event.get("ts")) or datetime.min.replace(tzinfo=timezone.utc)) >= APP_STARTED_AT
        ]
    if not include_follow_up:
        events = [event for event in events if str(event.get("post_action", "")) not in TERMINAL_POST_ACTIONS]

    deduped: dict[tuple[str, str], dict[str, Any]] = {}
    for event in events:
        event["overall_result"] = overall_result_for(event)
        key = (str(event.get("file_name", "")), str(event.get("ts", "")))
        deduped[key] = event
    items = list(deduped.values())
    items.sort(key=lambda item: str(item.get("ts", "")), reverse=True)
    return items[:limit]


def get_latest_log_event(current_session_only: bool = False) -> dict[str, Any] | None:
    items = read_scan_logs(limit=500, current_session_only=current_session_only, include_follow_up=False)
    if not items:
        return None
    return items[0]


def find_logged_event(file_name: str) -> dict[str, Any] | None:
    safe_name = Path(file_name).name
    if not safe_name:
        return None

    latest_match: dict[str, Any] | None = None
    for event in _iter_scan_events():
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

    staging_candidate = MANUAL_UPLOAD_DIR / safe_name
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


def resolve_session_dir(file_path: Path) -> Path | None:
    normalized = file_path.resolve()
    parent = normalized.parent
    if parent.name in {"in", "out"} and parent.parent.exists():
        session_dir = parent.parent
        if (session_dir / "sandbox.wsb").exists():
            return session_dir
    return None


def clear_result_state(file_name: str) -> None:
    SCAN_RESULTS.pop(Path(file_name).name, None)


def clear_job_state(scan_id: str) -> None:
    job = SCAN_JOBS.pop(scan_id, None)
    if job:
        clear_result_state(str(job.get("file_name") or ""))


def _sort_key_for_event(payload: dict[str, Any]) -> datetime:
    return parse_event_ts(payload.get("ts")) or datetime.min.replace(tzinfo=timezone.utc)


def get_latest_active_result() -> dict[str, Any] | None:
    if not SCAN_RESULTS:
        return None

    items = [dict(item) for item in SCAN_RESULTS.values()]
    if not items:
        return None

    items.sort(key=_sort_key_for_event, reverse=True)
    return items[0]


def get_latest_known_result() -> dict[str, Any] | None:
    candidates: list[dict[str, Any]] = []

    latest_active = get_latest_active_result()
    if latest_active:
        candidates.append(latest_active)

    latest_log = get_latest_log_event(current_session_only=True)
    if latest_log:
        candidates.append(latest_log)

    if not candidates:
        return None

    candidates.sort(key=_sort_key_for_event, reverse=True)
    return candidates[0]


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
    if PRELOAD_ML_ON_STARTUP:
        threading.Thread(target=preload_ml_stacks, name="ml-prewarm", daemon=True).start()


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
        "download_watch_dir": str(DOWNLOAD_WATCH_DIR),
        "manual_upload_dir": str(MANUAL_UPLOAD_DIR),
        "stg_image_size": stg_scanner.DEFAULT_IMAGE_SIZE,
        "stg_stego_threshold": stg_scanner.DEFAULT_STEGO_THRESHOLD,
        "stg_clean_threshold": stg_scanner.DEFAULT_CLEAN_THRESHOLD,
        "auto_scan_requires_downloads_to_target_staging": True,
        "message": (
            "Automatic sandboxing only happens when the browser or app downloads directly "
            f"into {DOWNLOAD_WATCH_DIR}. Manual uploads are stored separately."
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
            "message": "Unsupported file type. Only image files and .exe files are processed.",
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

    scan_id = uuid4().hex
    payload = start_background_job(scan_id, target_path, total)
    payload["source"] = "remote-upload"
    payload["message"] = "Upload completed. The remote scanning laptop has queued this file for analysis."
    return payload


@app.get("/api/scan/jobs/{scan_id}")
def get_scan_job(scan_id: str) -> dict[str, Any]:
    job = SCAN_JOBS.get(scan_id)
    if not job:
        raise HTTPException(status_code=404, detail="No scan job found for this scan ID")
    return job


@app.get("/api/scan/jobs/{scan_id}/report")
def get_scan_job_report(scan_id: str) -> dict[str, Any]:
    job = SCAN_JOBS.get(scan_id)
    if not job:
        raise HTTPException(status_code=404, detail="No scan job found for this scan ID")
    return build_scan_report(job)


@app.get("/api/scan/results/{file_name}")
def get_scan_result(file_name: str) -> dict[str, Any]:
    safe_name = Path(file_name).name
    record = SCAN_RESULTS.get(safe_name)
    if not record:
        raise HTTPException(status_code=404, detail="No active scan result found for this file")
    return record


@app.get("/api/scan/logs")
def get_scan_logs(limit: int = Query(default=50, ge=1, le=500)) -> dict[str, Any]:
    items = read_scan_logs(limit, current_session_only=False, include_follow_up=False)
    return {"count": len(items), "items": items}


@app.get("/api/scan/latest")
def get_latest_scan_result() -> dict[str, Any]:
    if LATEST_SCAN_JOB_ID and LATEST_SCAN_JOB_ID in SCAN_JOBS:
        return SCAN_JOBS[LATEST_SCAN_JOB_ID]

    latest = get_latest_known_result()
    if not latest:
        raise HTTPException(status_code=404, detail="No scan results available in this session")
    return latest


@app.get("/api/scan/files/{file_name}")
def download_file(file_name: str) -> FileResponse:
    file_path = resolve_managed_file(file_name)
    return FileResponse(path=file_path, filename=file_path.name, media_type="application/octet-stream")


@app.post("/api/scan/files/{file_name}/approve")
def approve_file(file_name: str) -> dict[str, str]:
    file_path = resolve_managed_file(file_name)
    session_dir = resolve_session_dir(file_path)
    if not session_dir:
        raise HTTPException(status_code=400, detail="This file is not in an active sandbox session")

    (session_dir / SESSION_APPROVE_MARKER).write_text("approved\n", encoding="utf-8")
    if file_path.exists():
        file_path.unlink()

    log_follow_up_event(file_name, "approved_via_result_page", "File was saved locally, removed from sandbox, and approved.")
    clear_result_state(file_name)
    return {"status": "approved", "file_name": Path(file_name).name}


@app.post("/api/scan/files/{file_name}/reject")
def reject_file(file_name: str) -> dict[str, str]:
    file_path = resolve_managed_file(file_name)
    session_dir = resolve_session_dir(file_path)
    if not session_dir:
        raise HTTPException(status_code=400, detail="This file is not in an active sandbox session")

    (session_dir / SESSION_REJECT_MARKER).write_text("rejected\n", encoding="utf-8")
    if file_path.exists():
        file_path.unlink()

    log_follow_up_event(file_name, "rejected_via_result_page", "File was rejected from the Result page and removed from the sandbox.")
    clear_result_state(file_name)
    return {"status": "rejected", "file_name": Path(file_name).name}


@app.delete("/api/scan/files/{file_name}")
def delete_file(file_name: str) -> dict[str, str]:
    file_path = resolve_managed_file(file_name)
    session_dir = resolve_session_dir(file_path)

    try:
        if session_dir:
            (session_dir / SESSION_REJECT_MARKER).write_text("rejected\n", encoding="utf-8")
        file_path.unlink()
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Delete failed: {exc}")

    if session_dir:
        log_follow_up_event(file_name, "rejected_via_result_page", "File was deleted from the Result page and the sandbox session was closed.")
    else:
        log_follow_up_event(file_name, "deleted", "Sandbox copy was deleted.")
    clear_result_state(file_name)
    return {"status": "deleted", "file_name": file_path.name}


@app.delete("/api/scan/jobs/{scan_id}")
def delete_scan_job(scan_id: str) -> dict[str, str]:
    job = SCAN_JOBS.get(scan_id)
    if not job:
        raise HTTPException(status_code=404, detail="No scan job found for this scan ID")

    staging_path = Path(str(job.get("staging_path") or ""))
    if staging_path.exists() and staging_path.is_file():
        try:
            staging_path.unlink()
        except Exception as exc:
            raise HTTPException(status_code=500, detail=f"Delete failed: {exc}")

    clear_job_state(scan_id)
    return {"status": "deleted", "scan_id": scan_id}














