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

DOWNLOAD_WATCH_DIR = Path(os.environ.get("SANDBOX_STAGING_DIR", r"D:\\Download"))
MANUAL_UPLOAD_DIR = Path(os.environ.get("MANUAL_UPLOAD_DIR", r"C:\\Sandbox_ManualUploads"))
MAX_FILE_SIZE_BYTES = 1024 * 1024 * 1024  # 1 GB
SCAN_RESULTS: dict[str, dict[str, Any]] = {}
APP_STARTED_AT = datetime.now(timezone.utc)
SESSION_APPROVE_MARKER = ".approved"
SESSION_REJECT_MARKER = ".rejected"
TERMINAL_POST_ACTIONS = {"approved_via_result_page", "rejected_via_result_page", "deleted"}

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


def iso_utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def safe_unique_path(original_name: str) -> Path:
    file_name = Path(original_name).name or "upload.bin"
    target = MANUAL_UPLOAD_DIR / file_name
    if not target.exists():
        return target

    stem = Path(file_name).stem
    suffix = Path(file_name).suffix
    return MANUAL_UPLOAD_DIR / f"{stem}_{uuid4().hex[:8]}{suffix}"


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


def read_scan_logs(
    limit: int,
    *,
    current_session_only: bool = True,
    include_follow_up: bool = False,
) -> list[dict[str, Any]]:
    events = _iter_scan_events()
    if current_session_only:
        events = [
            event
            for event in events
            if (parse_event_ts(event.get("ts")) or datetime.min.replace(tzinfo=timezone.utc)) >= APP_STARTED_AT
        ]
    if not include_follow_up:
        events = [event for event in events if str(event.get("post_action", "")) not in TERMINAL_POST_ACTIONS]
    for event in events:
        event["overall_result"] = overall_result_for(event)
    events.sort(key=lambda item: str(item.get("ts", "")), reverse=True)
    return events[:limit]


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

    return start_background_scan(target_path, total)


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

    try:
        file_path.unlink()
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Delete failed: {exc}")

    log_follow_up_event(file_name, "deleted", "Sandbox copy was deleted.")
    clear_result_state(file_name)
    return {"status": "deleted", "file_name": file_path.name}














