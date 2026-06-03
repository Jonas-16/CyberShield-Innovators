from __future__ import annotations

import json
import os
import hashlib
import queue
import shutil
import secrets
import subprocess
import threading
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from uuid import uuid4
from xml.sax.saxutils import escape

from fastapi import FastAPI, File, HTTPException, Query, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from pydantic import BaseModel
from app.scanner import SCAN_LOG_FILE, is_supported_file, ml_stack_status, scan_file, write_scan_event

try:
    import pymysql
    from pymysql.cursors import DictCursor
except Exception:
    pymysql = None
    DictCursor = None

CLOUD_UPLOAD_DIR = Path(os.environ.get("CLOUD_UPLOAD_DIR", Path(__file__).resolve().parent / "uploads"))
STAGING_DIR = CLOUD_UPLOAD_DIR
SANDBOX_DIR = Path(os.environ.get("SANDBOX_DIR", r"C:\Sandbox_VM_Input"))
SANDBOX_SESSION_ROOT = Path(os.environ.get("SANDBOX_SESSION_ROOT", str(SANDBOX_DIR / "sessions")))
WINDOWS_SANDBOX_EXE = Path(os.environ.get("WINDOWS_SANDBOX_EXE", r"C:\Windows\System32\WindowsSandbox.exe"))
SANDBOX_GUEST_MOUNT_DIR = r"C:\HostShare"
SANDBOX_GUEST_IN_DIR = SANDBOX_GUEST_MOUNT_DIR + r"\in"
SANDBOX_GUEST_OUT_DIR = SANDBOX_GUEST_MOUNT_DIR + r"\out"
SANDBOX_STARTUP_GRACE_SECONDS = 5
SANDBOX_APPROVE_MARKER = ".approved"
SANDBOX_REJECT_MARKER = ".rejected"
MAX_FILE_SIZE_BYTES = 1024 * 1024 * 1024  # 1 GB
SCAN_RESULTS: dict[str, dict[str, Any]] = {}
DECODER_REPORT_ROOT = Path(__file__).resolve().parent / "reports" / "stego_decoder"
APP_STARTED_AT = datetime.now(timezone.utc)
SCAN_JOB_QUEUE: queue.Queue[dict[str, Any]] = queue.Queue()
SCAN_WORKER_STARTED = False
SCAN_WORKER_LOCK = threading.Lock()
SCAN_ACTION_CONDITION = threading.Condition()
SESSION_APPROVE_MARKER = ".approved"
SESSION_REJECT_MARKER = ".rejected"
TERMINAL_POST_ACTIONS = {"approved_via_result_page", "rejected_via_result_page", "deleted"}
PASSWORD_ITERATIONS = 260000
MYSQL_HOST = os.environ.get("CYBERSHIELD_MYSQL_HOST", "127.0.0.1")
MYSQL_PORT = int(os.environ.get("CYBERSHIELD_MYSQL_PORT", "3306"))
MYSQL_USER = os.environ.get("CYBERSHIELD_MYSQL_USER", "root")
MYSQL_PASSWORD = os.environ.get("CYBERSHIELD_MYSQL_PASSWORD", "")
MYSQL_DATABASE = os.environ.get("CYBERSHIELD_MYSQL_DATABASE", "cybershield")

app = FastAPI(title="CyberShield Cloud Scanner API", version="1.0.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


class SignupRequest(BaseModel):
    name: str
    email: str
    password: str


class LoginRequest(BaseModel):
    email: str
    password: str


def ensure_staging_dir() -> None:
    CLOUD_UPLOAD_DIR.mkdir(parents=True, exist_ok=True)
    SANDBOX_SESSION_ROOT.mkdir(parents=True, exist_ok=True)


def safe_unique_path(original_name: str) -> Path:
    file_name = Path(original_name).name or "upload.bin"
    target = STAGING_DIR / file_name
    if not target.exists():
        return target

    stem = Path(file_name).stem
    suffix = Path(file_name).suffix
    return STAGING_DIR / f"{stem}_{uuid4().hex[:8]}{suffix}"


def normalize_user_id(user_id: str | None) -> str:
    value = str(user_id or "guest").strip().lower()
    safe = "".join(ch if ch.isalnum() or ch in {"-", "_", "."} else "-" for ch in value)
    return safe.strip("-") or "guest"


def result_key(user_id: str | None, file_name: str) -> str:
    return f"{normalize_user_id(user_id)}::{Path(file_name).name}"


def device_metadata(
    device_id: str | None = None,
    device_name: str | None = None,
    os_name: str | None = None,
    os_version: str | None = None,
    machine: str | None = None,
) -> dict[str, str]:
    return {
        "device_id": str(device_id or "unknown-device").strip() or "unknown-device",
        "device_name": str(device_name or "Unknown device").strip() or "Unknown device",
        "os_name": str(os_name or "Unknown OS").strip() or "Unknown OS",
        "os_version": str(os_version or "").strip(),
        "machine": str(machine or "").strip(),
    }


def normalize_email(value: str | None) -> str:
    return str(value or "").strip().lower()


def user_payload(row: dict[str, Any]) -> dict[str, Any]:
    return {
        "id": str(row.get("user_id") or ""),
        "user_id": str(row.get("user_id") or ""),
        "name": str(row.get("name") or ""),
        "email": str(row.get("email") or ""),
        "createdAt": str(row.get("created_at") or ""),
        "source": "mysql",
    }


def db_connection():
    if pymysql is None:
        raise HTTPException(status_code=500, detail="PyMySQL is not installed. Run pip install -r cloud/backend/requirements.txt")
    try:
        return pymysql.connect(
            host=MYSQL_HOST,
            port=MYSQL_PORT,
            user=MYSQL_USER,
            password=MYSQL_PASSWORD,
            database=MYSQL_DATABASE,
            cursorclass=DictCursor,
            autocommit=True,
        )
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Cannot connect to MySQL database '{MYSQL_DATABASE}': {exc}") from exc


def hash_password(password: str) -> str:
    salt = secrets.token_hex(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt.encode("utf-8"), PASSWORD_ITERATIONS)
    return f"pbkdf2_sha256${PASSWORD_ITERATIONS}${salt}${digest.hex()}"


def verify_password(password: str, stored_hash: str) -> bool:
    try:
        algorithm, iterations_text, salt, expected = str(stored_hash).split("$", 3)
        if algorithm != "pbkdf2_sha256":
            return False
        iterations = int(iterations_text)
        digest = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt.encode("utf-8"), iterations)
        return secrets.compare_digest(digest.hex(), expected)
    except Exception:
        return False


def unique_user_id(email: str) -> str:
    base = normalize_user_id(email.split("@", 1)[0] or email)
    candidate = base
    with db_connection() as conn:
        with conn.cursor() as cursor:
            while True:
                cursor.execute("SELECT id FROM users WHERE user_id=%s LIMIT 1", (candidate,))
                if cursor.fetchone() is None:
                    return candidate
                candidate = f"{base}-{uuid4().hex[:6]}"


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
    review_threshold = float(data.get("review_threshold") or stego_threshold)
    unsafe_threshold = float(data.get("unsafe_threshold") or 0.80)
    reasons = [str(reason).lower() for reason in data.get("reasons", []) if reason]

    if decision == "BLOCKED":
        return "Malicious"
    if isinstance(fused_risk, (int, float)) and fused_risk >= unsafe_threshold:
        return "Suspicious"
    if isinstance(fused_risk, (int, float)) and fused_risk >= review_threshold:
        return "Review"
    if predicted_label == "stego" and isinstance(fused_risk, (int, float)) and fused_risk < unsafe_threshold:
        return "Review"
    if predicted_label == "stego":
        return "Suspicious"
    if decision in {"STEGO", "UNCERTAIN"}:
        return "Review"
    if decision in {"PENDING", "IGNORED"}:
        return "Suspicious"
    if predicted_label == "cover":
        return "Safe"
    if suffix in {".jpg", ".jpeg", ".jfif", ".png", ".bmp", ".gif", ".tif", ".tiff", ".webp"} and engine != "stg-ml":
        return "Suspicious"
    if scanner_warning or (engine == "heuristic" and any("could not inspect" in reason for reason in reasons)):
        return "Suspicious"
    if explicit in {"Safe", "Review", "Suspicious", "Malicious"}:
        return explicit
    return "Safe"


def decision_to_result(decision: str) -> str:
    return overall_result_for({"decision": decision})


def build_sandbox_session(file_name: str) -> dict[str, Path | str]:
    session_id = f"{datetime.now().strftime('%Y%m%d_%H%M%S')}_{uuid4().hex[:8]}"
    session_dir = SANDBOX_SESSION_ROOT / session_id
    host_in_dir = session_dir / "in"
    host_out_dir = session_dir / "out"
    host_in_dir.mkdir(parents=True, exist_ok=True)
    host_out_dir.mkdir(parents=True, exist_ok=True)

    safe_name = Path(file_name).name or "upload.bin"
    return {
        "id": session_id,
        "dir": session_dir,
        "host_in_dir": host_in_dir,
        "host_out_dir": host_out_dir,
        "host_in_file": host_in_dir / safe_name,
        "host_out_file": host_out_dir / safe_name,
        "wsb_path": session_dir / "sandbox.wsb",
        "init_cmd_path": session_dir / "sandbox_init.cmd",
        "guest_watch_path": session_dir / "sandbox_watch.ps1",
        "approve_marker": session_dir / SANDBOX_APPROVE_MARKER,
        "reject_marker": session_dir / SANDBOX_REJECT_MARKER,
        "file_name": safe_name,
    }


def write_sandbox_session_files(session: dict[str, Path | str]) -> None:
    file_name = str(session["file_name"])
    guest_watch = (
        "$approve = \"{0}\"\r\n"
        "$reject = \"{1}\"\r\n"
        "while ($true) {{\r\n"
        "  if ((Test-Path $approve) -or (Test-Path $reject)) {{\r\n"
        "    Start-Sleep -Seconds 2\r\n"
        "    Stop-Process -Name explorer -ErrorAction SilentlyContinue\r\n"
        "    shutdown.exe /s /f /t 0\r\n"
        "    break\r\n"
        "  }}\r\n"
        "  Start-Sleep -Milliseconds 500\r\n"
        "}}\r\n"
    ).format(
        SANDBOX_GUEST_MOUNT_DIR + "\\" + SANDBOX_APPROVE_MARKER,
        SANDBOX_GUEST_MOUNT_DIR + "\\" + SANDBOX_REJECT_MARKER,
    )
    Path(session["guest_watch_path"]).write_text(guest_watch, encoding="utf-8")

    init_cmd = (
        "@echo off\r\n"
        "title CyberShield Sandbox Session\r\n"
        "if not exist \"{0}\" mkdir \"{0}\"\r\n"
        "echo CyberShield sandbox session started.\r\n"
        "echo Input file path: {1}\\{2}\r\n"
        "echo To approve, use the Result page or move file to: {3}\r\n"
        "echo To reject, use the Result page or delete file from: {1}\r\n"
        "start \"\" powershell.exe -NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File \"{4}\"\r\n"
        "start \"\" explorer.exe \"{1}\"\r\n"
    ).format(
        SANDBOX_GUEST_OUT_DIR,
        SANDBOX_GUEST_IN_DIR,
        file_name,
        SANDBOX_GUEST_OUT_DIR,
        SANDBOX_GUEST_MOUNT_DIR + r"\sandbox_watch.ps1",
    )
    Path(session["init_cmd_path"]).write_text(init_cmd, encoding="utf-8")

    wsb_contents = (
        "<Configuration>\n"
        "  <MappedFolders>\n"
        "    <MappedFolder>\n"
        "      <HostFolder>{0}</HostFolder>\n"
        "      <SandboxFolder>{1}</SandboxFolder>\n"
        "      <ReadOnly>false</ReadOnly>\n"
        "    </MappedFolder>\n"
        "  </MappedFolders>\n"
        "  <LogonCommand>\n"
        "    <Command>{2}</Command>\n"
        "  </LogonCommand>\n"
        "</Configuration>\n"
    ).format(
        escape(str(session["dir"])),
        escape(SANDBOX_GUEST_MOUNT_DIR),
        escape(SANDBOX_GUEST_MOUNT_DIR + r"\sandbox_init.cmd"),
    )
    Path(session["wsb_path"]).write_text(wsb_contents, encoding="utf-8")


def launch_windows_sandbox(session: dict[str, Path | str]) -> subprocess.Popen | None:
    if not WINDOWS_SANDBOX_EXE.exists():
        return None
    try:
        process = subprocess.Popen([str(WINDOWS_SANDBOX_EXE), str(session["wsb_path"])])
    except Exception:
        return None
    time.sleep(SANDBOX_STARTUP_GRACE_SECONDS)
    return process


def parse_event_ts(value: Any) -> datetime | None:
    if not value:
        return None
    try:
        return datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except Exception:
        return None


def process_staged_file(target_path: Path, user_id: str | None = None, device: dict[str, str] | None = None) -> dict[str, Any]:
    owner_id = normalize_user_id(user_id)
    device = device or device_metadata()
    scan_target = target_path
    session: dict[str, Path | str] | None = None
    try:
        session = build_sandbox_session(target_path.name)
        write_sandbox_session_files(session)
        scan_target = Path(session["host_in_file"])
        shutil.move(str(target_path), str(scan_target))

        sandbox_process = launch_windows_sandbox(session)
        if sandbox_process is None:
            raise RuntimeError(
                f"Windows Sandbox could not be launched from {WINDOWS_SANDBOX_EXE}. "
                "Enable Windows Sandbox or set WINDOWS_SANDBOX_EXE."
            )

        scan_result = scan_file(scan_target, log_event=False)
        scan_result["source"] = "cloud-sandbox-upload"
        scan_result["user_id"] = owner_id
        scan_result["sandbox_session_id"] = str(session["id"])
        scan_result.update(device)
    except Exception as exc:
        session_id = str(session["id"]) if session else None
        scan_result = {
            "decision": "UNCERTAIN",
            "engine": "none",
            "fused_risk": 0.5,
            "reasons": [],
            "scanner_warning": str(exc),
            "source": "cloud-sandbox-upload",
            "user_id": owner_id,
            "sandbox_session_id": session_id,
            **device,
        }

    overall_result = overall_result_for(scan_result)
    if session:
        if overall_result == "Safe":
            scan_result["post_action"] = "auto_saved_safe"
            scan_result["message"] = "Safe file was approved automatically. Monitored downloads will be restored by the watcher."
            try:
                Path(session["approve_marker"]).write_text("approved\n", encoding="utf-8")
            except Exception as exc:
                scan_result["post_action_warning"] = str(exc)
        elif overall_result == "Review":
            scan_result["post_action"] = "manual_review_required"
            scan_result["message"] = "Borderline scan result. Review the file and choose whether to save or delete it."
        else:
            scan_result["post_action"] = "auto_deleted_blocked"
            scan_result["message"] = "Suspicious or malicious file was deleted automatically."
            try:
                if scan_target.exists():
                    scan_target.unlink()
                Path(session["reject_marker"]).write_text("rejected\n", encoding="utf-8")
            except Exception as exc:
                scan_result["post_action_warning"] = str(exc)
    else:
        scan_result["post_action"] = "manual_review_required" if overall_result == "Review" else ("auto_deleted_blocked" if overall_result != "Safe" else "auto_saved_safe")
        scan_result["message"] = "Scan completed and automatic file handling was applied."

    scan_result["overall_result"] = overall_result
    write_scan_event(scan_result)

    payload = {
        "status": "completed",
        "file_name": scan_target.name,
        "staging_path": str(scan_target),
        "size_bytes": scan_target.stat().st_size if scan_target.exists() else 0,
        "scan_result": scan_result,
        "overall_result": overall_result,
        "source": "cloud-sandbox-upload",
        "user_id": owner_id,
        "post_action": scan_result.get("post_action"),
        **device,
        "ts": str(scan_result.get("ts") or datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")),
    }
    SCAN_RESULTS[result_key(owner_id, scan_target.name)] = payload
    return payload


def failed_scan_payload(
    target_path: Path,
    size_bytes: int,
    owner_id: str,
    device: dict[str, str],
    error: Exception,
) -> dict[str, Any]:
    return {
        "status": "failed",
        "file_name": target_path.name,
        "staging_path": str(target_path),
        "size_bytes": size_bytes,
        "scan_result": {
            "decision": "UNCERTAIN",
            "engine": "none",
            "fused_risk": 0.5,
            "reasons": [],
            "scanner_warning": str(error),
        },
        "overall_result": "Suspicious",
        "source": "cloud-sandbox-upload",
        "user_id": owner_id,
        **device,
        "message": "The queued scan failed before it could complete.",
        "ts": datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z"),
    }


def notify_scan_action() -> None:
    with SCAN_ACTION_CONDITION:
        SCAN_ACTION_CONDITION.notify_all()


def wait_for_scan_action(file_name: str, owner_id: str) -> None:
    key = result_key(owner_id, file_name)
    while True:
        record = SCAN_RESULTS.get(key)
        if not record:
            return
        if str(record.get("post_action", "")) in TERMINAL_POST_ACTIONS:
            return
        with SCAN_ACTION_CONDITION:
            SCAN_ACTION_CONDITION.wait(timeout=1.0)


def scan_job_worker_loop() -> None:
    while True:
        job = SCAN_JOB_QUEUE.get()
        target_path = job["target_path"]
        size_bytes = job["size_bytes"]
        owner_id = job["owner_id"]
        device = job["device"]
        try:
            queued_payload = SCAN_RESULTS.get(result_key(owner_id, target_path.name), {})
            SCAN_RESULTS[result_key(owner_id, target_path.name)] = {
                **queued_payload,
                "status": "processing",
                "message": "Scan is running. Windows Sandbox is starting and the sandbox copy is being scanned.",
                "ts": datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z"),
            }
            result = process_staged_file(target_path, owner_id, device)
            if str(result.get("post_action", "")) == "manual_review_required":
                SCAN_RESULTS[result_key(owner_id, result["file_name"])] = {
                    **result,
                    "status": "completed",
                    "message": "Scan complete. Waiting for this file to be approved/saved or rejected/deleted before starting the next queued file.",
                }
                wait_for_scan_action(str(result["file_name"]), owner_id)
        except Exception as exc:
            SCAN_RESULTS[result_key(owner_id, target_path.name)] = failed_scan_payload(
                target_path,
                size_bytes,
                owner_id,
                device,
                exc,
            )
        finally:
            SCAN_JOB_QUEUE.task_done()


def start_scan_worker_once() -> None:
    global SCAN_WORKER_STARTED
    with SCAN_WORKER_LOCK:
        if SCAN_WORKER_STARTED:
            return
        thread = threading.Thread(target=scan_job_worker_loop, name="cloud-scan-worker", daemon=True)
        thread.start()
        SCAN_WORKER_STARTED = True


def start_background_scan(
    target_path: Path,
    size_bytes: int,
    user_id: str | None = None,
    device: dict[str, str] | None = None,
) -> dict[str, Any]:
    owner_id = normalize_user_id(user_id)
    device = device or device_metadata()
    submitted_at = datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")
    payload = {
        "status": "queued",
        "file_name": target_path.name,
        "staging_path": str(target_path),
        "size_bytes": size_bytes,
        "scan_result": None,
        "overall_result": None,
        "source": "cloud-sandbox-upload",
        "user_id": owner_id,
        **device,
        "message": "Upload received by backend. Scan queued and will run after earlier files finish.",
        "ts": submitted_at,
    }
    SCAN_RESULTS[result_key(owner_id, target_path.name)] = payload
    start_scan_worker_once()
    SCAN_JOB_QUEUE.put(
        {
            "target_path": target_path,
            "size_bytes": size_bytes,
            "owner_id": owner_id,
            "device": device,
            "submitted_at": submitted_at,
        }
    )
    return payload


def read_scan_logs(limit: int, user_id: str | None = None) -> list[dict[str, Any]]:
    if not SCAN_LOG_FILE.exists():
        return []

    owner_id = normalize_user_id(user_id) if user_id is not None else None
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
            if owner_id is not None and normalize_user_id(event.get("user_id")) != owner_id:
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
    device = device_metadata(
        event.get("device_id"),
        event.get("device_name"),
        event.get("os_name"),
        event.get("os_version"),
        event.get("machine"),
    )
    return {
        "status": "completed",
        "file_name": safe_name,
        "staging_path": str(STAGING_DIR / safe_name),
        "size_bytes": 0,
        "scan_result": event,
        "overall_result": overall_result_for(event),
        "source": event.get("source") or "download-monitor",
        "user_id": normalize_user_id(event.get("user_id")),
        **device,
        "ts": str(event.get("ts") or datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")),
    }


def get_latest_active_result(user_id: str | None = None) -> dict[str, Any] | None:
    if not SCAN_RESULTS:
        return None
    owner_id = normalize_user_id(user_id) if user_id is not None else None
    items = [
        dict(item)
        for item in SCAN_RESULTS.values()
        if owner_id is None or normalize_user_id(item.get("user_id")) == owner_id
    ]
    items.sort(key=lambda item: str(item.get("ts", "")), reverse=True)
    return items[0] if items else None


def get_latest_log_event(current_session_only: bool = False, user_id: str | None = None) -> dict[str, Any] | None:
    items = read_scan_logs(limit=500, user_id=user_id)
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


def find_logged_event(file_name: str, user_id: str | None = None) -> dict[str, Any] | None:
    safe_name = Path(file_name).name
    if not safe_name or not SCAN_LOG_FILE.exists():
        return None

    owner_id = normalize_user_id(user_id) if user_id is not None else None
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
            if owner_id is not None and normalize_user_id(event.get("user_id")) != owner_id:
                continue
            latest_match = event
    if latest_match:
        latest_match["overall_result"] = overall_result_for(latest_match)
    return latest_match


def resolve_managed_file(file_name: str, user_id: str | None = None) -> Path:
    safe_name = Path(file_name).name
    if not safe_name:
        raise HTTPException(status_code=400, detail="Invalid file name")

    candidates: list[Path] = []

    staging_candidate = STAGING_DIR / safe_name
    candidates.append(staging_candidate)

    record = SCAN_RESULTS.get(result_key(user_id, safe_name))
    if record:
        staging_path = record.get("staging_path")
        if staging_path:
            candidates.append(Path(str(staging_path)))
        scan_result = record.get("scan_result") or {}
        scan_path = scan_result.get("path")
        if scan_path:
            candidates.append(Path(str(scan_path)))

    logged_event = find_logged_event(safe_name, user_id=user_id)
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


def resolve_decoder_report_asset(report_id: str, asset_name: str) -> Path:
    safe_report_id = Path(report_id).name
    if not safe_report_id or safe_report_id != report_id:
        raise HTTPException(status_code=400, detail="Invalid report id")

    report_dir = (DECODER_REPORT_ROOT / safe_report_id).resolve()
    root = DECODER_REPORT_ROOT.resolve()
    try:
        report_dir.relative_to(root)
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid report id")

    asset_path = (report_dir / asset_name).resolve()
    try:
        asset_path.relative_to(report_dir)
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid report asset")

    if not asset_path.exists() or not asset_path.is_file():
        raise HTTPException(status_code=404, detail="Report asset not found")
    return asset_path


def resolve_logged_session_dir(file_name: str, user_id: str | None = None) -> Path | None:
    logged_event = find_logged_event(file_name, user_id=user_id)
    logged_path = logged_event.get("path") if logged_event else None
    if not logged_path:
        return None
    return resolve_session_dir(Path(str(logged_path)))


def log_follow_up_event(file_name: str, action: str, message: str, user_id: str | None = None) -> None:
    latest = find_logged_event(file_name, user_id=user_id)
    if not latest:
        return

    payload = dict(latest)
    payload["post_action"] = action
    payload["message"] = message
    payload["user_id"] = normalize_user_id(user_id or payload.get("user_id"))
    payload["ts"] = datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")
    write_scan_event(payload)
    notify_scan_action()


@app.on_event("startup")
def on_startup() -> None:
    ensure_staging_dir()
    start_scan_worker_once()


@app.get("/api/health")
def health() -> dict[str, str]:
    return {"status": "ok"}


@app.post("/api/auth/signup")
async def signup(payload: SignupRequest) -> dict[str, Any]:
    name = str(payload.name or "").strip()
    email = normalize_email(payload.email)
    password = str(payload.password or "")

    if not name:
        raise HTTPException(status_code=400, detail="Name is required")
    if "@" not in email or "." not in email.rsplit("@", 1)[-1]:
        raise HTTPException(status_code=400, detail="Enter a valid email address")
    if len(password) < 6:
        raise HTTPException(status_code=400, detail="Password must be at least 6 characters")

    with db_connection() as conn:
        with conn.cursor() as cursor:
            cursor.execute("SELECT id FROM users WHERE email=%s LIMIT 1", (email,))
            if cursor.fetchone() is not None:
                raise HTTPException(status_code=409, detail="This email is already registered")

            user_id = unique_user_id(email)
            cursor.execute(
                "INSERT INTO users (user_id, name, email, password_hash) VALUES (%s, %s, %s, %s)",
                (user_id, name, email, hash_password(password)),
            )
            cursor.execute("SELECT user_id, name, email, created_at FROM users WHERE email=%s LIMIT 1", (email,))
            row = cursor.fetchone()

    return {"user": user_payload(row)}


@app.post("/api/auth/login")
async def login(payload: LoginRequest) -> dict[str, Any]:
    email = normalize_email(payload.email)
    password = str(payload.password or "")

    with db_connection() as conn:
        with conn.cursor() as cursor:
            cursor.execute(
                "SELECT user_id, name, email, password_hash, created_at FROM users WHERE email=%s LIMIT 1",
                (email,),
            )
            row = cursor.fetchone()

    if row is None or not verify_password(password, str(row.get("password_hash") or "")):
        raise HTTPException(status_code=401, detail="Invalid email or password")

    return {"user": user_payload(row)}


@app.get("/api/scan/ml-status")
def get_ml_status() -> dict[str, Any]:
    return ml_stack_status()


@app.get("/api/scan/config")
def get_scan_config() -> dict[str, Any]:
    return {
        "mode": "cloud-sandbox-upload",
        "upload_dir": str(CLOUD_UPLOAD_DIR),
        "auto_scan_requires_downloads_to_target_staging": False,
        "message": (
            "Frontend uploads are sent to this backend. The backend stores each file, "
            "moves it into a Windows Sandbox session, scans that sandbox copy, and returns results through the API."
        ),
    }


@app.post("/api/scan/upload")
async def upload_to_sandbox(
    file: UploadFile = File(...),
    user_id: str | None = Query(default=None),
    device_id: str | None = Query(default=None),
    device_name: str | None = Query(default=None),
    os_name: str | None = Query(default=None),
    os_version: str | None = Query(default=None),
    machine: str | None = Query(default=None),
) -> dict[str, Any]:
    ensure_staging_dir()
    owner_id = normalize_user_id(user_id)
    device = device_metadata(device_id, device_name, os_name, os_version, machine)

    if not file.filename:
        raise HTTPException(status_code=400, detail="Missing filename")

    if not is_supported_file(file.filename):
        await file.close()
        return {
            "status": "ignored",
            "file_name": Path(file.filename).name,
            "source": "cloud-sandbox-upload",
            "user_id": owner_id,
            **device,
            "message": "Unsupported file type. Only image files, .exe files, and .apk files are processed.",
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

    return start_background_scan(target_path, total, owner_id, device)


@app.get("/api/scan/results/{file_name}")
def get_scan_result(file_name: str, user_id: str | None = Query(default=None)) -> dict[str, Any]:
    safe_name = Path(file_name).name
    record = SCAN_RESULTS.get(result_key(user_id, safe_name))
    logged_event = find_logged_event(safe_name, user_id=user_id)

    if logged_event and str(logged_event.get("post_action", "")) not in TERMINAL_POST_ACTIONS:
        logged_ts = parse_event_ts(logged_event.get("ts"))
        record_ts = parse_event_ts(record.get("ts")) if record else None
        if not record or str(record.get("status") or "") in {"queued", "processing"} or not record_ts or (logged_ts and logged_ts >= record_ts):
            return result_payload_from_log(logged_event)

    if record:
        return record

    raise HTTPException(status_code=404, detail="No active scan result found for this file")


@app.get("/api/scan/logs")
def get_scan_logs(limit: int = Query(default=50, ge=1, le=500), user_id: str | None = Query(default=None)) -> dict[str, Any]:
    items = read_scan_logs(limit, user_id=user_id)
    return {"count": len(items), "items": items}


@app.get("/api/scan/latest")
def get_latest_scan_result(user_id: str | None = Query(default=None)) -> dict[str, Any]:
    latest_log = get_latest_log_event(current_session_only=True, user_id=user_id)
    latest_active = get_latest_active_result(user_id=user_id)

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
def download_file(file_name: str, user_id: str | None = Query(default=None)) -> FileResponse:
    file_path = resolve_managed_file(file_name, user_id=user_id)
    return FileResponse(path=file_path, filename=file_path.name, media_type="application/octet-stream")


@app.get("/api/scan/reports/{report_id}/{asset_name:path}")
def download_decoder_report_asset(
    report_id: str,
    asset_name: str,
    download: bool = Query(default=False),
) -> FileResponse:
    asset_path = resolve_decoder_report_asset(report_id, asset_name or "scan_report.html")
    if download:
        return FileResponse(path=asset_path, filename=asset_path.name)
    return FileResponse(path=asset_path)


@app.post("/api/scan/files/{file_name}/approve")
def approve_file(
    file_name: str,
    restore_to_downloads: bool = Query(default=True),
    user_id: str | None = Query(default=None),
) -> dict[str, str]:
    safe_name = Path(file_name).name
    file_path = resolve_managed_file(safe_name, user_id=user_id)
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
    log_follow_up_event(safe_name, "approved_via_result_page", message, user_id=user_id)
    SCAN_RESULTS.pop(result_key(user_id, safe_name), None)
    notify_scan_action()
    return {"status": "approved", "file_name": safe_name}


@app.post("/api/scan/files/{file_name}/reject")
def reject_file(file_name: str, user_id: str | None = Query(default=None)) -> dict[str, str]:
    safe_name = Path(file_name).name
    file_path: Path | None = None
    try:
        file_path = resolve_managed_file(safe_name, user_id=user_id)
    except HTTPException as exc:
        if exc.status_code != 404:
            raise

    session_dir = resolve_session_dir(file_path) or resolve_logged_session_dir(safe_name, user_id=user_id)
    if not session_dir:
        raise HTTPException(status_code=400, detail="This file is not in an active sandbox session")

    try:
        (session_dir / SESSION_REJECT_MARKER).write_text("rejected\n", encoding="utf-8")
        if file_path and file_path.exists():
            file_path.unlink()
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Reject failed: {exc}")

    log_follow_up_event(safe_name, "rejected_via_result_page", "File was rejected from the Result page and removed from the sandbox.", user_id=user_id)
    SCAN_RESULTS.pop(result_key(user_id, safe_name), None)
    notify_scan_action()
    return {"status": "rejected", "file_name": safe_name}


@app.delete("/api/scan/files/{file_name}")
def delete_file(
    file_name: str,
    user_id: str | None = Query(default=None),
    record_event: bool = Query(default=True),
) -> dict[str, str]:
    safe_name = Path(file_name).name
    file_path = resolve_managed_file(safe_name, user_id=user_id)
    session_dir = resolve_session_dir(file_path) or resolve_logged_session_dir(safe_name, user_id=user_id)

    try:
        if session_dir:
            (session_dir / SESSION_REJECT_MARKER).write_text("rejected\n", encoding="utf-8")
        file_path.unlink()
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Delete failed: {exc}")

    SCAN_RESULTS.pop(result_key(user_id, file_path.name), None)
    notify_scan_action()
    message = (
        "File was deleted from the Result page and the sandbox session was closed."
        if session_dir
        else "Backend copy was deleted from the Result page."
    )
    if record_event:
        log_follow_up_event(safe_name, "deleted", message, user_id=user_id)
    return {"status": "deleted", "file_name": file_path.name}
