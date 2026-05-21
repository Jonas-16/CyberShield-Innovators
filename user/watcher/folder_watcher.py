from __future__ import annotations

import json
import os
import getpass
import platform
import socket
import threading
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.parse import quote

import requests
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

APP_DIR = Path(__file__).resolve().parent
CONFIG_FILE = APP_DIR / "watcher_config.json"
STATE_FILE = APP_DIR / "watcher_state.json"
EVENTS_FILE = APP_DIR / "watcher_events.jsonl"
DEVICE_FILE = APP_DIR / "device_identity.json"

DEFAULT_BACKEND_URL = os.environ.get("CYBERSHIELD_BACKEND_URL", "http://127.0.0.1:8000")
POLL_INTERVAL_SECONDS = float(os.environ.get("CYBERSHIELD_WATCH_INTERVAL", "2"))
STABLE_SECONDS = float(os.environ.get("CYBERSHIELD_FILE_STABLE_SECONDS", "2"))
SUPPORTED_EXTENSIONS = {".exe", ".jpg", ".jpeg", ".jfif", ".png", ".bmp", ".gif", ".tif", ".tiff", ".webp"}


def default_watch_folders() -> list[str]:
    configured = os.environ.get("CYBERSHIELD_WATCH_FOLDERS")
    if configured:
        return [item for item in configured.split(os.pathsep) if item.strip()]

    candidates = [
        Path.home() / "Downloads",
        Path(r"D:\Download"),
    ]
    return [str(path) for path in candidates if path.is_dir()]

app = FastAPI(title="CyberShield User Folder Watcher", version="1.0.0")
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

lock = threading.Lock()
pending: dict[str, dict[str, Any]] = {}
last_error: str | None = None


class WatcherSettings(BaseModel):
    folders: list[str] = []
    backend_url: str | None = None
    user_id: str | None = None
    scan_existing: bool = False


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def normalize_folder(value: str) -> str:
    expanded = os.path.expandvars(str(value).strip().strip('"'))
    return str(Path(expanded).expanduser())


def load_json(path: Path, fallback: dict[str, Any]) -> dict[str, Any]:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return dict(fallback)


def save_json(path: Path, payload: dict[str, Any]) -> None:
    path.write_text(json.dumps(payload, indent=2), encoding="utf-8")


def load_device_info() -> dict[str, Any]:
    saved = load_json(DEVICE_FILE, {})
    device_id = str(saved.get("device_id") or f"device-{uuid.uuid4().hex}")
    if saved.get("device_id") != device_id:
        save_json(DEVICE_FILE, {"device_id": device_id, "created_at": utc_now()})

    return {
        "device_id": device_id,
        "device_name": socket.gethostname() or "Unknown device",
        "os_name": platform.system() or "Unknown OS",
        "os_version": platform.release() or "",
        "machine": platform.machine() or "",
        "username": getpass.getuser() or "",
    }


def load_config() -> dict[str, Any]:
    config = load_json(CONFIG_FILE, {"folders": default_watch_folders(), "backend_url": DEFAULT_BACKEND_URL, "user_id": "guest"})
    configured_folders = config.get("folders")
    if not isinstance(configured_folders, list) or not configured_folders:
        configured_folders = default_watch_folders()
    folders = []
    for folder in configured_folders:
        normalized = normalize_folder(folder)
        if normalized and normalized.lower() not in {item.lower() for item in folders}:
            folders.append(normalized)
    return {
        "folders": folders,
        "backend_url": str(config.get("backend_url") or DEFAULT_BACKEND_URL).rstrip("/"),
        "user_id": str(config.get("user_id") or "guest"),
    }


def save_config(folders: list[str], backend_url: str | None, user_id: str | None = None) -> dict[str, Any]:
    unique: list[str] = []
    for folder in folders:
        normalized = normalize_folder(folder)
        if normalized and normalized.lower() not in {item.lower() for item in unique}:
            unique.append(normalized)

    config = {
        "folders": unique,
        "backend_url": str(backend_url or DEFAULT_BACKEND_URL).rstrip("/"),
        "user_id": str(user_id or "guest"),
    }
    save_json(CONFIG_FILE, config)
    return config


def load_state() -> dict[str, Any]:
    state = load_json(STATE_FILE, {"files": {}})
    files = state.get("files")
    return {"files": files if isinstance(files, dict) else {}}


def save_state(state: dict[str, Any]) -> None:
    save_json(STATE_FILE, state)


def safe_restore_path(original_path: Path) -> Path:
    original_path.parent.mkdir(parents=True, exist_ok=True)
    if not original_path.exists():
        return original_path
    scan_date = datetime.now().strftime("%Y%m%d_%H%M%S")
    return original_path.parent / f"{original_path.stem}_restored_{scan_date}{original_path.suffix}"


def file_signature(path: Path) -> str | None:
    try:
        stat = path.stat()
    except OSError:
        return None
    return f"{stat.st_size}:{int(stat.st_mtime)}"


def iter_supported_files(folders: list[str]):
    for folder in folders:
        root = Path(folder)
        if not root.exists() or not root.is_dir():
            continue
        for path in root.rglob("*"):
            if path.is_file() and path.suffix.lower() in SUPPORTED_EXTENSIONS:
                yield path


def remember_existing_files(folders: list[str]) -> None:
    state = load_state()
    files = state["files"]
    changed = False
    for path in iter_supported_files(folders):
        signature = file_signature(path)
        if signature and str(path) not in files:
            files[str(path)] = {"signature": signature, "status": "known", "ts": utc_now()}
            changed = True
    if changed:
        save_state(state)


def write_event(payload: dict[str, Any]) -> None:
    EVENTS_FILE.parent.mkdir(parents=True, exist_ok=True)
    with EVENTS_FILE.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(payload, sort_keys=True) + "\n")


def upload_file(path: Path, backend_url: str, user_id: str) -> dict[str, Any]:
    device = load_device_info()
    with path.open("rb") as handle:
        response = requests.post(
            f"{backend_url.rstrip('/')}/api/scan/upload",
            params={
                "user_id": user_id,
                "device_id": device["device_id"],
                "device_name": device["device_name"],
                "os_name": device["os_name"],
                "os_version": device["os_version"],
                "machine": device["machine"],
            },
            files={"file": (path.name, handle, "application/octet-stream")},
            timeout=120,
        )
    try:
        payload = response.json()
    except Exception:
        payload = {"message": response.text}
    if response.status_code >= 400:
        raise RuntimeError(payload.get("detail") or payload.get("message") or f"Upload failed: {response.status_code}")
    return payload


def result_status(payload: dict[str, Any]) -> str:
    scan = payload.get("scan_result") if isinstance(payload.get("scan_result"), dict) else payload
    result = str(payload.get("overall_result") or scan.get("overall_result") or "").strip()
    if result in {"Safe", "Suspicious", "Malicious"}:
        return result

    decision = str(scan.get("decision") or "").upper()
    prediction = str(scan.get("predicted_label") or "").lower()
    risk = scan.get("fused_risk")
    threshold = scan.get("stego_threshold") if isinstance(scan.get("stego_threshold"), (int, float)) else 0.7

    if decision == "BLOCKED":
        return "Malicious"
    if prediction == "stego" or decision == "STEGO":
        return "Suspicious"
    if isinstance(risk, (int, float)) and risk >= threshold:
        return "Suspicious"
    return "Safe"


def fetch_scan_result(backend_url: str, file_name: str, user_id: str) -> dict[str, Any] | None:
    response = requests.get(
        f"{backend_url.rstrip('/')}/api/scan/results/{quote(file_name)}",
        params={"user_id": user_id},
        timeout=30,
    )
    if response.status_code == 404:
        return None
    response.raise_for_status()
    return response.json()


def download_backend_file(backend_url: str, file_name: str, target_path: Path, user_id: str) -> None:
    response = requests.get(
        f"{backend_url.rstrip('/')}/api/scan/files/{quote(file_name)}",
        params={"user_id": user_id},
        timeout=120,
    )
    response.raise_for_status()
    target_path.parent.mkdir(parents=True, exist_ok=True)
    with target_path.open("wb") as handle:
        handle.write(response.content)


def delete_backend_file(backend_url: str, file_name: str, user_id: str) -> None:
    response = requests.delete(
        f"{backend_url.rstrip('/')}/api/scan/files/{quote(file_name)}",
        params={"user_id": user_id, "record_event": "false"},
        timeout=30,
    )
    if response.status_code not in {200, 404}:
        response.raise_for_status()


def restore_backend_file(record: dict[str, Any], reason: str) -> dict[str, Any]:
    backend_url = str(record.get("backend_url") or DEFAULT_BACKEND_URL).rstrip("/")
    user_id = str(record.get("user_id") or "guest")
    backend_file_name = str(record.get("backend_file_name") or "")
    original_path = Path(str(record.get("original_path") or ""))
    if not backend_file_name:
        raise FileNotFoundError("Backend file name missing from watcher state")

    restored_path = safe_restore_path(original_path)
    download_backend_file(backend_url, backend_file_name, restored_path, user_id)
    signature = file_signature(restored_path)
    record.update({
        "original_path": str(restored_path),
        "signature": signature,
        "status": "restored",
        "restored_reason": reason,
        "restored_ts": utc_now(),
    })
    write_event({
        "ts": record["restored_ts"],
        "path": str(restored_path),
        "file_name": restored_path.name,
        "status": "restored",
        "reason": reason,
    })
    return {"status": "restored", "path": str(restored_path), "file_name": restored_path.name}


def process_backend_held_files(state: dict[str, Any], backend_url: str, user_id: str) -> bool:
    changed = False
    for path_key, record in list(state["files"].items()):
        if record.get("status") != "uploaded_to_backend":
            continue

        backend_file_name = str(record.get("backend_file_name") or "")
        if not backend_file_name:
            continue

        try:
            payload = fetch_scan_result(backend_url, backend_file_name, user_id)
            if not payload or payload.get("status") in {"processing", "queued"}:
                continue

            verdict = result_status(payload)
            record["scan_result"] = verdict
            record["scan_ts"] = utc_now()
            if verdict == "Safe":
                restored = restore_backend_file(record, "safe_scan_result")
                restored_key = str(restored.get("path") or path_key)
                if restored_key != path_key:
                    state["files"][restored_key] = record
                    state["files"].pop(path_key, None)
                delete_backend_file(backend_url, backend_file_name, user_id)
            else:
                record["status"] = "held_for_review"
                write_event({
                    "ts": utc_now(),
                    "path": record.get("original_path") or path_key,
                    "file_name": backend_file_name,
                    "status": "held_for_review",
                    "scan_result": verdict,
                })
            changed = True
        except Exception as exc:
            global last_error
            last_error = str(exc)
    return changed


def scan_once() -> None:
    global last_error
    config = load_config()
    state = load_state()
    files = state["files"]
    now = time.time()
    changed = process_backend_held_files(state, config["backend_url"], config["user_id"])

    for path in iter_supported_files(config["folders"]):
        path_key = str(path)
        signature = file_signature(path)
        if not signature:
            continue

        known = files.get(path_key)
        if known and known.get("signature") == signature:
            continue

        current = pending.get(path_key)
        if not current or current.get("signature") != signature:
            pending[path_key] = {"signature": signature, "first_seen": now}
            continue

        if now - float(current.get("first_seen", now)) < STABLE_SECONDS:
            continue

        try:
            payload = upload_file(path, config["backend_url"], config["user_id"])
            path.unlink()
            event = {
                "ts": utc_now(),
                "path": path_key,
                "file_name": path.name,
                "backend_url": config["backend_url"],
                "user_id": config["user_id"],
                **load_device_info(),
                "status": "uploaded_to_backend",
                "backend_response": payload,
            }
            files[path_key] = {
                "signature": signature,
                "status": "uploaded_to_backend",
                "ts": event["ts"],
                "original_path": path_key,
                "backend_file_name": payload.get("file_name") or path.name,
                "backend_url": config["backend_url"],
                "user_id": config["user_id"],
                "device_id": event.get("device_id"),
                "device_name": event.get("device_name"),
                "os_name": event.get("os_name"),
            }
            pending.pop(path_key, None)
            write_event(event)
            last_error = None
            changed = True
        except Exception as exc:
            last_error = str(exc)
            write_event({"ts": utc_now(), "path": path_key, "file_name": path.name, "status": "error", "error": last_error})

    if changed:
        save_state(state)


def worker_loop() -> None:
    while True:
        with lock:
            scan_once()
        time.sleep(POLL_INTERVAL_SECONDS)


@app.on_event("startup")
def start_worker() -> None:
    config = load_config()
    save_config(config["folders"], config["backend_url"], config["user_id"])
    remember_existing_files(config["folders"])
    thread = threading.Thread(target=worker_loop, name="cybershield-folder-watcher", daemon=True)
    thread.start()


@app.get("/api/health")
def health() -> dict[str, Any]:
    config = load_config()
    invalid_folders = [folder for folder in config["folders"] if not Path(folder).is_dir()]
    return {
        "status": "ok",
        "folders": len(config["folders"]),
        "invalid_folders": invalid_folders,
        "backend_url": config["backend_url"],
        "last_error": last_error,
    }


@app.get("/api/device")
def get_device() -> dict[str, Any]:
    return load_device_info()


@app.get("/api/settings")
def get_settings() -> dict[str, Any]:
    config = load_config()
    return {**config, "supported_extensions": sorted(SUPPORTED_EXTENSIONS)}


@app.post("/api/settings")
def update_settings(settings: WatcherSettings) -> dict[str, Any]:
    config = save_config(settings.folders, settings.backend_url, settings.user_id)
    if not settings.scan_existing:
        remember_existing_files(config["folders"])
    return {**config, "status": "saved"}


@app.get("/api/pick-folder")
def pick_folder() -> dict[str, Any]:
    try:
        import tkinter as tk
        from tkinter import filedialog

        root = tk.Tk()
        root.withdraw()
        root.attributes("-topmost", True)
        root.update()
        selected = filedialog.askdirectory(title="Select a folder to monitor")
        root.destroy()
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Folder picker failed: {exc}") from exc

    return {"path": normalize_folder(selected) if selected else None}


@app.get("/api/events")
def get_events(limit: int = 50) -> dict[str, Any]:
    if not EVENTS_FILE.exists():
        return {"count": 0, "items": []}
    items: list[dict[str, Any]] = []
    for line in EVENTS_FILE.read_text(encoding="utf-8").splitlines()[-limit:]:
        try:
            items.append(json.loads(line))
        except Exception:
            continue
    items.reverse()
    return {"count": len(items), "items": items}


@app.get("/api/files/{file_name}")
def get_watched_file(file_name: str) -> dict[str, Any]:
    state = load_state()
    safe_name = Path(file_name).name
    for record in state["files"].values():
        if Path(str(record.get("backend_file_name") or "")).name == safe_name:
            return dict(record)
    raise HTTPException(status_code=404, detail="No watcher record found for this file")


@app.post("/api/files/{file_name}/restore")
def restore_file(file_name: str) -> dict[str, Any]:
    state = load_state()
    safe_name = Path(file_name).name
    for path_key, record in list(state["files"].items()):
        if record.get("status") not in {"uploaded_to_backend", "held_for_review"}:
            continue
        if Path(str(record.get("backend_file_name") or "")).name != safe_name:
            continue
        result = restore_backend_file(record, "user_approved")
        restored_key = str(result.get("path") or path_key)
        if restored_key != path_key:
            state["files"][restored_key] = record
            state["files"].pop(path_key, None)
        save_state(state)
        return result
    raise HTTPException(status_code=404, detail="No backend-held file found for this scan result")


@app.delete("/api/files/{file_name}")
def mark_backend_held_file_deleted(file_name: str) -> dict[str, Any]:
    state = load_state()
    safe_name = Path(file_name).name
    for record in state["files"].values():
        if record.get("status") not in {"uploaded_to_backend", "held_for_review"}:
            continue
        if Path(str(record.get("backend_file_name") or "")).name != safe_name:
            continue
        record["status"] = "deleted"
        record["deleted_ts"] = utc_now()
        save_state(state)
        write_event({
            "ts": record["deleted_ts"],
            "path": record.get("original_path"),
            "file_name": safe_name,
            "status": "deleted",
        })
        return {"status": "deleted", "file_name": safe_name}
    raise HTTPException(status_code=404, detail="No backend-held file found for this scan result")


if __name__ == "__main__":
    import uvicorn

    uvicorn.run("folder_watcher:app", host="127.0.0.1", port=8765, reload=False)
