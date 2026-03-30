from __future__ import annotations

import json
from datetime import datetime, timezone
from importlib import import_module
from pathlib import Path
from typing import Any

SCAN_LOG_FILE = Path(__file__).resolve().parent / "reports" / "scan_events.jsonl"

IMAGE_EXTENSIONS = {".jpg", ".jpeg", ".png", ".bmp", ".tif", ".tiff", ".webp"}
ZD_EXTENSIONS = {".exe"}
SUPPORTED_EXTENSIONS = IMAGE_EXTENSIONS | ZD_EXTENSIONS


def is_supported_file(file_path):
    return Path(file_path).suffix.lower() in SUPPORTED_EXTENSIONS


def _get_scanner_module(file_path):
    suffix = Path(file_path).suffix.lower()
    if suffix in IMAGE_EXTENSIONS:
        return import_module("app.stg_scanner")
    if suffix in ZD_EXTENSIONS:
        return import_module("app.zd_scanner")
    return None


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def _normalize_image_result(payload: dict[str, Any], module: Any) -> dict[str, Any]:
    stego_prob = float(payload.get("stego_prob", 0.0) or 0.0)
    cover_prob = float(payload.get("cover_prob", 0.0) or 0.0)
    predicted_label = str(payload.get("predicted_label", payload.get("decision", "Unknown")))
    is_stego = predicted_label.strip().lower() == "stego"

    return {
        "path": str(payload.get("path", "")),
        "file_name": payload.get("file_name"),
        "decision": "UNCERTAIN" if is_stego else "ALLOWED",
        "static_prob": stego_prob,
        "behavior_risk": None,
        "fused_risk": stego_prob,
        "engine": "stg-ml",
        "reasons": ["steganography detected"] if is_stego else ["no steganography detected"],
        "scanner_stage": None,
        "scanner_warning": None,
        "predicted_label": predicted_label,
        "confidence": float(payload.get("confidence", stego_prob if is_stego else cover_prob) or 0.0),
        "stego_prob": stego_prob,
        "cover_prob": cover_prob,
        "stego_threshold": float(payload.get("stego_threshold", getattr(module, "DEFAULT_STEGO_THRESHOLD", 0.5)) or 0.5),
        "image_size": payload.get("image_size", getattr(module, "DEFAULT_IMAGE_SIZE", None)),
        "model_path": payload.get("model_path"),
        "checkpoint_epoch": payload.get("checkpoint_epoch"),
        "checkpoint_val_acc": payload.get("checkpoint_val_acc"),
        "checkpoint_val_auc": payload.get("checkpoint_val_auc"),
    }


def _unsupported_payload(file_path: str | Path) -> dict[str, Any]:
    path = Path(file_path)
    return {
        "path": str(path),
        "file_name": path.name,
        "decision": "IGNORED",
        "static_prob": None,
        "behavior_risk": None,
        "fused_risk": None,
        "engine": "unsupported",
        "reasons": ["unsupported file type"],
        "scanner_stage": None,
        "scanner_warning": None,
    }


def scan_file(file_path: str | Path, log_event: bool = True, **kwargs: Any):
    target = Path(file_path)
    module = _get_scanner_module(target)
    if module is None:
        payload = _unsupported_payload(target)
        return write_scan_event(payload) if log_event else payload

    suffix = target.suffix.lower()
    if suffix in IMAGE_EXTENSIONS:
        raw_result = module.scan_file(
            target,
            image_size=int(kwargs.get("image_size", getattr(module, "DEFAULT_IMAGE_SIZE", 96))),
            stego_threshold=float(kwargs.get("stego_threshold", getattr(module, "DEFAULT_STEGO_THRESHOLD", 0.5))),
            log_event=False,
        )
        payload = _normalize_image_result(raw_result, module)
    else:
        payload = module.scan_file(
            target,
            block_threshold=float(kwargs.get("block_threshold", getattr(module, "DEFAULT_BLOCK_THRESHOLD", 0.8))),
            allow_threshold=float(kwargs.get("allow_threshold", getattr(module, "DEFAULT_ALLOW_THRESHOLD", 0.2))),
            fusion_alpha=float(kwargs.get("fusion_alpha", 0.7)),
            log_event=False,
        )

    return write_scan_event(payload) if log_event else payload


def ml_stack_status():
    stg_ready = False
    zd_ready = False
    stg_error = None
    zd_error = None

    try:
        stg_module = import_module("app.stg_scanner")
        status_fn = getattr(stg_module, "ml_stack_status", None) or getattr(stg_module, "scanner_status", None)
        if status_fn is None:
            raise AttributeError("stg scanner status function not available")
        stg_status = status_fn()
        stg_ready = bool(stg_status.get("ready"))
    except Exception as exc:
        stg_error = str(exc)

    try:
        zd_status = import_module("app.zd_scanner").ml_stack_status()
        zd_ready = bool(zd_status.get("ready"))
    except Exception as exc:
        zd_error = str(exc)

    return {
        "ready": stg_ready or zd_ready,
        "stg": {"ready": stg_ready, "error": stg_error},
        "zd": {"ready": zd_ready, "error": zd_error},
    }


def preload_ml_stacks() -> dict[str, Any]:
    return ml_stack_status()


def write_scan_event(payload):
    SCAN_LOG_FILE.parent.mkdir(parents=True, exist_ok=True)
    with SCAN_LOG_FILE.open("a", encoding="utf-8") as fh:
        event = dict(payload)
        event.setdefault("ts", _utc_now())
        fh.write(json.dumps(event, ensure_ascii=False))
        fh.write("\n")
    return event
