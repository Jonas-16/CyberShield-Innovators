from __future__ import annotations

import json
from datetime import datetime, timezone
from importlib import import_module
from pathlib import Path
from typing import Any

import numpy as np
from PIL import Image

SCAN_LOG_FILE = Path(__file__).resolve().parent / "reports" / "scan_events.jsonl"
DEFAULT_REVIEW_THRESHOLD = 0.65
DEFAULT_UNSAFE_THRESHOLD = 0.80

IMAGE_EXTENSIONS = {".jpg", ".jpeg", ".jfif", ".png", ".bmp", ".gif", ".tif", ".tiff", ".webp"}
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
    if payload.get("reference_match"):
        return dict(payload)

    stego_prob = float(payload.get("stego_prob", 0.0) or 0.0)
    cover_prob = float(payload.get("cover_prob", 0.0) or 0.0)
    fused_risk = float(payload.get("fused_risk", stego_prob) or 0.0)
    risk_threshold = float(payload.get("stego_threshold", getattr(module, "DEFAULT_STEGO_THRESHOLD", 0.65)) or 0.65)
    is_stego = fused_risk >= risk_threshold
    normalized = dict(payload)
    normalized["path"] = str(payload.get("path", ""))
    normalized["file_name"] = payload.get("file_name")
    normalized["static_prob"] = stego_prob
    normalized["behavior_risk"] = payload.get("behavior_risk")
    normalized["fused_risk"] = fused_risk
    normalized["engine"] = payload.get("engine") or "stg-ml"
    normalized["confidence"] = float(payload.get("confidence", stego_prob if is_stego else cover_prob) or 0.0)
    normalized["stego_prob"] = stego_prob
    normalized["cover_prob"] = cover_prob
    normalized["stego_threshold"] = float(
        payload.get("stego_threshold", getattr(module, "DEFAULT_STEGO_THRESHOLD", 0.5)) or 0.5
    )
    normalized["review_threshold"] = DEFAULT_REVIEW_THRESHOLD
    normalized["unsafe_threshold"] = DEFAULT_UNSAFE_THRESHOLD
    normalized["image_size"] = payload.get("image_size", getattr(module, "DEFAULT_IMAGE_SIZE", None))
    normalized.setdefault("predicted_label", "Stego" if is_stego else "Cover")
    normalized.setdefault("decision", "STEGO" if is_stego else "COVER")
    normalized.setdefault("reasons", ["steganography detected"] if is_stego else ["no steganography detected"])
    return normalized


def _has_cybershield_sanitized_marker(target: Path) -> bool:
    try:
        with Image.open(target) as image:
            return str(image.info.get("CyberShieldSanitized", "")).lower() == "true"
    except Exception:
        return False


def _rgb_lsb_planes_are_clear(target: Path) -> bool:
    try:
        with Image.open(target) as image:
            if image.mode not in {"RGB", "RGBA", "L"}:
                image = image.convert("RGBA" if "A" in image.getbands() else "RGB")
            arr = np.array(image, dtype=np.uint8)
    except Exception:
        return False

    if arr.ndim == 2:
        return bool(np.all((arr & 1) == 0))

    channels_to_check = min(3, arr.shape[2])
    return bool(np.all((arr[:, :, :channels_to_check] & 1) == 0))


def _looks_like_cleaned_image(target: Path, decoder_result: dict[str, Any]) -> bool:
    if decoder_result.get("readable_message_found"):
        return False
    if int(decoder_result.get("candidate_count") or 0) > 0:
        return False
    suspected_tool = str(decoder_result.get("suspected_tool") or "").lower()
    if decoder_result.get("likely_encrypted_or_protected") and "or clean jpeg" not in suspected_tool:
        return False
    return _has_cybershield_sanitized_marker(target) and _rgb_lsb_planes_are_clear(target)


def _image_scan_is_safe(payload: dict[str, Any]) -> bool:
    decision = str(payload.get("decision") or "").upper()
    predicted_label = str(payload.get("predicted_label") or "").lower()
    warning = str(payload.get("scanner_warning") or "")
    risk = payload.get("fused_risk")
    threshold = payload.get("stego_threshold")
    threshold = float(threshold) if isinstance(threshold, (int, float)) else 0.65

    if warning:
        return False
    if decision in {"STEGO", "UNCERTAIN", "PENDING", "IGNORED", "BLOCKED"}:
        return False
    if predicted_label == "stego":
        return False
    if isinstance(risk, (int, float)) and float(risk) >= threshold:
        return False
    return decision in {"COVER", "ALLOWED"} or predicted_label == "cover"


def _attach_decoder_result(payload: dict[str, Any], target: Path) -> dict[str, Any]:
    enriched = dict(payload)
    if _image_scan_is_safe(enriched):
        enriched["stego_decoder"] = {
            "available": False,
            "skipped": True,
            "reason": "File is safe; nothing to decode.",
            "readable_message_found": False,
            "candidate_count": 0,
            "artifact_count": 0,
        }
        enriched["hidden_payload_found"] = False
        return enriched

    try:
        decoder = import_module("app.scanners.stg_decoder.scanner")
        decoder_result = decoder.scan_file(target)
    except Exception as exc:
        enriched["stego_decoder"] = {
            "available": False,
            "error": str(exc),
        }
        return enriched

    enriched["stego_decoder"] = {
        **decoder_result,
        "available": True,
    }

    reasons = list(enriched.get("reasons") or [])
    candidate_count = int(decoder_result.get("candidate_count") or 0)
    suspected_tool = str(decoder_result.get("suspected_tool") or "").lower()
    generic_jpeg_uncertainty = "or clean jpeg" in suspected_tool
    cleaned_image = _looks_like_cleaned_image(target, decoder_result)

    if cleaned_image:
        enriched["decision"] = "COVER"
        enriched["predicted_label"] = "Cover"
        enriched["fused_risk"] = min(float(enriched.get("fused_risk") or 0.0), 0.10)
        enriched["stego_prob"] = min(float(enriched.get("stego_prob") or 0.0), 0.10)
        enriched["cover_prob"] = max(float(enriched.get("cover_prob") or 0.0), 0.90)
        enriched["confidence"] = max(float(enriched.get("confidence") or 0.0), 0.90)
        reasons.append("cleaned image has no recovered payload and RGB LSB planes are clear")
    elif decoder_result.get("readable_message_found"):
        enriched["decision"] = "STEGO"
        enriched["predicted_label"] = "Stego"
        enriched["fused_risk"] = max(float(enriched.get("fused_risk") or 0.0), 0.95)
        reasons.append("readable hidden payload recovered")
    elif decoder_result.get("likely_encrypted_or_protected") and not generic_jpeg_uncertainty:
        if enriched.get("decision") in {"ALLOWED", "COVER"}:
            enriched["decision"] = "UNCERTAIN"
        enriched["fused_risk"] = max(float(enriched.get("fused_risk") or 0.0), 0.70)
        reasons.append("decoder found protected or encrypted steganography indicators")
    elif candidate_count > 0:
        enriched["fused_risk"] = max(float(enriched.get("fused_risk") or 0.0), 0.75)
        reasons.append("decoder produced hidden-message candidates")

    enriched["reasons"] = list(dict.fromkeys(reason for reason in reasons if reason))
    enriched["hidden_payload_found"] = bool(decoder_result.get("readable_message_found"))
    enriched["cleaned_image_verified"] = bool(cleaned_image)
    enriched["decoder_report_url"] = decoder_result.get("report_url")
    enriched["sanitized_image_url"] = (decoder_result.get("sanitized_image") or {}).get("url")
    return enriched


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
            enable_tta=bool(kwargs.get("enable_tta", getattr(module, "DEFAULT_TTA_ENABLED", False))),
            log_event=False,
        )
        payload = _normalize_image_result(raw_result, module)
        payload = _attach_decoder_result(payload, target)
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
