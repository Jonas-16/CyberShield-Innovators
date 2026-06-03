from __future__ import annotations

from functools import lru_cache
from pathlib import Path
from typing import Any

SCAN_LOG_FILE = Path(__file__).resolve().parent / 'reports' / 'scan_events.jsonl'
IMAGE_EXTENSIONS = {'.jpg', '.jpeg', '.png', '.bmp', '.tif', '.tiff', '.webp'}
EXECUTABLE_EXTENSIONS = {'.exe'}
APK_EXTENSIONS = {'.apk'}


@lru_cache(maxsize=1)
def _get_zd_scanner():
    from app import zd_scanner
    return zd_scanner


@lru_cache(maxsize=1)
def _get_stg_scanner():
    from app import stg_scanner
    return stg_scanner


@lru_cache(maxsize=1)
def _get_stg_decoder():
    from app.scanners.stg_decoder import scanner
    return scanner


@lru_cache(maxsize=1)
def _get_apk_scanner():
    from app import apk_scanner
    return apk_scanner


def write_scan_event(payload: dict[str, Any]) -> dict[str, Any]:
    return _get_zd_scanner().write_scan_event(payload)


def _is_image_file(target: Path) -> bool:
    return target.suffix.lower() in IMAGE_EXTENSIONS


def _is_executable_file(target: Path) -> bool:
    return target.suffix.lower() in EXECUTABLE_EXTENSIONS


def _is_apk_file(target: Path) -> bool:
    return target.suffix.lower() in APK_EXTENSIONS


def is_supported_file(file_path: str | Path) -> bool:
    target = Path(file_path)
    return _is_image_file(target) or _is_executable_file(target) or _is_apk_file(target)


def _normalize_stg_result(payload: dict[str, Any]) -> dict[str, Any]:
    if payload.get('reference_match'):
        return dict(payload)

    stg_scanner = _get_stg_scanner()
    zd_scanner = _get_zd_scanner()

    stego_prob = float(payload.get('stego_prob', 0.0))
    risk_threshold = float(payload.get('stego_threshold', stg_scanner.DEFAULT_STEGO_THRESHOLD))
    is_stego = stego_prob >= risk_threshold
    predicted_label = 'Stego' if is_stego else 'Cover'

    return {
        'path': str(payload.get('path', '')),
        'file_name': payload.get('file_name'),
        'decision': 'UNCERTAIN' if is_stego else 'ALLOWED',
        'static_prob': stego_prob,
        'behavior_risk': None,
        'fused_risk': stego_prob,
        'engine': 'stg-ml',
        'reasons': ['steganography detected'] if is_stego else ['no steganography detected'],
        'scanner_stage': None,
        'scanner_warning': None,
        'stego_prob': stego_prob,
        'cover_prob': float(payload.get('cover_prob', 0.0)),
        'predicted_label': predicted_label,
        'confidence': float(payload.get('confidence', 0.0)),
        'stego_threshold': float(payload.get('stego_threshold', stg_scanner.DEFAULT_STEGO_THRESHOLD)),
        'clean_threshold': payload.get('clean_threshold'),
        'config_ignored': payload.get('config_ignored'),
        'config_ignored_reason': payload.get('config_ignored_reason'),
        'block_threshold': float(zd_scanner.DEFAULT_BLOCK_THRESHOLD),
        'allow_threshold': float(zd_scanner.DEFAULT_ALLOW_THRESHOLD),
    }


def _attach_decoder_result(payload: dict[str, Any], target: Path) -> dict[str, Any]:
    enriched = dict(payload)
    try:
        decoder_result = _get_stg_decoder().scan_file(target)
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

    if decoder_result.get("readable_message_found"):
        enriched["decision"] = "STEGO"
        enriched["predicted_label"] = "Stego"
        enriched["fused_risk"] = max(float(enriched.get("fused_risk") or 0.0), 0.95)
        reasons.append("readable hidden payload recovered")
    elif decoder_result.get("likely_encrypted_or_protected") and not generic_jpeg_uncertainty:
        enriched["decision"] = "UNCERTAIN" if enriched.get("decision") in {"ALLOWED", "COVER"} else enriched.get("decision")
        enriched["fused_risk"] = max(float(enriched.get("fused_risk") or 0.0), 0.70)
        reasons.append("decoder found protected or encrypted steganography indicators")
    elif candidate_count > 0:
        enriched["fused_risk"] = max(float(enriched.get("fused_risk") or 0.0), 0.75)
        reasons.append("decoder produced hidden-message candidates")

    enriched["reasons"] = list(dict.fromkeys(reason for reason in reasons if reason))
    enriched["hidden_payload_found"] = bool(decoder_result.get("readable_message_found"))
    enriched["decoder_report_url"] = decoder_result.get("report_url")
    enriched["sanitized_image_url"] = (decoder_result.get("sanitized_image") or {}).get("url")
    return enriched


def scan_file(file_path: str | Path, log_event: bool = True, **kwargs: Any) -> dict[str, Any]:
    target = Path(file_path)

    if _is_image_file(target):
        stg_scanner = _get_stg_scanner()
        image_size = int(kwargs.get('image_size', stg_scanner.DEFAULT_IMAGE_SIZE))
        stego_threshold = float(kwargs.get('stego_threshold', stg_scanner.DEFAULT_STEGO_THRESHOLD))
        raw_result = stg_scanner.scan_file(
            target,
            image_size=image_size,
            stego_threshold=stego_threshold,
            log_event=False,
        )
        payload = _normalize_stg_result(raw_result)
        payload = _attach_decoder_result(payload, target)
        if log_event:
            return write_scan_event(payload)
        return payload

    if _is_apk_file(target):
        return _get_apk_scanner().scan_file(target, log_event=log_event)

    if not _is_executable_file(target):
        raise ValueError(f"Unsupported file type for scanning: {target.suffix.lower() or '<no extension>'}")

    zd_scanner = _get_zd_scanner()
    return zd_scanner.scan_file(
        target,
        block_threshold=float(kwargs.get('block_threshold', zd_scanner.DEFAULT_BLOCK_THRESHOLD)),
        allow_threshold=float(kwargs.get('allow_threshold', zd_scanner.DEFAULT_ALLOW_THRESHOLD)),
        fusion_alpha=float(kwargs.get('fusion_alpha', 0.7)),
        log_event=log_event,
    )


def ml_stack_status() -> dict[str, Any]:
    zd_status = _get_zd_scanner().ml_stack_status()
    stg_status = _get_stg_scanner().scanner_status()
    apk_status = _get_apk_scanner().ml_stack_status()
    return {
        'ready': bool(zd_status.get('ready')) and bool(stg_status.get('ready')) and bool(apk_status.get('ready')),
        'zd': zd_status,
        'stg': stg_status,
        'apk': apk_status,
    }

