from __future__ import annotations

from functools import lru_cache
from pathlib import Path
from typing import Any

SCAN_LOG_FILE = Path(__file__).resolve().parent / 'reports' / 'scan_events.jsonl'
IMAGE_EXTENSIONS = {'.jpg', '.jpeg', '.png', '.bmp', '.tif', '.tiff', '.webp'}
EXECUTABLE_EXTENSIONS = {'.exe'}


@lru_cache(maxsize=1)
def _get_zd_scanner():
    from app import zd_scanner
    return zd_scanner


@lru_cache(maxsize=1)
def _get_stg_scanner():
    from app import stg_scanner
    return stg_scanner


def write_scan_event(payload: dict[str, Any]) -> dict[str, Any]:
    return _get_zd_scanner().write_scan_event(payload)


def _is_image_file(target: Path) -> bool:
    return target.suffix.lower() in IMAGE_EXTENSIONS


def _is_executable_file(target: Path) -> bool:
    return target.suffix.lower() in EXECUTABLE_EXTENSIONS


def is_supported_file(file_path: str | Path) -> bool:
    target = Path(file_path)
    return _is_image_file(target) or _is_executable_file(target)


def _normalize_stg_result(payload: dict[str, Any]) -> dict[str, Any]:
    stg_scanner = _get_stg_scanner()
    zd_scanner = _get_zd_scanner()

    stego_prob = float(payload.get('stego_prob', 0.0))
    predicted_label = str(payload.get('predicted_label', payload.get('decision', 'Unknown')))
    is_stego = predicted_label.lower() == 'stego'

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
        'block_threshold': float(zd_scanner.DEFAULT_BLOCK_THRESHOLD),
        'allow_threshold': float(zd_scanner.DEFAULT_ALLOW_THRESHOLD),
    }


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
        if log_event:
            return write_scan_event(payload)
        return payload

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
    return {
        'ready': bool(zd_status.get('ready')) and bool(stg_status.get('ready')),
        'zd': zd_status,
        'stg': stg_status,
    }

