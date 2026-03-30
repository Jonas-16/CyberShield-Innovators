from __future__ import annotations

from app.scanners.stg.scanner import (
    DEFAULT_IMAGE_SIZE,
    DEFAULT_STEGO_THRESHOLD,
    scan_directory,
    scan_file,
    scanner_status,
    write_scan_event,
)


def ml_stack_status():
    return scanner_status()

