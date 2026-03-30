from pathlib import Path
from importlib import import_module

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


def scan_file(file_path):
    module = _get_scanner_module(file_path)
    if module is None:
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
    return module.scan_file(file_path)


def ml_stack_status():
    stg_ready = False
    zd_ready = False
    stg_error = None
    zd_error = None

    try:
        stg_ready = bool(import_module("app.stg_scanner").ml_stack_status().get("ready"))
    except Exception as exc:
        stg_error = str(exc)

    try:
        zd_ready = bool(import_module("app.zd_scanner").ml_stack_status().get("ready"))
    except Exception as exc:
        zd_error = str(exc)

    return {
        "ready": stg_ready or zd_ready,
        "stg": {"ready": stg_ready, "error": stg_error},
        "zd": {"ready": zd_ready, "error": zd_error},
    }


def write_scan_event(payload):
    SCAN_LOG_FILE.parent.mkdir(parents=True, exist_ok=True)
    with SCAN_LOG_FILE.open("a", encoding="utf-8") as fh:
        import json
        fh.write(json.dumps(payload, ensure_ascii=False))
        fh.write("\n")
