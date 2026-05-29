from __future__ import annotations

import contextlib
import hashlib
import io
from datetime import datetime
from pathlib import Path
from typing import Any

import numpy as np
from PIL import Image, ImageOps
from PIL.PngImagePlugin import PngInfo

from . import hstego

APP_ROOT = Path(__file__).resolve().parents[2]
REPORT_ROOT = APP_ROOT / "reports" / "stego_decoder"
DEFAULT_GUESS_LIMIT = 30


def _safe_report_id(target: Path) -> str:
    stamp = datetime.utcnow().strftime("%Y%m%d%H%M%S")
    digest = hashlib.sha256(str(target.resolve()).encode("utf-8", errors="ignore")).hexdigest()[:12]
    stem = "".join(ch if ch.isalnum() or ch in {"-", "_"} else "-" for ch in target.stem).strip("-")
    return f"{stamp}-{digest}-{stem[:40] or 'image'}"


def _public_report_url(report_id: str, file_name: str = "scan_report.html") -> str:
    return f"/api/scan/reports/{report_id}/{file_name}"


def _write_sanitized_image(input_path: Path, output_dir: Path) -> dict[str, Any]:
    output_name = f"cleaned_{input_path.stem[:80] or 'image'}.png"
    output_path = output_dir / output_name

    with Image.open(input_path) as image:
        image = ImageOps.exif_transpose(image)
        if image.mode not in {"RGB", "RGBA", "L"}:
            image = image.convert("RGBA" if "A" in image.getbands() else "RGB")

        arr = np.array(image, dtype=np.uint8)
        if arr.ndim == 2:
            arr = arr & 0xFE
            cleaned = Image.fromarray(arr, mode="L")
        else:
            cleaned_arr = arr.copy()
            channels_to_clean = min(3, cleaned_arr.shape[2])
            cleaned_arr[:, :, :channels_to_clean] = cleaned_arr[:, :, :channels_to_clean] & 0xFE
            cleaned = Image.fromarray(cleaned_arr, mode=image.mode)

        metadata = PngInfo()
        metadata.add_text("CyberShieldSanitized", "true")
        metadata.add_text("CyberShieldSanitizer", "metadata-stripped-lsb-cleared")
        cleaned.save(output_path, format="PNG", pnginfo=metadata, optimize=True)

    return {
        "path": str(output_path),
        "file_name": output_path.name,
        "url": output_path.name,
        "cybershield_sanitized": True,
        "method": "metadata removed, image re-encoded as PNG, RGB least-significant bits cleared",
    }


def scan_file(
    file_path: str | Path,
    *,
    expected_text: str | None = None,
    passphrase: str | None = None,
    wordlist_path: str | None = None,
    wordlist_limit: int = 500,
    guess_seeds: list[str] | None = None,
    guess_limit: int = DEFAULT_GUESS_LIMIT,
) -> dict[str, Any]:
    target = Path(file_path)
    if not target.exists() or not target.is_file():
        raise FileNotFoundError(f"Target file not found: {target}")

    REPORT_ROOT.mkdir(parents=True, exist_ok=True)
    report_id = _safe_report_id(target)
    output_dir = REPORT_ROOT / report_id

    stdout = io.StringIO()
    with contextlib.redirect_stdout(stdout):
        summary = hstego.scan(
            target,
            output_dir,
            expected_text=expected_text,
            passphrase=passphrase,
            wordlist_path=wordlist_path,
            wordlist_limit=wordlist_limit,
            guess_seeds=guess_seeds,
            guess_limit=guess_limit,
        )

    summary = dict(summary or {})
    try:
        sanitized = _write_sanitized_image(target, output_dir)
        sanitized["url"] = _public_report_url(report_id, sanitized["file_name"])
        summary["sanitized_image"] = sanitized
    except Exception as exc:
        summary["sanitized_image"] = {
            "error": str(exc),
            "method": "metadata removal and LSB clearing could not be completed",
        }

    summary["report_id"] = report_id
    summary["report_url"] = _public_report_url(report_id)
    summary["text_report_url"] = _public_report_url(report_id, "scan_report.txt")
    summary["stdout"] = stdout.getvalue().strip()
    return summary
