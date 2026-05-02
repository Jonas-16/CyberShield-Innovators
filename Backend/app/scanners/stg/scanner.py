from __future__ import annotations

import argparse
import json
import os
from datetime import datetime
from functools import lru_cache
from pathlib import Path
from typing import Any

import numpy as np
import torch
from PIL import Image
from torch import Tensor, nn
from torchvision import models

Image.MAX_IMAGE_PIXELS = None

APP_ROOT = Path(__file__).resolve().parents[2]
MODEL_PATH = APP_ROOT / "models" / "stg_models" / "base_v2.pth"
REPORTS_DIR = APP_ROOT / "reports"
REPORTS_DIR.mkdir(parents=True, exist_ok=True)
SCAN_LOG_FILE = REPORTS_DIR / "scan_events.jsonl"

DEFAULT_IMAGE_SIZE = 512
DEFAULT_STEGO_THRESHOLD = 0.5
DEFAULT_CLEAN_THRESHOLD = 0.5
DEFAULT_TTA_ENABLED = os.environ.get("STG_ENABLE_TTA", "0").strip().lower() in {"1", "true", "yes", "on"}


class ScannerError(RuntimeError):
    def __init__(self, stage: str, message: str):
        super().__init__(message)
        self.stage = stage


def write_scan_event(payload: dict[str, Any]) -> dict[str, Any]:
    event = dict(payload)
    event.setdefault("ts", datetime.utcnow().isoformat(timespec="seconds") + "Z")
    with SCAN_LOG_FILE.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(event) + "\n")
    return event


class BaseV2Net(nn.Module):
    def __init__(self) -> None:
        super().__init__()
        backbone = models.resnet50(weights=None)
        self.conv1 = nn.Conv2d(3, 64, kernel_size=3, stride=1, padding=1, bias=False)
        self.bn1 = backbone.bn1
        self.relu = backbone.relu
        self.maxpool = nn.Identity()
        self.layer1 = backbone.layer1
        self.layer2 = backbone.layer2
        self.avgpool = nn.AdaptiveAvgPool2d((1, 1))
        self.fc1 = nn.Linear(512, 1)

    def forward(self, x: Tensor) -> Tensor:
        x = self.conv1(x)
        x = self.bn1(x)
        x = self.relu(x)
        x = self.maxpool(x)
        x = self.layer1(x)
        x = self.layer2(x)
        x = self.avgpool(x)
        x = torch.flatten(x, 1)
        x = self.fc1(x)
        return x


@lru_cache(maxsize=1)
def load_model(model_path: Path = MODEL_PATH) -> nn.Module:
    if not model_path.exists():
        raise ScannerError("model_file", f"Model not found: {model_path}")

    device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
    model = BaseV2Net().to(device)

    try:
        try:
            state_dict = torch.load(str(model_path), map_location=device, weights_only=True)
        except TypeError:
            state_dict = torch.load(str(model_path), map_location=device)
    except Exception as exc:
        raise ScannerError("load_checkpoint", str(exc)) from exc

    if not isinstance(state_dict, dict):
        raise ScannerError("checkpoint_format", "Expected a state_dict in base_v2.pth.")

    try:
        model.load_state_dict(state_dict, strict=True)
    except Exception as exc:
        raise ScannerError("load_state_dict", str(exc)) from exc

    model.eval()
    return model


def preprocess_image(image_path: Path, image_size: int = DEFAULT_IMAGE_SIZE) -> np.ndarray:
    try:
        image = Image.open(image_path).convert("RGB")
    except Exception as exc:
        raise ScannerError("open_image", str(exc)) from exc

    image = image.resize((image_size, image_size))
    image_array = np.asarray(image, dtype=np.float32) / 255.0
    return image_array


def build_augmented_batch(image_array: np.ndarray, enable_tta: bool = DEFAULT_TTA_ENABLED) -> Tensor:
    variants = [image_array]
    if enable_tta:
        variants.extend(
            [
                np.flip(image_array, axis=1).copy(),
                np.flip(image_array, axis=0).copy(),
                np.flip(np.flip(image_array, axis=0), axis=1).copy(),
            ]
        )
    tensors = [torch.from_numpy(np.transpose(variant, (2, 0, 1))).float() for variant in variants]
    return torch.stack(tensors, dim=0)


def _build_result(
    target: Path,
    clean_confidence: float,
    stego_prob: float,
    image_size: int,
    score_variants: list[float],
) -> dict[str, Any]:
    is_stego = stego_prob >= DEFAULT_STEGO_THRESHOLD
    predicted_label = "Stego" if is_stego else "Cover"
    confidence = stego_prob if is_stego else clean_confidence
    probabilities = {
        "Cover": clean_confidence,
        "Stego": stego_prob,
    }
    return {
        "path": str(target),
        "file_name": target.name,
        "decision": "STEGO" if is_stego else "COVER",
        "predicted_label": predicted_label,
        "confidence": float(confidence),
        "cover_prob": float(clean_confidence),
        "stego_prob": float(stego_prob),
        "probabilities": probabilities,
        "image_size": image_size,
        "model_path": str(MODEL_PATH),
        "score_variants": score_variants,
    }


def scan_file(
    file_path: str | Path,
    image_size: int = DEFAULT_IMAGE_SIZE,
    stego_threshold: float = DEFAULT_STEGO_THRESHOLD,
    enable_tta: bool = DEFAULT_TTA_ENABLED,
    log_event: bool = True,
) -> dict[str, Any]:
    target = Path(file_path)
    if not target.exists() or not target.is_file():
        raise FileNotFoundError(f"Target file not found: {target}")

    model = load_model()
    device = next(model.parameters()).device
    image_array = preprocess_image(target, image_size=image_size)
    batch = build_augmented_batch(image_array, enable_tta=enable_tta).to(device)

    with torch.inference_mode():
        logits = model(batch).reshape(-1)
        variant_scores = torch.sigmoid(logits).detach().cpu().numpy().astype(float)

    stego_prob = float(np.mean(variant_scores))
    clean_confidence = float(max(0.0, min(1.0, 1.0 - stego_prob)))
    payload = _build_result(
        target=target,
        clean_confidence=clean_confidence,
        stego_prob=stego_prob,
        image_size=image_size,
        score_variants=[float(score) for score in variant_scores.tolist()],
    )
    payload["stego_threshold"] = float(stego_threshold)
    payload["clean_threshold"] = float(DEFAULT_CLEAN_THRESHOLD)
    payload["score"] = stego_prob
    payload["tta_enabled"] = bool(enable_tta)

    if stego_prob < stego_threshold:
        payload["decision"] = "COVER"
        payload["predicted_label"] = "Cover"
        payload["confidence"] = clean_confidence
    else:
        payload["decision"] = "STEGO"
        payload["predicted_label"] = "Stego"
        payload["confidence"] = stego_prob

    if log_event:
        return write_scan_event(payload)
    return payload


def scan_directory(
    directory: str | Path,
    image_size: int = DEFAULT_IMAGE_SIZE,
    stego_threshold: float = DEFAULT_STEGO_THRESHOLD,
    enable_tta: bool = DEFAULT_TTA_ENABLED,
    log_event: bool = False,
) -> list[dict[str, Any]]:
    target_dir = Path(directory)
    if not target_dir.exists() or not target_dir.is_dir():
        raise FileNotFoundError(f"Directory not found: {target_dir}")

    supported_exts = {".jpg", ".jpeg", ".jfif", ".png", ".bmp", ".gif", ".tif", ".tiff", ".webp"}
    results: list[dict[str, Any]] = []
    for path in sorted(target_dir.iterdir()):
        if path.is_file() and path.suffix.lower() in supported_exts:
            results.append(
                scan_file(
                    path,
                    image_size=image_size,
                    stego_threshold=stego_threshold,
                    enable_tta=enable_tta,
                    log_event=log_event,
                )
            )
    return results


def scanner_status() -> dict[str, Any]:
    status: dict[str, Any] = {
        "model_path": str(MODEL_PATH),
        "model_exists": MODEL_PATH.exists(),
        "torch": True,
        "pillow": True,
        "torchvision": True,
        "ready": False,
        "classes": ["Cover", "Stego"],
        "errors": [],
        "image_size": DEFAULT_IMAGE_SIZE,
        "tta_enabled": DEFAULT_TTA_ENABLED,
    }

    try:
        load_model.cache_clear()
        load_model()
        status["ready"] = True
    except Exception as exc:
        status["errors"].append(str(exc))
    return status


def main() -> None:
    parser = argparse.ArgumentParser(description="Scan image files with the local steganalysis model.")
    parser.add_argument("target", type=Path, help="Image file or directory to scan")
    parser.add_argument("--image-size", type=int, default=DEFAULT_IMAGE_SIZE)
    parser.add_argument("--stego-threshold", type=float, default=DEFAULT_STEGO_THRESHOLD)
    parser.add_argument("--enable-tta", action="store_true", help="Run 4-way test-time augmentation for stego scans")
    parser.add_argument("--status", action="store_true", help="Show model readiness and exit")
    args = parser.parse_args()

    if args.status:
        print(json.dumps(scanner_status(), indent=2))
        return

    if args.target.is_dir():
        result = scan_directory(
            args.target,
            image_size=args.image_size,
            stego_threshold=args.stego_threshold,
            enable_tta=args.enable_tta,
        )
    else:
        result = scan_file(
            args.target,
            image_size=args.image_size,
            stego_threshold=args.stego_threshold,
            enable_tta=args.enable_tta,
        )
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
