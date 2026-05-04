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

try:
    import cv2  # type: ignore
except Exception:
    cv2 = None

try:
    from efficientnet_pytorch import EfficientNet  # type: ignore
except Exception:
    EfficientNet = None

Image.MAX_IMAGE_PIXELS = None

APP_ROOT = Path(__file__).resolve().parents[2]
MODEL_PATH = APP_ROOT / "models" / "stg_models" / "base_v2.pth"
MODEL_BIN_PATH = APP_ROOT / "models" / "stg_models" / "model.bin"
DETECTOR_CONFIG_PATH = APP_ROOT / "models" / "stg_models" / "detector_config.json"
REPORTS_DIR = APP_ROOT / "reports"
REPORTS_DIR.mkdir(parents=True, exist_ok=True)
SCAN_LOG_FILE = REPORTS_DIR / "scan_events.jsonl"

DEFAULT_IMAGE_SIZE = 512
DEFAULT_CLEAN_THRESHOLD = float(os.environ.get("STG_CLEAN_THRESHOLD", "0.35"))
DEFAULT_STEGO_THRESHOLD = float(os.environ.get("STG_STEGO_THRESHOLD", "0.55"))
DEFAULT_TTA_ENABLED = os.environ.get("STG_ENABLE_TTA", "1").strip().lower() in {"1", "true", "yes", "on"}
IMAGENET_MEAN = np.asarray((0.485, 0.456, 0.406), dtype=np.float32)
IMAGENET_STD = np.asarray((0.229, 0.224, 0.225), dtype=np.float32)
BASE_TTA_MODES = ("identity", "hflip", "vflip", "hvflip")
ROBUST_TTA_MODES = ("identity", "hflip", "vflip", "hvflip", "transpose", "transpose_h", "transpose_v", "rot180")


class ScannerError(RuntimeError):
    def __init__(self, stage: str, message: str):
        super().__init__(message)
        self.stage = stage


def load_detector_config(config_path: Path = DETECTOR_CONFIG_PATH) -> dict[str, Any] | None:
    if not config_path.exists():
        return None
    try:
        with config_path.open("r", encoding="utf-8") as handle:
            return json.load(handle)
    except Exception as exc:
        raise ScannerError("load_detector_config", str(exc)) from exc


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


def get_net() -> nn.Module:
    if EfficientNet is None:
        raise ScannerError("import_efficientnet", "efficientnet_pytorch is not installed.")
    net = EfficientNet.from_name("efficientnet-b4")
    net._fc = nn.Linear(in_features=1792, out_features=4, bias=True)
    return net


def _load_state_dict(model_path: Path, device: torch.device) -> Any:
    try:
        try:
            return torch.load(str(model_path), map_location=device, weights_only=True)
        except TypeError:
            return torch.load(str(model_path), map_location=device)
    except Exception as exc:
        raise ScannerError("load_checkpoint", str(exc)) from exc


def _load_base_v2_model(model_path: Path, device: torch.device) -> dict[str, Any]:
    model = BaseV2Net().to(device)
    state_dict = _load_state_dict(model_path, device)
    if isinstance(state_dict, dict) and "model_state_dict" in state_dict:
        state_dict = state_dict["model_state_dict"]
    if not isinstance(state_dict, dict):
        raise ScannerError("checkpoint_format", f"Expected a state_dict in {model_path.name}.")
    try:
        model.load_state_dict(state_dict, strict=True)
    except Exception as exc:
        raise ScannerError("load_state_dict", str(exc)) from exc
    model.eval()
    return {
        "name": model_path.stem,
        "kind": "binary",
        "model": model,
        "preprocess": "base_v2",
        "tta_modes": BASE_TTA_MODES,
    }


def _load_model_bin(model_path: Path, device: torch.device) -> dict[str, Any]:
    state_dict = _load_state_dict(model_path, device)
    if isinstance(state_dict, dict) and "model_state_dict" in state_dict:
        model = get_net().to(device)
        try:
            model.load_state_dict(state_dict["model_state_dict"], strict=True)
        except Exception as exc:
            raise ScannerError("load_state_dict", str(exc)) from exc
        model.eval()
        return {
            "name": model_path.stem,
            "kind": "multiclass",
            "model": model,
            "preprocess": "imagenet",
            "tta_modes": ROBUST_TTA_MODES,
            "clean_class_index": 2,
        }
    raise ScannerError("checkpoint_format", f"Unsupported model.bin checkpoint format in {model_path.name}.")


@lru_cache(maxsize=1)
def load_models() -> dict[str, Any]:
    device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
    loaded_models: list[dict[str, Any]] = []
    warnings: list[str] = []

    if MODEL_PATH.exists():
        loaded_models.append(_load_base_v2_model(MODEL_PATH, device))
    if MODEL_BIN_PATH.exists():
        try:
            loaded_models.append(_load_model_bin(MODEL_BIN_PATH, device))
        except Exception as exc:
            warnings.append(f"model.bin disabled: {exc}")

    if not loaded_models:
        raise ScannerError("model_file", f"No supported steganalysis model weights found in {MODEL_PATH.parent}")

    return {"models": tuple(loaded_models), "warnings": tuple(warnings)}


def _read_image_array(image_path: Path) -> tuple[np.ndarray, tuple[int, int]]:
    if cv2 is not None:
        try:
            image = cv2.imread(str(image_path), cv2.IMREAD_COLOR)
            if image is None:
                raise ScannerError("open_image", f"Could not read image: {image_path}")
            image = cv2.cvtColor(image, cv2.COLOR_BGR2RGB).astype(np.float32) / 255.0
            h, w = image.shape[:2]
            return image, (w, h)
        except Exception as exc:
            raise ScannerError("open_image", str(exc)) from exc

    try:
        image = Image.open(image_path).convert("RGB")
    except Exception as exc:
        raise ScannerError("open_image", str(exc)) from exc

    image_array = np.asarray(image, dtype=np.float32) / 255.0
    h, w = image_array.shape[:2]
    return image_array, (w, h)


def _normalize_imagenet(image_array: np.ndarray) -> np.ndarray:
    return (image_array - IMAGENET_MEAN) / IMAGENET_STD


def _resize_stretch(image_array: np.ndarray, image_size: int) -> np.ndarray:
    if cv2 is None:
        raise ScannerError("import_cv2", "OpenCV is required for the updated steganalysis pipeline.")
    return cv2.resize(image_array, (image_size, image_size), interpolation=cv2.INTER_AREA)


def _resize_letterbox(image_array: np.ndarray, image_size: int) -> np.ndarray:
    if cv2 is None:
        raise ScannerError("import_cv2", "OpenCV is required for the updated steganalysis pipeline.")

    height, width = image_array.shape[:2]
    scale = min(image_size / max(width, 1), image_size / max(height, 1))
    resized_width = max(1, int(round(width * scale)))
    resized_height = max(1, int(round(height * scale)))
    resized = cv2.resize(image_array, (resized_width, resized_height), interpolation=cv2.INTER_AREA)

    pad_left = (image_size - resized_width) // 2
    pad_right = image_size - resized_width - pad_left
    pad_top = (image_size - resized_height) // 2
    pad_bottom = image_size - resized_height - pad_top

    return cv2.copyMakeBorder(
        resized,
        pad_top,
        pad_bottom,
        pad_left,
        pad_right,
        borderType=cv2.BORDER_REFLECT_101,
    )


def preprocess_image(image_path: Path, image_size: int = DEFAULT_IMAGE_SIZE) -> tuple[dict[str, dict[str, Tensor]], tuple[int, int]]:
    image_array, original_size = _read_image_array(image_path)
    base_stretched = _resize_stretch(image_array, image_size)
    imagenet_stretched = _normalize_imagenet(base_stretched)
    imagenet_letterboxed = _normalize_imagenet(_resize_letterbox(image_array, image_size))

    tensors = {
        "base_v2": {
            "stretch_resize": torch.from_numpy(np.transpose(base_stretched, (2, 0, 1))).float().unsqueeze(0),
        },
        "imagenet": {
            "stretch_resize": torch.from_numpy(np.transpose(imagenet_stretched, (2, 0, 1))).float().unsqueeze(0),
            "aspect_letterbox": torch.from_numpy(np.transpose(imagenet_letterboxed, (2, 0, 1))).float().unsqueeze(0),
        },
    }
    return tensors, original_size


def apply_tta(image_tensor: Tensor, mode: str) -> Tensor:
    if mode == "identity":
        return image_tensor
    if mode == "hflip":
        return torch.flip(image_tensor, dims=[3])
    if mode == "vflip":
        return torch.flip(image_tensor, dims=[2])
    if mode == "hvflip":
        return torch.flip(image_tensor, dims=[2, 3])
    if mode == "transpose":
        return image_tensor.transpose(2, 3)
    if mode == "transpose_h":
        return torch.flip(image_tensor.transpose(2, 3), dims=[3])
    if mode == "transpose_v":
        return torch.flip(image_tensor.transpose(2, 3), dims=[2])
    if mode == "rot180":
        return torch.rot90(image_tensor, 2, dims=[2, 3])
    raise ScannerError("tta_mode", f"Unsupported TTA mode: {mode}")


def predict_with_model(
    model_entry: dict[str, Any],
    image_variants: dict[str, dict[str, Tensor]],
    enable_tta: bool,
    *,
    clean_class_index: int | None = None,
) -> tuple[float, float, dict[str, float]]:
    model = model_entry["model"]
    device = next(model.parameters()).device
    image_tensors = image_variants[model_entry["preprocess"]]
    modes = tuple(model_entry.get("tta_modes", BASE_TTA_MODES)) if enable_tta else ("identity",)
    all_scores: list[float] = []
    variant_scores: dict[str, float] = {}

    with torch.inference_mode():
        for variant_name, image_tensor in image_tensors.items():
            current_scores: list[float] = []
            for mode in modes:
                augmented_tensor = apply_tta(image_tensor.to(device), mode)
                pred = model(augmented_tensor)
                if model_entry["kind"] == "binary":
                    score = float(torch.sigmoid(pred).item())
                else:
                    probs = nn.functional.softmax(pred, dim=1)
                    effective_clean_class_index = int(
                        model_entry.get("clean_class_index", 0) if clean_class_index is None else clean_class_index
                    )
                    score = float((1.0 - probs[:, effective_clean_class_index]).item())
                current_scores.append(score)
                all_scores.append(score)
            variant_scores[variant_name] = float(np.mean(current_scores))

    return float(np.mean(all_scores)), float(np.std(all_scores)), variant_scores


def get_model_entry(model_bundle: dict[str, Any], model_name: str) -> dict[str, Any]:
    for model_entry in model_bundle["models"]:
        if str(model_entry["name"]) == str(model_name):
            return model_entry
    raise KeyError(f"Configured steganalysis model '{model_name}' is not loaded.")


def _build_result(
    target: Path,
    decision: str,
    clean_confidence: float,
    stego_prob: float,
    image_size: int,
    score_variants: dict[str, float],
    *,
    tta_std: float,
    preprocessing_disagreement: float,
    original_size: tuple[int, int],
    models_used: list[str],
    tta_enabled: bool,
) -> dict[str, Any]:
    predicted_label = {"STEGO": "Stego", "COVER": "Cover", "UNCERTAIN": "Uncertain"}.get(decision, "Uncertain")
    confidence = stego_prob if decision == "STEGO" else clean_confidence if decision == "COVER" else max(stego_prob, clean_confidence)
    probabilities = {
        "Cover": clean_confidence,
        "Stego": stego_prob,
    }
    return {
        "path": str(target),
        "file_name": target.name,
        "decision": decision,
        "predicted_label": predicted_label,
        "confidence": float(confidence),
        "cover_prob": float(clean_confidence),
        "stego_prob": float(stego_prob),
        "fused_risk": float(stego_prob),  # ← Added for compatibility with frontend logs
        "static_prob": float(stego_prob),  # ← Added as alias for consistency with ML engine
        "probabilities": probabilities,
        "image_size": image_size,
        "model_path": str(MODEL_PATH),
        "model_names": models_used,
        "original_size": {"width": int(original_size[0]), "height": int(original_size[1])},
        "tta_std": float(tta_std),
        "preprocessing_disagreement": float(preprocessing_disagreement),
        "score_variants": score_variants,
        "tta_enabled": bool(tta_enabled),
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

    model_bundle = load_models()
    models_loaded = tuple(model_bundle["models"])
    model_warnings = [str(item) for item in model_bundle.get("warnings", ())]
    detector_config = load_detector_config()
    image_tensors, original_size = preprocess_image(target, image_size=image_size)
    model_scores: list[float] = []
    model_stds: list[float] = []
    variant_spreads: list[float] = []
    variant_score_accumulator: dict[str, list[float]] = {}
    per_model_scores: dict[str, float] = {}
    per_model_tta_std: dict[str, float] = {}
    per_model_variants: dict[str, dict[str, float]] = {}

    for model_entry in models_loaded:
        score, score_std, variant_scores = predict_with_model(model_entry, image_tensors, enable_tta=enable_tta)
        model_scores.append(score)
        model_stds.append(score_std)
        per_model_scores[str(model_entry["name"])] = float(score)
        per_model_tta_std[str(model_entry["name"])] = float(score_std)
        per_model_variants[str(model_entry["name"])] = {key: float(value) for key, value in variant_scores.items()}
        for variant_name, variant_score in variant_scores.items():
            variant_score_accumulator.setdefault(variant_name, []).append(float(variant_score))
        variant_spreads.append(max(variant_scores.values()) - min(variant_scores.values()))

    ensemble_variant_scores = {
        name: float(np.mean(scores)) for name, scores in variant_score_accumulator.items() if scores
    }
    stego_prob = float(np.mean(model_scores))
    clean_threshold = float(DEFAULT_CLEAN_THRESHOLD)
    active_model_name = "ensemble"
    strategy_label = "ensemble-average"
    active_variants = ensemble_variant_scores
    tta_std = float(np.mean(model_stds)) if model_stds else 0.0

    if detector_config is not None:
        strategy = dict(detector_config.get("strategy") or {})
        try:
            active_model_name = str(strategy["model_name"])
            strategy_label = str(strategy.get("kind", "configured"))
            active_model = get_model_entry(model_bundle, active_model_name)
            clean_class_index = strategy.get("clean_class_index")
            stego_prob, tta_std, active_variants = predict_with_model(
                active_model,
                image_tensors,
                enable_tta=enable_tta,
                clean_class_index=int(clean_class_index) if clean_class_index is not None else None,
            )
            thresholds = dict(detector_config.get("thresholds") or {})
            clean_threshold = float(thresholds.get("clean", clean_threshold))
            stego_threshold = float(thresholds.get("stego", stego_threshold))
        except Exception as exc:
            model_warnings.append(f"detector_config disabled: {exc}")
            active_model_name = "ensemble"
            strategy_label = "ensemble-average"
            active_variants = ensemble_variant_scores
            stego_prob = float(np.mean(model_scores))
            tta_std = float(np.mean(model_stds)) if model_stds else 0.0

    clean_confidence = float(max(0.0, min(1.0, 1.0 - stego_prob)))
    preprocessing_disagreement = float(np.mean(variant_spreads)) if variant_spreads else 0.0

    if stego_prob <= clean_threshold:
        decision = "COVER"
    elif stego_prob >= stego_threshold:
        decision = "STEGO"
    else:
        decision = "UNCERTAIN"
    payload = _build_result(
        target=target,
        decision=decision,
        clean_confidence=clean_confidence,
        stego_prob=stego_prob,
        image_size=image_size,
        score_variants=active_variants,
        tta_std=tta_std,
        preprocessing_disagreement=preprocessing_disagreement,
        original_size=original_size,
        models_used=[str(entry["name"]) for entry in models_loaded],
        tta_enabled=enable_tta,
    )
    if model_warnings:
        payload["model_warnings"] = model_warnings
    payload["active_model_name"] = active_model_name
    payload["active_strategy"] = strategy_label
    payload["model_scores"] = per_model_scores
    payload["model_tta_std"] = per_model_tta_std
    payload["model_variant_scores"] = per_model_variants
    payload["detector_config_loaded"] = detector_config is not None
    payload["stego_threshold"] = float(stego_threshold)
    payload["clean_threshold"] = clean_threshold
    payload["score"] = stego_prob

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
        "clean_threshold": DEFAULT_CLEAN_THRESHOLD,
        "stego_threshold": DEFAULT_STEGO_THRESHOLD,
        "model_bin_path": str(MODEL_BIN_PATH),
        "model_bin_exists": MODEL_BIN_PATH.exists(),
        "detector_config_path": str(DETECTOR_CONFIG_PATH),
        "detector_config_exists": DETECTOR_CONFIG_PATH.exists(),
        "model_names": [],
    }

    try:
        load_models.cache_clear()
        model_bundle = load_models()
        status["model_names"] = [str(entry["name"]) for entry in model_bundle["models"]]
        status["warnings"] = [str(item) for item in model_bundle.get("warnings", ())]
        detector_config = load_detector_config()
        if detector_config is not None:
            status["detector_config"] = detector_config
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
