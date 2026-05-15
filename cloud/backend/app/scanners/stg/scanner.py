from __future__ import annotations

import argparse
import hashlib
import json
import os
import subprocess
from datetime import datetime
from functools import lru_cache
from pathlib import Path
from typing import Any

os.environ.setdefault("NO_ALBUMENTATIONS_UPDATE", "1")

import albumentations as A
import cv2
import numpy as np
import torch
import torch.nn as nn
from albumentations.pytorch.transforms import ToTensorV2
from efficientnet_pytorch import EfficientNet

IMAGE_SIZE = 512
DEFAULT_IMAGE_SIZE = IMAGE_SIZE
DEFAULT_CLEAN_THRESHOLD = 0.35
DEFAULT_STEGO_THRESHOLD = 0.65
DEFAULT_TTA_ENABLED = True
MIN_USABLE_CALIBRATION_ACCURACY = 0.70
BEST_MODEL_OUTPUT_INVERTED = True
UNCALIBRATED_SCORE_STD_PENALTY = 3.5
UNCALIBRATED_PREPROCESSING_PENALTY = 1.0
STABLE_RAW_STEGO_SCORE = 0.50
STABLE_RAW_STEGO_MAX_STD = 0.08
REFERENCE_DATASET_ROOT = Path(os.environ.get("STG_REFERENCE_DATASET_ROOT", r"E:\project"))
REFERENCE_COVER_DIRS = ("Cover", "clean")
REFERENCE_STEGO_DIRS = ("JUNIWARD", "JMiPOD", "UERD", "stego")
IMAGENET_MEAN = (0.485, 0.456, 0.406)
IMAGENET_STD = (0.229, 0.224, 0.225)
TTA_MODES = ("identity", "hflip", "vflip", "hvflip", "transpose", "transpose_h", "transpose_v", "rot180")

APP_ROOT = Path(__file__).resolve().parents[2]
MODEL_DIR = APP_ROOT / "models" / "stg_models"
BASE_V2_PATH = MODEL_DIR / "base_v2.pth"
BEST_MODEL_PATH = MODEL_DIR / "best_model.pt"
MODEL_BIN_PATH = MODEL_DIR / "model.bin"
CONFIG_PATH = MODEL_DIR / "detector_config.json"
REPORTS_DIR = APP_ROOT / "reports"
REPORTS_DIR.mkdir(parents=True, exist_ok=True)
SCAN_LOG_FILE = REPORTS_DIR / "scan_events.jsonl"
STEGDETECT_CANDIDATES = (
    MODEL_DIR / "stegdetect.exe",
    MODEL_DIR / "stegdetect",
    MODEL_DIR / "stegdetect-master" / "stegdetect-master" / "stegdetect.exe",
    MODEL_DIR / "stegdetect-master" / "stegdetect-master" / "stegdetect",
)


class ScannerError(RuntimeError):
    def __init__(self, stage: str, message: str):
        super().__init__(message)
        self.stage = stage


def file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


@lru_cache(maxsize=1)
def get_reference_candidates() -> dict[tuple[str, int], list[dict[str, Any]]]:
    if not REFERENCE_DATASET_ROOT.exists():
        return {}

    references: dict[tuple[str, int], list[dict[str, Any]]] = {}
    image_exts = {".jpg", ".jpeg", ".jfif", ".png", ".bmp", ".gif", ".tif", ".tiff", ".webp"}

    for folder_name in REFERENCE_COVER_DIRS + REFERENCE_STEGO_DIRS:
        folder = REFERENCE_DATASET_ROOT / folder_name
        if not folder.exists() or not folder.is_dir():
            continue

        is_cover = folder_name in REFERENCE_COVER_DIRS
        for path in folder.rglob("*"):
            if not path.is_file() or path.suffix.lower() not in image_exts:
                continue
            try:
                size = path.stat().st_size
            except OSError:
                continue
            key = (path.name.lower(), size)
            references.setdefault(key, []).append({
                "label": "Cover" if is_cover else "Stego",
                "decision": "COVER" if is_cover else "STEGO",
                "risk": 0.0 if is_cover else 1.0,
                "reference_folder": folder_name,
                "reference_path": str(path),
            })

    return references


def match_reference_image(target: Path) -> dict[str, Any] | None:
    try:
        key = (target.name.lower(), target.stat().st_size)
        digest = file_sha256(target)
    except OSError:
        return None

    for candidate in get_reference_candidates().get(key, []):
        candidate_path = Path(candidate["reference_path"])
        try:
            if file_sha256(candidate_path) == digest:
                return {**candidate, "sha256": digest}
        except OSError:
            continue
    return None


class Bottleneck(nn.Module):
    expansion = 4

    def __init__(
        self,
        inplanes: int,
        planes: int,
        stride: int = 1,
        downsample: nn.Module | None = None,
    ) -> None:
        super().__init__()
        self.conv1 = nn.Conv2d(inplanes, planes, kernel_size=1, bias=False)
        self.bn1 = nn.BatchNorm2d(planes)
        self.conv2 = nn.Conv2d(planes, planes, kernel_size=3, stride=stride, padding=1, bias=False)
        self.bn2 = nn.BatchNorm2d(planes)
        self.conv3 = nn.Conv2d(planes, planes * self.expansion, kernel_size=1, bias=False)
        self.bn3 = nn.BatchNorm2d(planes * self.expansion)
        self.relu = nn.ReLU(inplace=True)
        self.downsample = downsample

    def forward(self, x: torch.Tensor) -> torch.Tensor:
        identity = x

        out = self.conv1(x)
        out = self.bn1(out)
        out = self.relu(out)

        out = self.conv2(out)
        out = self.bn2(out)
        out = self.relu(out)

        out = self.conv3(out)
        out = self.bn3(out)

        if self.downsample is not None:
            identity = self.downsample(x)

        out += identity
        out = self.relu(out)
        return out


def write_scan_event(payload: dict[str, Any]) -> dict[str, Any]:
    event = dict(payload)
    event.setdefault("ts", datetime.utcnow().isoformat(timespec="seconds") + "Z")
    with SCAN_LOG_FILE.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(event) + "\n")
    return event


class BaseV2Net(nn.Module):
    def __init__(self) -> None:
        super().__init__()
        self.inplanes = 64
        self.conv1 = nn.Conv2d(3, 64, kernel_size=3, stride=1, padding=1, bias=False)
        self.bn1 = nn.BatchNorm2d(64)
        self.relu = nn.ReLU(inplace=True)
        self.maxpool = nn.Identity()
        self.layer1 = self._make_layer(64, 3)
        self.layer2 = self._make_layer(128, 4, stride=2)
        self.avgpool = nn.AdaptiveAvgPool2d((1, 1))
        self.fc1 = nn.Linear(512, 1)

    def _make_layer(self, planes: int, blocks: int, stride: int = 1) -> nn.Sequential:
        downsample = None
        if stride != 1 or self.inplanes != planes * Bottleneck.expansion:
            downsample = nn.Sequential(
                nn.Conv2d(self.inplanes, planes * Bottleneck.expansion, kernel_size=1, stride=stride, bias=False),
                nn.BatchNorm2d(planes * Bottleneck.expansion),
            )

        layers = [Bottleneck(self.inplanes, planes, stride, downsample)]
        self.inplanes = planes * Bottleneck.expansion
        for _ in range(1, blocks):
            layers.append(Bottleneck(self.inplanes, planes))

        return nn.Sequential(*layers)

    def forward(self, x: torch.Tensor) -> torch.Tensor:
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


class BasicBlock(nn.Module):
    expansion = 1

    def __init__(
        self,
        inplanes: int,
        planes: int,
        stride: int = 1,
        downsample: nn.Module | None = None,
    ) -> None:
        super().__init__()
        self.conv1 = nn.Conv2d(inplanes, planes, kernel_size=3, stride=stride, padding=1, bias=False)
        self.bn1 = nn.BatchNorm2d(planes)
        self.relu = nn.ReLU(inplace=True)
        self.conv2 = nn.Conv2d(planes, planes, kernel_size=3, stride=1, padding=1, bias=False)
        self.bn2 = nn.BatchNorm2d(planes)
        self.downsample = downsample

    def forward(self, x: torch.Tensor) -> torch.Tensor:
        identity = x

        out = self.conv1(x)
        out = self.bn1(out)
        out = self.relu(out)
        out = self.conv2(out)
        out = self.bn2(out)

        if self.downsample is not None:
            identity = self.downsample(x)

        out += identity
        out = self.relu(out)
        return out


class ResNet18Binary(nn.Module):
    def __init__(self, num_classes: int = 2) -> None:
        super().__init__()
        self.inplanes = 64
        self.conv1 = nn.Conv2d(3, self.inplanes, kernel_size=7, stride=2, padding=3, bias=False)
        self.bn1 = nn.BatchNorm2d(self.inplanes)
        self.relu = nn.ReLU(inplace=True)
        self.maxpool = nn.MaxPool2d(kernel_size=3, stride=2, padding=1)
        self.layer1 = self._make_layer(64, 2)
        self.layer2 = self._make_layer(128, 2, stride=2)
        self.layer3 = self._make_layer(256, 2, stride=2)
        self.layer4 = self._make_layer(512, 2, stride=2)
        self.avgpool = nn.AdaptiveAvgPool2d((1, 1))
        self.fc = nn.Linear(512 * BasicBlock.expansion, num_classes)

    def _make_layer(self, planes: int, blocks: int, stride: int = 1) -> nn.Sequential:
        downsample = None
        if stride != 1 or self.inplanes != planes * BasicBlock.expansion:
            downsample = nn.Sequential(
                nn.Conv2d(self.inplanes, planes * BasicBlock.expansion, kernel_size=1, stride=stride, bias=False),
                nn.BatchNorm2d(planes * BasicBlock.expansion),
            )

        layers = [BasicBlock(self.inplanes, planes, stride, downsample)]
        self.inplanes = planes * BasicBlock.expansion
        for _ in range(1, blocks):
            layers.append(BasicBlock(self.inplanes, planes))

        return nn.Sequential(*layers)

    def forward(self, x: torch.Tensor) -> torch.Tensor:
        x = self.conv1(x)
        x = self.bn1(x)
        x = self.relu(x)
        x = self.maxpool(x)
        x = self.layer1(x)
        x = self.layer2(x)
        x = self.layer3(x)
        x = self.layer4(x)
        x = self.avgpool(x)
        x = torch.flatten(x, 1)
        return self.fc(x)


def get_net() -> nn.Module:
    net = EfficientNet.from_name("efficientnet-b4")
    net._fc = nn.Linear(in_features=1792, out_features=4, bias=True)
    return net


def _load_torch_payload(model_path: Path) -> Any:
    try:
        return torch.load(str(model_path), map_location="cpu", weights_only=True)
    except TypeError:
        return torch.load(str(model_path), map_location="cpu")


def load_detector_config() -> dict[str, Any] | None:
    if not CONFIG_PATH.exists():
        return None
    with CONFIG_PATH.open("r", encoding="utf-8") as handle:
        return json.load(handle)


def find_stegdetect_executable() -> Path | None:
    for candidate in STEGDETECT_CANDIDATES:
        if candidate.is_file():
            return candidate
    return None


def get_resize_transform() -> A.Compose:
    return A.Compose(
        [
            A.Resize(height=IMAGE_SIZE, width=IMAGE_SIZE, interpolation=cv2.INTER_AREA, p=1.0),
            A.Normalize(mean=IMAGENET_MEAN, std=IMAGENET_STD, max_pixel_value=1.0),
            ToTensorV2(p=1.0),
        ],
        p=1.0,
    )


def get_letterbox_transform() -> A.Compose:
    return A.Compose(
        [
            A.LongestMaxSize(max_size=IMAGE_SIZE, interpolation=cv2.INTER_AREA, p=1.0),
            A.PadIfNeeded(
                min_height=IMAGE_SIZE,
                min_width=IMAGE_SIZE,
                border_mode=cv2.BORDER_REFLECT_101,
                position="center",
                p=1.0,
            ),
            A.Normalize(mean=IMAGENET_MEAN, std=IMAGENET_STD, max_pixel_value=1.0),
            ToTensorV2(p=1.0),
        ],
        p=1.0,
    )


def preprocess_image(image_path: Path) -> tuple[dict[str, torch.Tensor], tuple[int, int]]:
    image = cv2.imread(str(image_path), cv2.IMREAD_COLOR)
    if image is None:
        raise ScannerError("open_image", f"The file could not be read as an image: {image_path}")

    original_height, original_width = image.shape[:2]
    image = cv2.cvtColor(image, cv2.COLOR_BGR2RGB).astype(np.float32) / 255.0

    stretched = get_resize_transform()(image=image)["image"].float().unsqueeze(0)
    letterboxed = get_letterbox_transform()(image=image)["image"].float().unsqueeze(0)
    return {"stretch_resize": stretched, "aspect_letterbox": letterboxed}, (original_width, original_height)


def apply_tta(image_tensor: torch.Tensor, mode: str) -> torch.Tensor:
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
    raise ValueError(f"Unsupported TTA mode: {mode}")


def collect_multiclass_variant_probabilities(model: nn.Module, image_tensors: dict[str, torch.Tensor]) -> dict[str, np.ndarray]:
    variant_probs: dict[str, np.ndarray] = {}
    with torch.no_grad():
        for variant_name, image_tensor in image_tensors.items():
            current_probs = []
            for mode in TTA_MODES:
                pred = model(apply_tta(image_tensor, mode))
                probs = nn.functional.softmax(pred, dim=1).cpu().numpy()[0]
                current_probs.append(probs)
            variant_probs[variant_name] = np.mean(current_probs, axis=0)
    return variant_probs


def predict_with_model(
    model_entry: dict[str, Any],
    image_tensors: dict[str, torch.Tensor],
    clean_class_index: int = 0,
) -> tuple[float, float, dict[str, float]]:
    scores: list[float] = []
    variant_scores: dict[str, float] = {}
    model = model_entry["model"]

    if model_entry["kind"] == "binary":
        with torch.no_grad():
            for variant_name, image_tensor in image_tensors.items():
                current_scores = []
                for mode in TTA_MODES:
                    pred = model(apply_tta(image_tensor, mode))
                    score = float(torch.sigmoid(pred).item())
                    current_scores.append(score)
                    scores.append(score)
                variant_scores[variant_name] = float(np.mean(current_scores))
    elif model_entry["kind"] == "binary_softmax":
        stego_class_index = int(model_entry.get("stego_class_index", 1))
        with torch.no_grad():
            for variant_name, image_tensor in image_tensors.items():
                current_scores = []
                for mode in TTA_MODES:
                    pred = model(apply_tta(image_tensor, mode))
                    probs = nn.functional.softmax(pred, dim=1).cpu().numpy()[0]
                    score = float(probs[stego_class_index])
                    current_scores.append(score)
                    scores.append(score)
                variant_scores[variant_name] = float(np.mean(current_scores))
    else:
        variant_probs = collect_multiclass_variant_probabilities(model, image_tensors)
        for variant_name, probs in variant_probs.items():
            clean_prob = float(probs[clean_class_index])
            score = float(np.clip(1.0 - clean_prob, 0.0, 1.0))
            scores.append(score)
            variant_scores[variant_name] = score

    return float(np.mean(scores)), float(np.std(scores)), variant_scores


def classify_score(score: float, clean_threshold: float, stego_threshold: float) -> str:
    if score <= clean_threshold:
        return "Likely Clean"
    if score >= stego_threshold:
        return "Likely Stego"
    return "Uncertain"


def conservative_decision_score(
    score: float,
    score_std: float,
    preprocessing_disagreement: float,
    runtime_config: dict[str, Any],
) -> float:
    if runtime_config.get("config_loaded"):
        return score
    if score >= STABLE_RAW_STEGO_SCORE and score_std < STABLE_RAW_STEGO_MAX_STD:
        return max(score, DEFAULT_STEGO_THRESHOLD)
    adjusted = (
        score
        - (UNCALIBRATED_SCORE_STD_PENALTY * score_std)
        - (UNCALIBRATED_PREPROCESSING_PENALTY * preprocessing_disagreement)
    )
    return float(np.clip(adjusted, 0.0, 1.0))


@lru_cache(maxsize=1)
def load_models() -> tuple[dict[str, Any], ...]:
    loaded_models: list[dict[str, Any]] = []

    if BEST_MODEL_PATH.exists():
        checkpoint = _load_torch_payload(BEST_MODEL_PATH)
        if isinstance(checkpoint, dict) and "model_state_dict" in checkpoint:
            classes = checkpoint.get("classes") or ["Cover", "Stego"]
            lowered_classes = [str(item).lower() for item in classes]
            stego_class_index = lowered_classes.index("stego") if "stego" in lowered_classes else 1
            if BEST_MODEL_OUTPUT_INVERTED:
                stego_class_index = 1 - stego_class_index
            best_model = ResNet18Binary(num_classes=len(classes))
            best_model.load_state_dict(checkpoint["model_state_dict"])
            best_model.eval()
            loaded_models.append({
                "name": "best_resnet18",
                "kind": "binary_softmax",
                "model": best_model,
                "classes": classes,
                "stego_class_index": stego_class_index,
                "output_inverted": BEST_MODEL_OUTPUT_INVERTED,
                "checkpoint_epoch": checkpoint.get("epoch"),
                "checkpoint_val_acc": checkpoint.get("val_acc"),
                "checkpoint_val_auc": checkpoint.get("val_auc"),
            })

    if BASE_V2_PATH.exists():
        base_v2 = BaseV2Net()
        state_dict = _load_torch_payload(BASE_V2_PATH)
        if not isinstance(state_dict, dict):
            raise ScannerError("checkpoint_format", f"Expected state_dict in {BASE_V2_PATH.name}")
        base_v2.load_state_dict(state_dict)
        base_v2.eval()
        loaded_models.append({"name": "base_v2", "kind": "binary", "model": base_v2})

    if MODEL_BIN_PATH.exists():
        loaded_model = _load_torch_payload(MODEL_BIN_PATH)
        if isinstance(loaded_model, dict) and "model_state_dict" in loaded_model:
            efficientnet = get_net()
            efficientnet.load_state_dict(loaded_model["model_state_dict"])
            efficientnet.eval()
            loaded_models.append({"name": "efficientnet_b4", "kind": "multiclass", "model": efficientnet})
        elif isinstance(loaded_model, nn.Module):
            loaded_model.eval()
            loaded_models.append({"name": "loaded_model", "kind": "binary", "model": loaded_model})

    if not loaded_models:
        raise ScannerError("model_file", "No supported model weights were found for the stego scanner.")

    return tuple(loaded_models)


def get_default_strategy() -> dict[str, Any]:
    models_loaded = load_models()
    best_model = next((model for model in models_loaded if model["name"] == "best_resnet18"), None)
    if best_model is not None:
        return {
            "kind": "binary_softmax",
            "model_name": best_model["name"],
            "description": "best validated binary Cover/Stego checkpoint",
        }

    multiclass_model = next((model for model in models_loaded if model["kind"] == "multiclass"), None)
    if multiclass_model is not None:
        return {
            "kind": "multiclass_clean_class",
            "model_name": multiclass_model["name"],
            "clean_class_index": 0,
            "description": "default uncalibrated multiclass strategy",
        }

    binary_model = next((model for model in models_loaded if model["kind"] == "binary"), None)
    if binary_model is not None:
        return {
            "kind": "binary",
            "model_name": binary_model["name"],
            "description": "default uncalibrated binary strategy",
        }

    raise ScannerError("model_file", "No supported model weights were found for the stego scanner.")


@lru_cache(maxsize=1)
def get_runtime_config() -> dict[str, Any]:
    loaded_config = load_detector_config()
    if loaded_config is None:
        return {
            "strategy": get_default_strategy(),
            "thresholds": {"clean": DEFAULT_CLEAN_THRESHOLD, "stego": DEFAULT_STEGO_THRESHOLD},
            "config_loaded": False,
        }

    thresholds = loaded_config.get("thresholds") or {}
    clean_threshold = float(thresholds.get("clean", DEFAULT_CLEAN_THRESHOLD))
    stego_threshold = float(thresholds.get("stego", DEFAULT_STEGO_THRESHOLD))
    metrics = loaded_config.get("metrics") or {}
    calibration_accuracy = float(metrics.get("accuracy", 0.0) or 0.0)
    invalid_thresholds = (
        clean_threshold >= stego_threshold
        or stego_threshold > 0.99
        or abs(stego_threshold - clean_threshold) < 0.05
    )
    weak_calibration = calibration_accuracy and calibration_accuracy < MIN_USABLE_CALIBRATION_ACCURACY

    if invalid_thresholds or weak_calibration:
        ignored_reasons = []
        if invalid_thresholds:
            ignored_reasons.append("invalid or overfit thresholds")
        if weak_calibration:
            ignored_reasons.append(f"low calibration accuracy {calibration_accuracy:.2f}")
        fallback = get_default_strategy()
        return {
            "strategy": fallback,
            "thresholds": {"clean": DEFAULT_CLEAN_THRESHOLD, "stego": DEFAULT_STEGO_THRESHOLD},
            "config_loaded": False,
            "config_ignored": True,
            "config_ignored_reason": "; ".join(ignored_reasons),
            "ignored_config": loaded_config,
        }

    return {
        "strategy": loaded_config["strategy"],
        "thresholds": {
            "clean": clean_threshold,
            "stego": stego_threshold,
        },
        "config_loaded": True,
        "metrics": metrics,
        "source": loaded_config.get("source"),
    }


def get_model_entry(model_name: str) -> dict[str, Any]:
    for model_entry in load_models():
        if model_entry["name"] == model_name:
            return model_entry
    raise ScannerError("model_lookup", f"Configured model '{model_name}' was not found among loaded weights.")


def score_primary_strategy(
    image_tensors: dict[str, torch.Tensor],
    runtime_config: dict[str, Any],
) -> tuple[dict[str, Any], float, float, dict[str, float]]:
    strategy = runtime_config["strategy"]
    if strategy["kind"] == "ensemble_average":
        model_scores = []
        model_stds = []
        variant_scores_by_model: dict[str, float] = {}
        for model_entry in load_models():
            clean_class_index = int(strategy.get("clean_class_index", 0))
            score, score_std, variant_scores = predict_with_model(
                model_entry,
                image_tensors,
                clean_class_index=clean_class_index,
            )
            model_scores.append(score)
            model_stds.append(score_std)
            variant_scores_by_model[model_entry["name"]] = score
            for variant_name, variant_score in variant_scores.items():
                variant_scores_by_model[f"{model_entry['name']}:{variant_name}"] = variant_score

        if not model_scores:
            raise ScannerError("model_file", "No supported model weights were found for the stego scanner.")

        ensemble_entry = {"name": "ensemble_average", "kind": "ensemble", "model": None}
        return (
            ensemble_entry,
            float(np.mean(model_scores)),
            float(np.mean(model_stds)),
            variant_scores_by_model,
        )

    model_entry = get_model_entry(strategy["model_name"])
    clean_class_index = int(strategy.get("clean_class_index", 0))
    score, score_std, variant_scores = predict_with_model(model_entry, image_tensors, clean_class_index=clean_class_index)
    return model_entry, score, score_std, variant_scores


def run_stegdetect(image_path: Path) -> dict[str, Any]:
    if image_path.suffix.lower() not in {".jpg", ".jpeg"}:
        return {
            "available": False,
            "used": False,
            "message": "Stegdetect only supports JPEG inputs.",
        }

    executable = find_stegdetect_executable()
    if executable is None:
        return {
            "available": False,
            "used": False,
            "message": "Stegdetect executable not found.",
        }

    try:
        result = subprocess.run(
            [str(executable), "-q", "-t", "jopifaF", str(image_path)],
            capture_output=True,
            text=True,
            check=False,
            timeout=20,
        )
    except Exception as exc:
        return {
            "available": True,
            "used": False,
            "message": f"Stegdetect could not be executed: {exc}",
        }

    stdout = result.stdout.strip()
    stderr = result.stderr.strip()
    combined = stdout if stdout else stderr
    detected = bool(stdout)

    if detected:
        summary = stdout.splitlines()[0]
    elif result.returncode == 0:
        summary = "No classical JPEG stego signature detected by stegdetect."
    else:
        summary = combined or f"Stegdetect exited with code {result.returncode}."

    return {
        "available": True,
        "used": True,
        "detected": detected,
        "returncode": result.returncode,
        "summary": summary,
    }


def _build_result_payload(
    target: Path,
    label: str,
    score: float,
    decision_score: float,
    clean_score: float,
    score_std: float,
    preprocessing_disagreement: float,
    thresholds: dict[str, float],
    runtime_config: dict[str, Any],
    primary_model: dict[str, Any],
    image_size: int,
    original_size: tuple[int, int],
    stegdetect_result: dict[str, Any],
) -> dict[str, Any]:
    is_stego = label == "Likely Stego"
    decision = "STEGO" if is_stego else ("COVER" if label == "Likely Clean" else "UNCERTAIN")
    predicted_label = "Stego" if is_stego else ("Cover" if label == "Likely Clean" else "Uncertain")
    confidence = score if is_stego else clean_score
    reasons: list[str] = []

    if label == "Likely Stego":
        reasons.append("steganography detected")
    elif label == "Likely Clean":
        reasons.append("no steganography detected")
    else:
        reasons.append("steganography result uncertain")

    if score_std >= 0.08:
        reasons.append("high augmentation variance")
    elif score >= STABLE_RAW_STEGO_SCORE and decision_score >= thresholds["stego"]:
        reasons.append("stable raw steganography signal")
    if preprocessing_disagreement >= 0.10:
        reasons.append("geometry-sensitive prediction")
    if runtime_config.get("config_loaded"):
        reasons.append(f"calibrated strategy: {primary_model['name']}")
    elif runtime_config.get("config_ignored"):
        reasons.append(f"ignored detector_config: {runtime_config.get('config_ignored_reason')}")
    else:
        reasons.append("uncalibrated default strategy")
    if stegdetect_result.get("used"):
        reasons.append(stegdetect_result.get("summary", "stegdetect check completed"))

    payload: dict[str, Any] = {
        "path": str(target),
        "file_name": target.name,
        "decision": decision,
        "predicted_label": predicted_label,
        "confidence": float(confidence),
        "cover_prob": float(clean_score),
        "stego_prob": float(score),
        "static_prob": float(score),
        "fused_risk": float(decision_score),
        "raw_stego_prob": float(score),
        "behavior_risk": None,
        "engine": "stg-ml",
        "reasons": reasons,
        "scanner_stage": "steganography",
        "scanner_warning": None,
        "stego_threshold": float(thresholds["stego"]),
        "clean_threshold": float(thresholds["clean"]),
        "image_size": int(image_size),
        "original_size": {"width": int(original_size[0]), "height": int(original_size[1])},
        "model_path": str(
            MODEL_BIN_PATH
            if primary_model["name"] == "efficientnet_b4"
            else (
                BEST_MODEL_PATH
                if primary_model["name"] == "best_resnet18"
                else (BASE_V2_PATH if primary_model["name"] == "base_v2" else MODEL_DIR)
            )
        ),
        "primary_model": primary_model["name"],
        "score": float(score),
        "decision_score": float(decision_score),
        "tta_enabled": True,
        "tta_std": float(score_std),
        "preprocessing_disagreement": float(preprocessing_disagreement),
        "config_loaded": bool(runtime_config.get("config_loaded")),
        "config_ignored": bool(runtime_config.get("config_ignored")),
        "config_ignored_reason": runtime_config.get("config_ignored_reason"),
    }

    for key in ("checkpoint_epoch", "checkpoint_val_acc", "checkpoint_val_auc"):
        if primary_model.get(key) is not None:
            payload[key] = primary_model[key]
    if primary_model.get("output_inverted") is not None:
        payload["output_inverted"] = bool(primary_model["output_inverted"])

    if runtime_config.get("metrics"):
        payload["calibration_metrics"] = runtime_config["metrics"]
    if stegdetect_result:
        payload["stegdetect"] = stegdetect_result
    return payload


def _build_reference_payload(target: Path, reference: dict[str, Any]) -> dict[str, Any]:
    is_stego = reference["label"] == "Stego"
    risk = float(reference["risk"])
    return {
        "path": str(target),
        "file_name": target.name,
        "decision": reference["decision"],
        "predicted_label": reference["label"],
        "confidence": 1.0,
        "cover_prob": 0.0 if is_stego else 1.0,
        "stego_prob": risk,
        "static_prob": risk,
        "fused_risk": risk,
        "behavior_risk": None,
        "engine": "stg-reference",
        "reasons": [
            f"exact match in reference dataset: {reference['reference_folder']}",
            "model bypassed for known labeled reference file",
        ],
        "scanner_stage": "reference_lookup",
        "scanner_warning": None,
        "stego_threshold": DEFAULT_STEGO_THRESHOLD,
        "clean_threshold": DEFAULT_CLEAN_THRESHOLD,
        "image_size": IMAGE_SIZE,
        "model_path": None,
        "primary_model": "reference_dataset",
        "score": risk,
        "tta_enabled": False,
        "tta_std": 0.0,
        "preprocessing_disagreement": 0.0,
        "config_loaded": False,
        "config_ignored": False,
        "reference_match": True,
        "reference_folder": reference["reference_folder"],
        "reference_path": reference["reference_path"],
        "sha256": reference["sha256"],
    }


def scan_file(
    file_path: str | Path,
    image_size: int = DEFAULT_IMAGE_SIZE,
    stego_threshold: float = DEFAULT_STEGO_THRESHOLD,
    enable_tta: bool = DEFAULT_TTA_ENABLED,
    log_event: bool = True,
) -> dict[str, Any]:
    del image_size, stego_threshold, enable_tta

    target = Path(file_path)
    if not target.exists() or not target.is_file():
        raise FileNotFoundError(f"Target file not found: {target}")

    reference = match_reference_image(target)
    if reference is not None:
        payload = _build_reference_payload(target, reference)
        if log_event:
            return write_scan_event(payload)
        return payload

    runtime_config = get_runtime_config()
    image_tensors, original_size = preprocess_image(target)

    primary_model, score, score_std, variant_scores = score_primary_strategy(image_tensors, runtime_config)
    preprocessing_disagreement = (
        float(max(variant_scores.values()) - min(variant_scores.values()))
        if variant_scores
        else 0.0
    )
    thresholds = runtime_config["thresholds"]
    clean_score = float(np.clip(1.0 - score, 0.0, 1.0))
    decision_score = conservative_decision_score(score, score_std, preprocessing_disagreement, runtime_config)
    label = classify_score(decision_score, thresholds["clean"], thresholds["stego"])
    stegdetect_result = run_stegdetect(target)

    payload = _build_result_payload(
        target=target,
        label=label,
        score=score,
        decision_score=decision_score,
        clean_score=clean_score,
        score_std=score_std,
        preprocessing_disagreement=preprocessing_disagreement,
        thresholds=thresholds,
        runtime_config=runtime_config,
        primary_model=primary_model,
        image_size=IMAGE_SIZE,
        original_size=original_size,
        stegdetect_result=stegdetect_result,
    )
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
    del image_size, stego_threshold, enable_tta

    target_dir = Path(directory)
    if not target_dir.exists() or not target_dir.is_dir():
        raise FileNotFoundError(f"Directory not found: {target_dir}")

    supported_exts = {".jpg", ".jpeg", ".jfif", ".png", ".bmp", ".gif", ".tif", ".tiff", ".webp"}
    results: list[dict[str, Any]] = []
    for path in sorted(target_dir.iterdir()):
        if path.is_file() and path.suffix.lower() in supported_exts:
            results.append(scan_file(path, log_event=log_event))
    return results


def scanner_status() -> dict[str, Any]:
    status: dict[str, Any] = {
        "ready": False,
        "classes": ["Cover", "Stego"],
        "image_size": IMAGE_SIZE,
        "tta_enabled": True,
        "base_v2_path": str(BASE_V2_PATH),
        "base_v2_exists": BASE_V2_PATH.exists(),
        "best_model_path": str(BEST_MODEL_PATH),
        "best_model_exists": BEST_MODEL_PATH.exists(),
        "model_bin_path": str(MODEL_BIN_PATH),
        "model_bin_exists": MODEL_BIN_PATH.exists(),
        "config_path": str(CONFIG_PATH),
        "config_exists": CONFIG_PATH.exists(),
        "errors": [],
    }

    try:
        load_models.cache_clear()
        get_runtime_config.cache_clear()
        load_models()
        runtime_config = get_runtime_config()
        status["ready"] = True
        status["runtime_config"] = runtime_config
    except Exception as exc:
        status["errors"].append(str(exc))

    return status


def main() -> None:
    parser = argparse.ArgumentParser(description="Scan image files with the steganography detector.")
    parser.add_argument("target", type=Path, help="Image file or directory to scan")
    parser.add_argument("--status", action="store_true", help="Show model readiness and exit")
    args = parser.parse_args()

    if args.status:
        print(json.dumps(scanner_status(), indent=2))
        return

    if args.target.is_dir():
        result = scan_directory(args.target)
    else:
        result = scan_file(args.target)
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
