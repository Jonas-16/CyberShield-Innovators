from __future__ import annotations

import argparse
import json
from datetime import datetime
from pathlib import Path
from typing import Any

import numpy as np
import torch
from PIL import Image
from torch import Tensor, nn

Image.MAX_IMAGE_PIXELS = None

APP_ROOT = Path(__file__).resolve().parents[2]
MODEL_PATH = APP_ROOT / "models" / "stg_models" / "best_model.pt"
REPORTS_DIR = APP_ROOT / "reports"
REPORTS_DIR.mkdir(parents=True, exist_ok=True)
SCAN_LOG_FILE = REPORTS_DIR / "scan_events.jsonl"

DEFAULT_IMAGE_SIZE = 96
DEFAULT_STEGO_THRESHOLD = 0.5
IMAGENET_MEAN = np.array([0.485, 0.456, 0.406], dtype=np.float32)
IMAGENET_STD = np.array([0.229, 0.224, 0.225], dtype=np.float32)


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
        self.stride = stride

    def forward(self, x: Tensor) -> Tensor:
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


class ResNet(nn.Module):
    def __init__(self, block: type[BasicBlock], layers: list[int], num_classes: int) -> None:
        super().__init__()
        self.inplanes = 64
        self.conv1 = nn.Conv2d(3, 64, kernel_size=7, stride=2, padding=3, bias=False)
        self.bn1 = nn.BatchNorm2d(64)
        self.relu = nn.ReLU(inplace=True)
        self.maxpool = nn.MaxPool2d(kernel_size=3, stride=2, padding=1)
        self.layer1 = self._make_layer(block, 64, layers[0])
        self.layer2 = self._make_layer(block, 128, layers[1], stride=2)
        self.layer3 = self._make_layer(block, 256, layers[2], stride=2)
        self.layer4 = self._make_layer(block, 512, layers[3], stride=2)
        self.avgpool = nn.AdaptiveAvgPool2d((1, 1))
        self.fc = nn.Linear(512 * block.expansion, num_classes)

    def _make_layer(self, block: type[BasicBlock], planes: int, blocks: int, stride: int = 1) -> nn.Sequential:
        downsample = None
        if stride != 1 or self.inplanes != planes * block.expansion:
            downsample = nn.Sequential(
                nn.Conv2d(self.inplanes, planes * block.expansion, kernel_size=1, stride=stride, bias=False),
                nn.BatchNorm2d(planes * block.expansion),
            )

        layers = [block(self.inplanes, planes, stride, downsample)]
        self.inplanes = planes * block.expansion
        for _ in range(1, blocks):
            layers.append(block(self.inplanes, planes))
        return nn.Sequential(*layers)

    def forward(self, x: Tensor) -> Tensor:
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
        x = self.fc(x)
        return x


def build_resnet18(num_classes: int) -> ResNet:
    return ResNet(BasicBlock, [2, 2, 2, 2], num_classes=num_classes)


def load_checkpoint(model_path: Path = MODEL_PATH) -> tuple[nn.Module, list[str], dict[str, Any]]:
    if not model_path.exists():
        raise ScannerError("model_file", f"Model not found: {model_path}")

    device = torch.device("cuda" if torch.cuda.is_available() else "cpu")

    try:
        try:
            checkpoint = torch.load(str(model_path), map_location=device, weights_only=True)
        except TypeError:
            checkpoint = torch.load(str(model_path), map_location=device)
    except Exception as exc:
        raise ScannerError("load_checkpoint", str(exc)) from exc

    if not isinstance(checkpoint, dict):
        raise ScannerError("checkpoint_format", "Checkpoint is not a dictionary.")

    classes = checkpoint.get("classes")
    if not isinstance(classes, list) or not classes:
        raise ScannerError("checkpoint_classes", "Checkpoint does not contain valid classes.")

    state_dict = checkpoint.get("model_state_dict")
    if not isinstance(state_dict, dict):
        raise ScannerError("checkpoint_state_dict", "Checkpoint does not contain model_state_dict.")

    model = build_resnet18(num_classes=len(classes)).to(device)
    try:
        model.load_state_dict(state_dict, strict=True)
    except Exception as exc:
        raise ScannerError("load_state_dict", str(exc)) from exc

    model.eval()
    return model, classes, checkpoint


def preprocess_image(image_path: Path, image_size: int = DEFAULT_IMAGE_SIZE) -> Tensor:
    try:
        image = Image.open(image_path).convert("RGB")
    except Exception as exc:
        raise ScannerError("open_image", str(exc)) from exc

    image = image.resize((image_size, image_size))
    image_array = np.asarray(image, dtype=np.float32) / 255.0
    image_array = (image_array - IMAGENET_MEAN) / IMAGENET_STD
    image_array = np.transpose(image_array, (2, 0, 1))
    return torch.from_numpy(image_array).unsqueeze(0)


def _build_result(
    target: Path,
    predicted_label: str,
    confidence: float,
    probabilities: dict[str, float],
    checkpoint_meta: dict[str, Any],
    image_size: int,
) -> dict[str, Any]:
    stego_prob = probabilities.get("Stego", 0.0)
    cover_prob = probabilities.get("Cover", 0.0)
    decision = "STEGO" if predicted_label.lower() == "stego" else "COVER"
    return {
        "path": str(target),
        "file_name": target.name,
        "decision": decision,
        "predicted_label": predicted_label,
        "confidence": confidence,
        "cover_prob": cover_prob,
        "stego_prob": stego_prob,
        "probabilities": probabilities,
        "image_size": image_size,
        "model_path": str(MODEL_PATH),
        "checkpoint_epoch": checkpoint_meta.get("epoch"),
        "checkpoint_val_acc": checkpoint_meta.get("val_acc"),
        "checkpoint_val_auc": checkpoint_meta.get("val_auc"),
    }


def scan_file(
    file_path: str | Path,
    image_size: int = DEFAULT_IMAGE_SIZE,
    stego_threshold: float = DEFAULT_STEGO_THRESHOLD,
    log_event: bool = True,
) -> dict[str, Any]:
    target = Path(file_path)
    if not target.exists() or not target.is_file():
        raise FileNotFoundError(f"Target file not found: {target}")

    model, classes, checkpoint = load_checkpoint()
    device = next(model.parameters()).device
    x = preprocess_image(target, image_size=image_size).to(device)

    with torch.inference_mode():
        logits = model(x)
        probs = torch.softmax(logits, dim=1).squeeze(0).detach().cpu().numpy()

    probabilities = {label: float(prob) for label, prob in zip(classes, probs)}
    stego_prob = probabilities.get("Stego", 0.0)
    if stego_prob >= stego_threshold and "Stego" in probabilities:
        predicted_label = "Stego"
        confidence = stego_prob
    else:
        predicted_label = max(probabilities, key=probabilities.get)
        confidence = probabilities[predicted_label]

    payload = _build_result(
        target=target,
        predicted_label=predicted_label,
        confidence=float(confidence),
        probabilities=probabilities,
        checkpoint_meta=checkpoint,
        image_size=image_size,
    )
    payload["stego_threshold"] = float(stego_threshold)

    if log_event:
        return write_scan_event(payload)
    return payload


def scan_directory(
    directory: str | Path,
    image_size: int = DEFAULT_IMAGE_SIZE,
    stego_threshold: float = DEFAULT_STEGO_THRESHOLD,
    log_event: bool = False,
) -> list[dict[str, Any]]:
    target_dir = Path(directory)
    if not target_dir.exists() or not target_dir.is_dir():
        raise FileNotFoundError(f"Directory not found: {target_dir}")

    supported_exts = {".jpg", ".jpeg", ".png", ".bmp", ".tif", ".tiff", ".webp"}
    results: list[dict[str, Any]] = []
    for path in sorted(target_dir.iterdir()):
        if path.is_file() and path.suffix.lower() in supported_exts:
            results.append(
                scan_file(
                    path,
                    image_size=image_size,
                    stego_threshold=stego_threshold,
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
        "ready": False,
        "classes": None,
        "errors": [],
    }

    try:
        _, classes, checkpoint = load_checkpoint()
        status["ready"] = True
        status["classes"] = classes
        status["checkpoint_epoch"] = checkpoint.get("epoch")
        status["checkpoint_val_acc"] = checkpoint.get("val_acc")
        status["checkpoint_val_auc"] = checkpoint.get("val_auc")
    except Exception as exc:
        status["errors"].append(str(exc))
    return status


def main() -> None:
    parser = argparse.ArgumentParser(description="Scan image files with the local steganalysis model.")
    parser.add_argument("target", type=Path, help="Image file or directory to scan")
    parser.add_argument("--image-size", type=int, default=DEFAULT_IMAGE_SIZE)
    parser.add_argument("--stego-threshold", type=float, default=DEFAULT_STEGO_THRESHOLD)
    parser.add_argument("--status", action="store_true", help="Show model readiness and exit")
    args = parser.parse_args()

    if args.status:
        print(json.dumps(scanner_status(), indent=2))
        return

    if args.target.is_dir():
        result = scan_directory(args.target, image_size=args.image_size, stego_threshold=args.stego_threshold)
    else:
        result = scan_file(args.target, image_size=args.image_size, stego_threshold=args.stego_threshold)
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()






