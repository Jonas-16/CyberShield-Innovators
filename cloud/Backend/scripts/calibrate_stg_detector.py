"""
Steganalysis Model Threshold Calibration Tool

Analyzes model predictions on known cover and stego images to find optimal thresholds.
Identifies why steganographic images are being misclassified.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any, Iterable

import numpy as np
import torch

from app.scanners.stg import scanner


IMAGE_EXTENSIONS = (".jpg", ".jpeg", ".png", ".bmp", ".tif", ".tiff", ".webp")
SUPPORTED_EXTS = {".jpg", ".jpeg", ".jfif", ".png", ".bmp", ".gif", ".tif", ".tiff", ".webp"}


def iter_images(folder: Path) -> Iterable[Path]:
    for path in sorted(folder.rglob("*")):
        if path.is_file() and path.suffix.lower() in IMAGE_EXTENSIONS:
            yield path


def collect_multiclass_variant_probabilities(
    model_entry: dict[str, Any],
    image_variants: dict[str, dict[str, torch.Tensor]],
    *,
    enable_tta: bool,
) -> list[np.ndarray]:
    model = model_entry["model"]
    device = next(model.parameters()).device
    image_tensors = image_variants[model_entry["preprocess"]]
    modes = tuple(model_entry.get("tta_modes", scanner.ROBUST_TTA_MODES)) if enable_tta else ("identity",)
    outputs: list[np.ndarray] = []

    with torch.inference_mode():
        for image_tensor in image_tensors.values():
            current_probs: list[np.ndarray] = []
            for mode in modes:
                augmented_tensor = scanner.apply_tta(image_tensor.to(device), mode)
                pred = model(augmented_tensor)
                probs = torch.softmax(pred, dim=1).cpu().numpy()[0]
                current_probs.append(probs)
            outputs.append(np.mean(current_probs, axis=0))
    return outputs


def score_image(image_path: Path, *, enable_tta: bool) -> dict[str, Any]:
    model_bundle = scanner.load_models()
    image_variants, _ = scanner.preprocess_image(image_path)

    model_details: dict[str, Any] = {}
    multiclass_variants: dict[str, list[np.ndarray]] = {}

    for model_entry in model_bundle["models"]:
        score, score_std, variant_scores = scanner.predict_with_model(model_entry, image_variants, enable_tta=enable_tta)
        model_name = str(model_entry["name"])
        model_details[model_name] = {
            "score": float(score),
            "tta_stability": float(score_std),
            "variant_scores": {key: float(value) for key, value in variant_scores.items()},
            "kind": str(model_entry["kind"]),
        }
        if model_entry["kind"] == "multiclass":
            multiclass_variants[model_name] = collect_multiclass_variant_probabilities(
                model_entry,
                image_variants,
                enable_tta=enable_tta,
            )

    return {
        "path": str(image_path),
        "model_details": model_details,
        "multiclass_variants": multiclass_variants,
    }


def evaluate_split(folder: Path, expected_label: str, *, enable_tta: bool) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for image_path in iter_images(folder):
        result = score_image(image_path, enable_tta=enable_tta)
        result["expected"] = expected_label
        rows.append(result)
    return rows


def get_multiclass_class_count(rows: list[dict[str, Any]], model_name: str) -> int:
    for row in rows:
        variant_probs = row.get("multiclass_variants", {}).get(model_name, [])
        if variant_probs:
            return len(variant_probs[0])
    return 0


def build_candidate_strategies(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    strategies: list[dict[str, Any]] = []
    model_names = sorted({model_name for row in rows for model_name in row.get("model_details", {}).keys()})
    for model_name in model_names:
        if any(model_name in row.get("multiclass_variants", {}) for row in rows):
            class_count = get_multiclass_class_count(rows, model_name)
            for clean_class_index in range(class_count):
                strategies.append(
                    {
                        "kind": "multiclass_clean_class",
                        "model_name": model_name,
                        "clean_class_index": clean_class_index,
                        "label": f"{model_name} clean_class={clean_class_index}",
                    }
                )
        else:
            strategies.append(
                {
                    "kind": "binary",
                    "model_name": model_name,
                    "label": f"{model_name} binary",
                }
            )
    return strategies


def get_strategy_score(row: dict[str, Any], strategy: dict[str, Any]) -> float:
    if strategy["kind"] == "binary":
        return float(row["model_details"][strategy["model_name"]]["score"])

    variant_probs = row["multiclass_variants"].get(strategy["model_name"], [])
    if not variant_probs:
        raise KeyError(f"No multiclass variants recorded for {strategy['model_name']}.")
    mean_probs = np.mean(variant_probs, axis=0)
    clean_prob = float(mean_probs[int(strategy["clean_class_index"])])
    return float(np.clip(1.0 - clean_prob, 0.0, 1.0))


def generate_threshold_candidates(scores: list[float]) -> list[float]:
    unique_scores = sorted(set(float(score) for score in scores))
    if not unique_scores:
        return [0.0, 1.0]
    candidates = {0.0, 1.0}
    candidates.update(unique_scores)
    for left, right in zip(unique_scores, unique_scores[1:]):
        candidates.add((left + right) / 2.0)
    return sorted(candidates)


def evaluate_strategy(
    rows: list[dict[str, Any]],
    strategy: dict[str, Any],
    clean_threshold: float,
    stego_threshold: float,
) -> dict[str, Any]:
    predicted_clean = 0
    predicted_stego = 0
    uncertain = 0
    correct_non_uncertain = 0
    false_positives = 0
    false_negatives = 0
    strategy_scores: list[float] = []

    for row in rows:
        score = get_strategy_score(row, strategy)
        strategy_scores.append(score)
        if score <= clean_threshold:
            predicted = "clean"
            predicted_clean += 1
        elif score >= stego_threshold:
            predicted = "stego"
            predicted_stego += 1
        else:
            predicted = "uncertain"
            uncertain += 1

        if predicted == "clean":
            if row["expected"] == "clean":
                correct_non_uncertain += 1
            else:
                false_negatives += 1
        elif predicted == "stego":
            if row["expected"] == "stego":
                correct_non_uncertain += 1
            else:
                false_positives += 1

    coverage = len(rows) - uncertain
    accuracy = (correct_non_uncertain / coverage) if coverage else 0.0
    return {
        "strategy": strategy,
        "clean_threshold": float(clean_threshold),
        "stego_threshold": float(stego_threshold),
        "coverage": int(coverage),
        "uncertain": int(uncertain),
        "accuracy": float(accuracy),
        "correct_non_uncertain": int(correct_non_uncertain),
        "false_positives": int(false_positives),
        "false_negatives": int(false_negatives),
        "mean_stego_score": float(np.mean(strategy_scores)) if strategy_scores else 0.0,
        "predicted_clean": int(predicted_clean),
        "predicted_stego": int(predicted_stego),
    }


def find_best_strategy(rows: list[dict[str, Any]]) -> dict[str, Any] | None:
    best_result: dict[str, Any] | None = None
    for strategy in build_candidate_strategies(rows):
        scores = [get_strategy_score(row, strategy) for row in rows]
        threshold_candidates = generate_threshold_candidates(scores)
        for clean_threshold in threshold_candidates:
            for stego_threshold in threshold_candidates:
                if clean_threshold > stego_threshold:
                    continue
                result = evaluate_strategy(rows, strategy, clean_threshold, stego_threshold)
                ranking = (
                    result["correct_non_uncertain"],
                    result["coverage"],
                    result["accuracy"],
                    -result["uncertain"],
                )
                if best_result is None or ranking > best_result["ranking"]:
                    best_result = {"ranking": ranking, "result": result}
    return None if best_result is None else best_result["result"]


def save_detector_config(best: dict[str, Any], clean_dir: Path, stego_dir: Path, output_path: Path) -> None:
    strategy = dict(best["strategy"])
    strategy.pop("label", None)
    config = {
        "strategy": strategy,
        "thresholds": {
            "clean": float(best["clean_threshold"]),
            "stego": float(best["stego_threshold"]),
        },
        "metrics": {
            "correct_non_uncertain": int(best["correct_non_uncertain"]),
            "coverage": int(best["coverage"]),
            "total": int(best["coverage"] + best["uncertain"]),
            "accuracy": float(best["accuracy"]),
            "false_positives": int(best["false_positives"]),
            "false_negatives": int(best["false_negatives"]),
            "uncertain": int(best["uncertain"]),
            "predicted_clean": int(best["predicted_clean"]),
            "predicted_stego": int(best["predicted_stego"]),
        },
        "source": {
            "clean_dir": str(clean_dir.resolve()),
            "stego_dir": str(stego_dir.resolve()),
        },
    }
    output_path.write_text(json.dumps(config, indent=2), encoding="utf-8")


def main() -> None:
    parser = argparse.ArgumentParser(description="Calibrate the steganalysis detector on labeled clean/stego folders.")
    parser.add_argument("--clean-dir", required=True, type=Path)
    parser.add_argument("--stego-dir", required=True, type=Path)
    parser.add_argument("--output", type=Path, default=scanner.DETECTOR_CONFIG_PATH)
    parser.add_argument("--disable-tta", action="store_true")
    args = parser.parse_args()

    clean_dir = args.clean_dir.resolve()
    stego_dir = args.stego_dir.resolve()
    if not clean_dir.is_dir():
        raise ValueError(f"Clean dir not found: {clean_dir}")
    if not stego_dir.is_dir():
        raise ValueError(f"Stego dir not found: {stego_dir}")

    rows = evaluate_split(clean_dir, "clean", enable_tta=not args.disable_tta)
    rows.extend(evaluate_split(stego_dir, "stego", enable_tta=not args.disable_tta))
    if not rows:
        raise ValueError("No supported images found in the supplied folders.")

    best = find_best_strategy(rows)
    if best is None:
        raise RuntimeError("Could not determine a detector strategy.")

    args.output.parent.mkdir(parents=True, exist_ok=True)
    save_detector_config(best, clean_dir, stego_dir, args.output)
    print(json.dumps(best, indent=2))
    print(f"Saved config: {args.output.resolve()}")


if __name__ == "__main__":
    main()
