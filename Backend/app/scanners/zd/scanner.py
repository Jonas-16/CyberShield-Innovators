from __future__ import annotations

import json
import os
import sys
from functools import lru_cache
from collections.abc import Sequence
from datetime import datetime
from pathlib import Path
from typing import Any

import numpy as np

APP_ROOT = Path(__file__).resolve().parents[2]
MODEL_DIR = APP_ROOT / "models" / "zd_models"
MODEL_PATH = MODEL_DIR / "cyber_shield_zero_day.pth"
NORM_PATH = MODEL_DIR / "normalization.npz"
REPORTS_DIR = APP_ROOT / "reports"
REPORTS_DIR.mkdir(parents=True, exist_ok=True)
SCAN_LOG_FILE = REPORTS_DIR / "scan_events.jsonl"

DEFAULT_BLOCK_THRESHOLD = 0.8
DEFAULT_ALLOW_THRESHOLD = 0.2


class ScannerStageError(RuntimeError):
    def __init__(self, stage: str, message: str):
        super().__init__(message)
        self.stage = stage


def _patch_numpy_for_legacy_ember() -> None:
    """
    Older EMBER code references deprecated NumPy aliases removed in modern NumPy.
    Provide aliases so feature extraction doesn't crash.
    """
    legacy_aliases = {
        "int": int,
        "float": float,
        "bool": bool,
        "object": object,
    }
    for alias, target in legacy_aliases.items():
        if not hasattr(np, alias):
            setattr(np, alias, target)


def _patch_sklearn_hasher_for_ember() -> None:
    """
    Some EMBER versions pass a single string sample into sklearn's FeatureHasher.
    Newer sklearn rejects that input. Wrap it into a one-sample iterable.
    """
    try:
        from sklearn.feature_extraction import _hash
        from sklearn.feature_extraction import FeatureHasher
    except Exception:
        return

    def _wrap_hasher(cls):
        if getattr(cls.transform, "_ember_patched", False):
            return

        original_transform = cls.transform

        def patched_transform(self, raw_X):
            if isinstance(raw_X, str):
                raw_X = [[raw_X]]
            elif isinstance(raw_X, Sequence) and not isinstance(raw_X, (bytes, bytearray)):
                if len(raw_X) > 0 and all(isinstance(item, str) for item in raw_X):
                    raw_X = [list(raw_X)]

            try:
                return original_transform(self, raw_X)
            except ValueError as exc:
                msg = str(exc)
                if "Samples can not be a single string" not in msg:
                    raise
                if isinstance(raw_X, str):
                    return original_transform(self, [[raw_X]])
                if isinstance(raw_X, Sequence) and not isinstance(raw_X, (bytes, bytearray)):
                    if len(raw_X) > 0 and all(isinstance(item, str) for item in raw_X):
                        return original_transform(self, [list(raw_X)])
                raise

        patched_transform._ember_patched = True  # type: ignore[attr-defined]
        cls.transform = patched_transform

    _wrap_hasher(_hash.FeatureHasher)
    _wrap_hasher(FeatureHasher)


def _patch_lief_for_ember() -> None:
    """
    EMBER expects old LIEF symbols such as `lief.bad_format`.
    Newer LIEF wheels removed/renamed them, which crashes feature extraction.
    Provide backward-compatible aliases so EMBER can run.
    """
    try:
        import lief
    except Exception:
        return

    # EMBER references legacy LIEF exception symbols that may be missing in new wheels.
    legacy_exception_names = (
        "bad_format",
        "bad_file",
        "pe_error",
        "parser_error",
        "read_out_of_bound",
        "not_found",
    )
    for name in legacy_exception_names:
        if not hasattr(lief, name):
            setattr(lief, name, Exception)


@lru_cache(maxsize=1)
def _init_ember_raw_extractor():
    _patch_numpy_for_legacy_ember()
    _patch_sklearn_hasher_for_ember()
    _patch_lief_for_ember()
    ember_root = APP_ROOT / "ember-master" / "ember-master"
    if ember_root.is_dir() and str(ember_root) not in sys.path:
        sys.path.insert(0, str(ember_root))

    from ember.features import PEFeatureExtractor

    return PEFeatureExtractor(feature_version=2)


@lru_cache(maxsize=1)
def _load_normalization() -> tuple[np.ndarray | None, np.ndarray | None]:
    if not NORM_PATH.exists():
        return None, None
    data = np.load(NORM_PATH)
    return data.get("mean"), data.get("std")


@lru_cache(maxsize=1)
def _load_model_bundle():
    try:
        import torch
    except Exception as exc:
        raise ScannerStageError("import_torch", str(exc))

    try:
        from .model_def import ZeroDayDetector
    except Exception as exc:
        raise ScannerStageError("import_model_def", str(exc))

    try:
        extractor = _init_ember_raw_extractor()
    except Exception as exc:
        raise ScannerStageError("init_extractor", str(exc))

    try:
        mean, std = _load_normalization()
    except Exception as exc:
        raise ScannerStageError("load_normalization", str(exc))

    input_dim = extractor.dim if mean is None else int(mean.shape[0])

    if not MODEL_PATH.exists():
        raise ScannerStageError("model_file", f"Model not found: {MODEL_PATH}")

    try:
        device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
        model = ZeroDayDetector(input_dim).to(device)
    except Exception as exc:
        raise ScannerStageError("init_model", str(exc))

    try:
        try:
            checkpoint = torch.load(str(MODEL_PATH), map_location=device, weights_only=True)
        except TypeError:
            checkpoint = torch.load(str(MODEL_PATH), map_location=device)
    except Exception as exc:
        raise ScannerStageError("load_checkpoint", str(exc))

    state_dict = checkpoint
    if isinstance(checkpoint, dict):
        if "state_dict" in checkpoint:
            state_dict = checkpoint["state_dict"]
        elif "model_state_dict" in checkpoint:
            state_dict = checkpoint["model_state_dict"]

    try:
        missing, unexpected = model.load_state_dict(state_dict, strict=False)
        if missing or unexpected:
            raise ScannerStageError(
                "model_state_mismatch",
                f"missing={len(missing)}, unexpected={len(unexpected)}",
            )
        model.eval()
    except ScannerStageError:
        raise
    except Exception as exc:
        raise ScannerStageError("load_state_dict", str(exc))

    return {
        "torch": torch,
        "device": device,
        "model": model,
        "extractor": extractor,
        "mean": mean,
        "std": std,
    }


def _extract_features(file_path: Path, extractor) -> np.ndarray:
    with file_path.open("rb") as handle:
        bytez = handle.read()
    vec = extractor.feature_vector(bytez)
    return vec.astype(np.float32)


def _combine_scores(static_prob: float, behavior_risk: float | None, fusion_alpha: float) -> float:
    if behavior_risk is None:
        return static_prob
    alpha = min(1.0, max(0.0, float(fusion_alpha)))
    return (alpha * static_prob) + ((1.0 - alpha) * behavior_risk)


def write_scan_event(payload: dict[str, Any]) -> dict[str, Any]:
    event = dict(payload)
    event.setdefault("ts", datetime.utcnow().isoformat(timespec="seconds") + "Z")
    with SCAN_LOG_FILE.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(event) + "\n")
    return event


def _heuristic_scan(file_path: Path) -> dict[str, Any]:
    name = file_path.name.lower()
    suspicious_exts = {".exe", ".dll", ".bat", ".cmd", ".ps1", ".vbs", ".js", ".scr", ".msi"}
    reasons: list[str] = []
    risk = 0.1

    ext = file_path.suffix.lower()
    if ext in suspicious_exts:
        risk += 0.55
        reasons.append(f"suspicious extension: {ext}")

    try:
        with file_path.open("rb") as handle:
            header = handle.read(2)
        if header == b"MZ":
            risk += 0.25
            reasons.append("portable executable header detected")
    except OSError:
        reasons.append("could not inspect file header")

    risk = min(0.99, max(0.01, risk))
    if risk > DEFAULT_BLOCK_THRESHOLD:
        decision = "BLOCKED"
    elif risk < DEFAULT_ALLOW_THRESHOLD:
        decision = "ALLOWED"
    else:
        decision = "UNCERTAIN"

    return {
        "engine": "heuristic",
        "decision": decision,
        "static_prob": risk,
        "behavior_risk": None,
        "fused_risk": risk,
        "reasons": reasons or ["no high-risk signals detected"],
    }


def _ml_scan(
    file_path: Path,
    block_threshold: float,
    allow_threshold: float,
    fusion_alpha: float,
) -> dict[str, Any]:
    try:
        bundle = _load_model_bundle()
    except Exception as exc:
        if isinstance(exc, ScannerStageError):
            raise
        raise ScannerStageError("load_model_bundle", str(exc))

    torch = bundle["torch"]
    device = bundle["device"]
    model = bundle["model"]
    extractor = bundle["extractor"]
    mean = bundle["mean"]
    std = bundle["std"]

    try:
        features = _extract_features(file_path, extractor)
    except Exception as exc:
        raise ScannerStageError("extract_features", str(exc))

    try:
        if mean is not None and std is not None:
            if features.shape[0] != mean.shape[0] or features.shape[0] != std.shape[0]:
                raise ScannerStageError(
                    "normalization_shape",
                    f"feature_dim={features.shape[0]}, mean_dim={mean.shape[0]}, std_dim={std.shape[0]}",
                )
            std_safe = np.where(std == 0, 1.0, std)
            features = (features - mean) / std_safe
    except ScannerStageError:
        raise
    except Exception as exc:
        raise ScannerStageError("normalize_features", str(exc))

    try:
        x = torch.tensor(features).unsqueeze(0).to(device)
        with torch.no_grad():
            static_prob = float(torch.sigmoid(model(x)).item())
    except Exception as exc:
        raise ScannerStageError("run_inference", str(exc))

    risk = _combine_scores(static_prob, None, fusion_alpha)
    if risk > block_threshold:
        decision = "BLOCKED"
    elif risk < allow_threshold:
        decision = "ALLOWED"
    else:
        decision = "UNCERTAIN"

    return {
        "engine": "ml",
        "decision": decision,
        "static_prob": static_prob,
        "behavior_risk": None,
        "fused_risk": risk,
        "reasons": [],
    }


def scan_file(
    file_path: str | Path,
    block_threshold: float = DEFAULT_BLOCK_THRESHOLD,
    allow_threshold: float = DEFAULT_ALLOW_THRESHOLD,
    fusion_alpha: float = 0.7,
    log_event: bool = True,
) -> dict[str, Any]:
    target = Path(file_path)
    if not target.exists() or not target.is_file():
        raise FileNotFoundError(f"Target file not found: {target}")

    result: dict[str, Any]
    try:
        result = _ml_scan(
            target,
            block_threshold=block_threshold,
            allow_threshold=allow_threshold,
            fusion_alpha=fusion_alpha,
        )
    except Exception as exc:
        result = _heuristic_scan(target)
        if isinstance(exc, ScannerStageError):
            result["scanner_stage"] = exc.stage
            result["scanner_warning"] = f"[{exc.stage}] {exc}"
        else:
            result["scanner_warning"] = str(exc)

    payload = {
        "path": str(target),
        "file_name": target.name,
        "decision": result["decision"],
        "static_prob": float(result.get("static_prob", 0.0)),
        "behavior_risk": result.get("behavior_risk"),
        "fused_risk": float(result.get("fused_risk", 0.0)),
        "engine": result.get("engine", "unknown"),
        "reasons": result.get("reasons", []),
        "scanner_stage": result.get("scanner_stage"),
        "scanner_warning": result.get("scanner_warning"),
        "block_threshold": float(block_threshold),
        "allow_threshold": float(allow_threshold),
    }
    if log_event:
        return write_scan_event(payload)
    return payload


def ml_stack_status() -> dict[str, Any]:
    status: dict[str, Any] = {
        "model_path": str(MODEL_PATH),
        "norm_path": str(NORM_PATH),
        "model_exists": MODEL_PATH.exists(),
        "norm_exists": NORM_PATH.exists(),
        "torch": False,
        "ember": False,
        "lief": False,
        "ready": False,
        "errors": [],
    }

    try:
        import torch  # noqa: F401
        status["torch"] = True
    except Exception as exc:
        status["errors"].append(f"torch: {exc}")

    try:
        _load_model_bundle()
        status["ember"] = True
        status["torch"] = True
        status["lief"] = True
    except Exception as exc:
        if isinstance(exc, ScannerStageError):
            status["errors"].append(f"{exc.stage}: {exc}")
        else:
            status["errors"].append(f"load_bundle: {exc}")

    status["ready"] = bool(
        status["model_exists"]
        and status["norm_exists"]
        and status["torch"]
        and status["ember"]
        and status["lief"]
    )
    return status






