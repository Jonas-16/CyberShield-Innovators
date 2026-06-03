from __future__ import annotations

import json
import math
import os
import re
import zipfile
import hashlib
from datetime import datetime, timezone
from functools import lru_cache
from pathlib import Path
from typing import Any

import numpy as np

APP_ROOT = Path(__file__).resolve().parents[2]
MODEL_DIR = APP_ROOT / "models" / "apk_models"
DEFAULT_MODEL_PATH = MODEL_DIR / "apk.pth"
METRICS_PATH = MODEL_DIR / "latest_metrics.json"
MODEL_PATH = Path(os.environ.get("APK_MODEL_PATH", str(DEFAULT_MODEL_PATH)))
REPORTS_DIR = APP_ROOT / "reports"
REPORTS_DIR.mkdir(parents=True, exist_ok=True)
SCAN_LOG_FILE = REPORTS_DIR / "scan_events.jsonl"

MODEL_DISPLAY_NAME = "Cyber Shield APK Zero-Day Detector"
MODEL_ARCHITECTURE_NAME = "Static APK Feature MLP"
APK_PREPROCESSING_VERSION = "ember_raw_counts_v2"
DEFAULT_LOGIT_THRESHOLD = -0.2528649866580963
DEFAULT_ALLOW_THRESHOLD = 0.20
DEFAULT_UNSAFE_THRESHOLD = 0.95
APK_BLOCK_THRESHOLD = 0.90
APK_HEURISTIC_BLOCK_THRESHOLD = 0.55
PRINTABLE_RE = re.compile(rb"[\x20-\x7e]{5,}")
URL_RE = re.compile(r"https?://[^\s\"'<>]+", re.IGNORECASE)
IP_RE = re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b")
SUSPICIOUS_APK_STRINGS = {
    "su",
    "busybox",
    "keylogger",
    "smsmanager",
    "sendtextmessage",
    "deviceadminreceiver",
    "dexclassloader",
    "loadclass",
    "runtime.getruntime",
    "exec(",
    "getexternalstoragedirectory",
    "accessibilityservice",
    "bind_accessibility_service",
    "request_install_packages",
    "system_alert_window",
    "receive_boot_completed",
    "read_sms",
    "send_sms",
    "record_audio",
    "camera",
    "read_contacts",
    "write_settings",
    "package_usage_stats",
    "query_all_packages",
    "manage_external_storage",
}
HIGH_RISK_PERMISSIONS = {
    "android.permission.bind_accessibility_service",
    "android.permission.request_install_packages",
    "android.permission.system_alert_window",
    "android.permission.receive_boot_completed",
    "android.permission.read_sms",
    "android.permission.send_sms",
    "android.permission.record_audio",
    "android.permission.camera",
    "android.permission.read_contacts",
    "android.permission.write_settings",
    "android.permission.package_usage_stats",
    "android.permission.query_all_packages",
    "android.permission.manage_external_storage",
}
SUSPICIOUS_FILE_EXTENSIONS = {
    ".sh",
    ".bat",
    ".cmd",
    ".ps1",
    ".exe",
    ".dll",
    ".jar",
    ".class",
    ".py",
}

FALLBACK_STRING_COUNT_KEYS = [
    ".click(",
    "/bin/",
    "/dev/",
    "/proc/",
    "/tmp/",
    "/usr/",
    "base64",
    "btc_wallet",
    "cache",
    "certificate",
    "clipboard",
    "connect",
    "cookie",
    "create",
    "crypt",
    "debug",
    "decode",
    "delete",
    "directory",
    "disk",
    "download",
    "encode",
    "enum",
    "environment",
    "exit",
    "file_path",
    "file",
    "hidden",
    "html",
    "http",
    "http://",
    "https://",
    "install",
    "internet",
    "ipv4_addr",
    "ipv6_addr",
    "keyboard",
    "memory",
    "module",
    "mutex",
    "onlick",
    "password",
    "privilege",
    "process",
    "resource",
    "security",
    "service",
    "snapshot",
    "system",
    "thread",
    "token",
    "url",
    "wallet",
    "window",
]


class ApkScannerError(RuntimeError):
    def __init__(self, stage: str, message: str):
        super().__init__(message)
        self.stage = stage


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def _sigmoid(value: float) -> float:
    if value >= 0:
        return 1.0 / (1.0 + math.exp(-value))
    exp_value = math.exp(value)
    return exp_value / (1.0 + exp_value)


def _safe_float(value: Any) -> float:
    if value is None:
        return 0.0
    if isinstance(value, bool):
        return float(value)
    if isinstance(value, (int, float)):
        return float(value)
    return 0.0


def _pad_or_trim(values: list[float], size: int) -> list[float]:
    if len(values) >= size:
        return values[:size]
    return values + [0.0] * (size - len(values))


def _byte_histogram(bytez: bytes) -> list[float]:
    if not bytez:
        return [0.0] * 256
    counts = np.bincount(np.frombuffer(bytez, dtype=np.uint8), minlength=256).astype(np.float32)
    return counts.tolist()


def _entropy_from_counts(counts: np.ndarray) -> float:
    total = float(counts.sum())
    if total <= 0:
        return 0.0
    probs = counts[counts > 0] / total
    return float(-(probs * np.log2(probs)).sum())


def _byte_entropy_histogram(bytez: bytes, window_size: int = 2048, step_size: int = 1024) -> list[float]:
    hist = np.zeros((16, 16), dtype=np.float32)
    if not bytez:
        return hist.reshape(-1).tolist()

    if len(bytez) < window_size:
        windows = [bytez]
    else:
        windows = [bytez[offset : offset + window_size] for offset in range(0, len(bytez) - window_size + 1, step_size)]

    for window in windows:
        arr = np.frombuffer(window, dtype=np.uint8)
        counts = np.bincount(arr, minlength=256).astype(np.float32)
        entropy_bin = min(15, int((_entropy_from_counts(counts) / 8.0) * 16.0))
        byte_bins = np.bincount(arr >> 4, minlength=16).astype(np.float32)
        hist[entropy_bin] += byte_bins

    total = float(hist.sum())
    return hist.reshape(-1).tolist()


def _printable_distribution(strings: list[bytes], printable_count: int) -> list[float]:
    dist = np.zeros(96, dtype=np.float32)
    if printable_count <= 0:
        return dist.tolist()
    for item in strings:
        arr = np.frombuffer(item, dtype=np.uint8)
        arr = arr[(arr >= 32) & (arr <= 127)]
        if arr.size:
            dist += np.bincount(arr - 32, minlength=96).astype(np.float32)
    return dist.tolist()


def _string_entropy(strings: list[bytes]) -> float:
    if not strings:
        return 0.0
    joined = b"".join(strings)
    if not joined:
        return 0.0
    counts = np.bincount(np.frombuffer(joined, dtype=np.uint8), minlength=256).astype(np.float32)
    return _entropy_from_counts(counts)


def _string_count_features(text: str, keys: list[str]) -> list[float]:
    lowered = text.lower()
    return [float(lowered.count(key.lower())) for key in keys]


def _zip_metadata(bytez: bytes) -> tuple[list[str], int]:
    try:
        from io import BytesIO

        with zipfile.ZipFile(BytesIO(bytez)) as archive:
            names = archive.namelist()
            compressed = sum(int(info.compress_size or 0) for info in archive.infolist())
            return names, compressed
    except Exception:
        return [], 0


def _sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _zip_security_details(bytez: bytes) -> dict[str, Any]:
    details: dict[str, Any] = {
        "duplicate_entries": [],
        "path_traversal_entries": [],
        "encrypted_entry_count": 0,
        "suspicious_embedded_files": [],
        "max_compression_ratio": 0.0,
        "certificate_sha256": [],
    }
    try:
        from io import BytesIO

        with zipfile.ZipFile(BytesIO(bytez)) as archive:
            seen: set[str] = set()
            duplicates: set[str] = set()
            path_traversal: list[str] = []
            suspicious_files: list[str] = []
            cert_hashes: list[str] = []
            encrypted = 0
            max_ratio = 0.0

            for info in archive.infolist():
                normalized = info.filename.replace("\\", "/").lower()
                if normalized in seen:
                    duplicates.add(normalized)
                seen.add(normalized)

                parts = [part for part in normalized.split("/") if part]
                if normalized.startswith("/") or ".." in parts:
                    path_traversal.append(info.filename)

                if info.flag_bits & 0x1:
                    encrypted += 1

                if info.compress_size:
                    max_ratio = max(max_ratio, float(info.file_size or 0) / max(float(info.compress_size), 1.0))

                suffix = Path(normalized).suffix
                if suffix in SUSPICIOUS_FILE_EXTENSIONS:
                    suspicious_files.append(info.filename)

                if normalized.startswith("meta-inf/") and suffix in {".rsa", ".dsa", ".ec"}:
                    try:
                        cert_hashes.append(_sha256_hex(archive.read(info)))
                    except Exception:
                        continue

            details["duplicate_entries"] = sorted(duplicates)[:20]
            details["path_traversal_entries"] = path_traversal[:20]
            details["encrypted_entry_count"] = encrypted
            details["suspicious_embedded_files"] = suspicious_files[:30]
            details["max_compression_ratio"] = float(max_ratio)
            details["certificate_sha256"] = sorted(set(cert_hashes))[:10]
    except Exception:
        pass
    return details


def _read_zip_entries(bytez: bytes, max_entry_bytes: int = 8_000_000) -> dict[str, bytes]:
    entries: dict[str, bytes] = {}
    try:
        from io import BytesIO

        with zipfile.ZipFile(BytesIO(bytez)) as archive:
            for info in archive.infolist():
                if int(info.file_size or 0) > max_entry_bytes:
                    continue
                name = info.filename
                lowered = name.lower()
                if (
                    lowered == "androidmanifest.xml"
                    or lowered.endswith(".dex")
                    or lowered.startswith("meta-inf/")
                    or lowered.endswith((".so", ".xml", ".txt", ".properties"))
                ):
                    try:
                        entries[name] = archive.read(info)
                    except Exception:
                        continue
    except Exception:
        return {}
    return entries


def _extract_manifest_text(entries: dict[str, bytes]) -> str:
    manifest = next((value for key, value in entries.items() if key.lower() == "androidmanifest.xml"), b"")
    if not manifest:
        return ""
    ascii_strings = PRINTABLE_RE.findall(manifest)
    return "\n".join(item.decode("latin1", errors="ignore") for item in ascii_strings)


def _apk_static_analysis(bytez: bytes, target: Path) -> dict[str, Any]:
    names, compressed_size = _zip_metadata(bytez)
    lowered_names = [name.lower() for name in names]
    zip_security = _zip_security_details(bytez)
    entries = _read_zip_entries(bytez)
    manifest_text = _extract_manifest_text(entries)
    combined_text = "\n".join(
        [
            target.name.lower(),
            "\n".join(lowered_names),
            manifest_text.lower(),
            "\n".join(
                value.decode("latin1", errors="ignore").lower()
                for key, value in entries.items()
                if key.lower().endswith((".dex", ".xml", ".txt", ".properties"))
            ),
        ]
    )

    dex_files = [name for name in lowered_names if name.endswith(".dex")]
    native_libs = [name for name in lowered_names if name.startswith("lib/") and name.endswith(".so")]
    cert_files = [
        name
        for name in lowered_names
        if name.startswith("meta-inf/") and name.endswith((".rsa", ".dsa", ".ec", ".sf"))
    ]
    high_risk_permissions = sorted(permission for permission in HIGH_RISK_PERMISSIONS if permission in combined_text)
    suspicious_hits = sorted(token for token in SUSPICIOUS_APK_STRINGS if token in combined_text)
    urls = sorted(set(URL_RE.findall(combined_text)))[:50]
    ip_addresses = sorted(set(IP_RE.findall(combined_text)))[:50]
    raw_ip_urls = sorted(url for url in urls if IP_RE.search(url))[:20]

    reasons: list[str] = []
    risk = 0.10
    valid_zip = bool(names)
    if not valid_zip:
        risk += 0.45
        reasons.append("apk is not a readable zip container")
    if not any(name == "androidmanifest.xml" for name in lowered_names):
        risk += 0.20
        reasons.append("AndroidManifest.xml not found")
    if not cert_files:
        risk += 0.20
        reasons.append("APK signing certificate files not found")
    if len(dex_files) > 1:
        risk += min(0.12, 0.03 * (len(dex_files) - 1))
        reasons.append(f"multiple dex files: {len(dex_files)}")
    if native_libs:
        risk += min(0.10, 0.02 * len(native_libs))
        reasons.append(f"native libraries present: {len(native_libs)}")
    if high_risk_permissions:
        risk += min(0.25, 0.05 * len(high_risk_permissions))
        reasons.append("high-risk Android permissions requested")
    if suspicious_hits:
        risk += min(0.25, 0.04 * len(suspicious_hits))
        reasons.append("suspicious Android strings found")
    if raw_ip_urls:
        risk += min(0.12, 0.04 * len(raw_ip_urls))
        reasons.append("network URLs use raw IP addresses")
    if len(ip_addresses) >= 5:
        risk += 0.08
        reasons.append("many IP address strings found")
    if zip_security["duplicate_entries"]:
        risk += 0.10
        reasons.append("duplicate ZIP entries found")
    if zip_security["path_traversal_entries"]:
        risk += 0.25
        reasons.append("ZIP path traversal entries found")
    if zip_security["encrypted_entry_count"]:
        risk += 0.10
        reasons.append("encrypted ZIP entries found")
    if zip_security["suspicious_embedded_files"]:
        risk += min(0.12, 0.04 * len(zip_security["suspicious_embedded_files"]))
        reasons.append("suspicious embedded file types found")
    if zip_security["max_compression_ratio"] >= 100.0:
        risk += 0.08
        reasons.append("very high compression ratio entry found")
    if "apkpure" in target.name.lower():
        risk += 0.08
        reasons.append("third-party APK distribution filename")

    low_risk_structure = (
        valid_zip
        and any(name == "androidmanifest.xml" for name in lowered_names)
        and bool(cert_files)
        and bool(dex_files)
        and not high_risk_permissions
        and not suspicious_hits
        and not zip_security["path_traversal_entries"]
        and not zip_security["duplicate_entries"]
    )
    if low_risk_structure:
        risk = max(0.01, risk - 0.10)
        reasons.append("standard APK structure with no strong static indicators")

    risk = float(min(0.99, max(0.01, risk)))
    evidence_level = "high" if risk >= APK_HEURISTIC_BLOCK_THRESHOLD else ("medium" if risk >= 0.30 else "low")
    return {
        "valid_zip": valid_zip,
        "entry_count": len(names),
        "compressed_size": int(compressed_size),
        "dex_count": len(dex_files),
        "native_library_count": len(native_libs),
        "certificate_file_count": len(cert_files),
        "certificate_sha256": zip_security["certificate_sha256"],
        "manifest_strings_available": bool(manifest_text),
        "high_risk_permissions": high_risk_permissions[:20],
        "suspicious_indicators": suspicious_hits[:30],
        "url_count": len(urls),
        "sample_urls": urls[:10],
        "ip_address_count": len(ip_addresses),
        "sample_ip_addresses": ip_addresses[:10],
        "raw_ip_urls": raw_ip_urls,
        "duplicate_entries": zip_security["duplicate_entries"],
        "path_traversal_entries": zip_security["path_traversal_entries"],
        "encrypted_entry_count": zip_security["encrypted_entry_count"],
        "suspicious_embedded_files": zip_security["suspicious_embedded_files"],
        "max_compression_ratio": zip_security["max_compression_ratio"],
        "low_risk_structure": low_risk_structure,
        "evidence_level": evidence_level,
        "heuristic_risk": risk,
        "heuristic_reasons": reasons or ["no strong APK structural indicators found"],
    }


def _build_feature_vector(bytez: bytes, string_count_keys: list[str]) -> np.ndarray:
    strings = PRINTABLE_RE.findall(bytez)
    printable_count = int(sum(len(item) for item in strings))
    string_lengths = [len(item) for item in strings]
    decoded_strings = "\n".join(item.decode("latin1", errors="ignore") for item in strings)
    zip_names, compressed_size = _zip_metadata(bytez)
    if zip_names:
        decoded_strings = decoded_strings + "\n" + "\n".join(zip_names)

    features: list[float] = []
    features.extend(_byte_histogram(bytez))
    features.extend(_byte_entropy_histogram(bytez))
    features.extend(_printable_distribution(strings, printable_count))
    features.extend(
        [
            float(len(strings)),
            float(np.mean(string_lengths)) if string_lengths else 0.0,
            float(printable_count),
            _string_entropy(strings),
            float(len(bytez)),
            _entropy_from_counts(np.bincount(np.frombuffer(bytez, dtype=np.uint8), minlength=256).astype(np.float32))
            if bytez
            else 0.0,
            1.0 if bytez.startswith(b"MZ") else 0.0,
        ]
    )
    features.extend(_pad_or_trim([float(item) for item in bytez[:4]], 4))
    features.extend(_string_count_features(decoded_strings, string_count_keys))

    return np.asarray(features, dtype=np.float32)


def _extract_state_dict(checkpoint: Any) -> dict[str, Any]:
    if isinstance(checkpoint, dict):
        state_dict = checkpoint.get("model_state_dict") or checkpoint.get("state_dict")
        if isinstance(state_dict, dict):
            return state_dict
    if isinstance(checkpoint, dict):
        return checkpoint
    raise ApkScannerError("checkpoint_format", f"Unsupported checkpoint format: {type(checkpoint).__name__}")


def _load_metrics() -> dict[str, Any]:
    if not METRICS_PATH.exists():
        return {}
    try:
        with METRICS_PATH.open("r", encoding="utf-8") as handle:
            return json.load(handle)
    except Exception:
        return {}


@lru_cache(maxsize=1)
def _load_model_bundle():
    try:
        import torch
    except Exception as exc:
        raise ApkScannerError("import_torch", str(exc))

    try:
        from .model_def import ApkMLP
    except Exception as exc:
        raise ApkScannerError("import_model_def", str(exc))

    if not MODEL_PATH.exists():
        raise ApkScannerError("model_file", f"Model not found: {MODEL_PATH}")

    try:
        device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
        try:
            checkpoint = torch.load(str(MODEL_PATH), map_location=device, weights_only=False)
        except TypeError:
            checkpoint = torch.load(str(MODEL_PATH), map_location=device)
    except Exception as exc:
        raise ApkScannerError("load_checkpoint", str(exc))

    input_dim = int(checkpoint.get("input_dim", 673)) if isinstance(checkpoint, dict) else 673
    hidden_dims = list(checkpoint.get("hidden_dims", [2048, 1024, 512])) if isinstance(checkpoint, dict) else [2048, 1024, 512]
    dropout = float(checkpoint.get("dropout", 0.1)) if isinstance(checkpoint, dict) else 0.1
    string_count_keys = list(checkpoint.get("string_count_keys", FALLBACK_STRING_COUNT_KEYS)) if isinstance(checkpoint, dict) else FALLBACK_STRING_COUNT_KEYS
    scaler_mean = checkpoint.get("scaler_mean") if isinstance(checkpoint, dict) else None
    scaler_std = checkpoint.get("scaler_std") if isinstance(checkpoint, dict) else None
    if scaler_mean is None or scaler_std is None:
        raise ApkScannerError("normalization", "Checkpoint does not contain scaler_mean/scaler_std")

    try:
        model = ApkMLP(input_dim=input_dim, hidden_dims=hidden_dims, dropout=dropout).to(device)
        model.load_state_dict(_extract_state_dict(checkpoint))
        model.eval()
    except Exception as exc:
        raise ApkScannerError("load_state_dict", str(exc))

    return {
        "torch": torch,
        "device": device,
        "model": model,
        "input_dim": input_dim,
        "hidden_dims": hidden_dims,
        "dropout": dropout,
        "scaler_mean": np.asarray(scaler_mean, dtype=np.float32),
        "scaler_std": np.asarray(scaler_std, dtype=np.float32),
        "string_count_keys": string_count_keys,
        "metrics": _load_metrics(),
    }


def current_model_identity() -> dict[str, Any]:
    return {
        "model_name": MODEL_DISPLAY_NAME,
        "model_architecture": MODEL_ARCHITECTURE_NAME,
        "model_artifact_name": MODEL_PATH.name,
        "model_artifact_path": str(MODEL_PATH),
    }


def write_scan_event(payload: dict[str, Any]) -> dict[str, Any]:
    event = {**current_model_identity(), **dict(payload)}
    event.setdefault("ts", _utc_now())
    with SCAN_LOG_FILE.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(event) + "\n")
    return event


def _heuristic_scan(target: Path, warning: str | None = None) -> dict[str, Any]:
    reasons = ["android package extension detected"]
    risk = 0.35
    try:
        with target.open("rb") as handle:
            header = handle.read(4)
        if header.startswith(b"PK"):
            risk += 0.10
            reasons.append("zip/apk container header detected")
        else:
            risk += 0.20
            reasons.append("apk extension without zip container header")
    except OSError:
        reasons.append("could not inspect file header")
        risk += 0.15

    risk = min(0.95, risk)
    decision = "UNCERTAIN" if risk >= DEFAULT_ALLOW_THRESHOLD else "ALLOWED"
    if warning:
        reasons.append("trained apk model verdict unavailable; result held for review")
    return {
        **current_model_identity(),
        "engine": "apk-heuristic" if warning is None else "apk-ml-unavailable",
        "apk_preprocessing_version": APK_PREPROCESSING_VERSION,
        "decision": decision,
        "static_prob": risk,
        "behavior_risk": None,
        "fused_risk": risk,
        "predicted_label": "Suspicious APK" if decision == "UNCERTAIN" else "Likely Benign APK",
        "confidence": risk if decision == "UNCERTAIN" else 1.0 - risk,
        "reasons": reasons,
        "scanner_stage": "apk_static",
        "scanner_warning": warning,
        "risk_band": "medium" if risk >= DEFAULT_ALLOW_THRESHOLD else "low",
        "review_threshold": _sigmoid(DEFAULT_LOGIT_THRESHOLD),
        "unsafe_threshold": DEFAULT_UNSAFE_THRESHOLD,
    }


def _ml_scan(target: Path) -> dict[str, Any]:
    bundle = _load_model_bundle()
    torch = bundle["torch"]
    with target.open("rb") as handle:
        bytez = handle.read()

    apk_analysis = _apk_static_analysis(bytez, target)
    raw_features = _build_feature_vector(bytez, bundle["string_count_keys"])
    input_dim = int(bundle["input_dim"])
    if raw_features.shape[0] != input_dim:
        raise ApkScannerError("feature_shape", f"feature_dim={raw_features.shape[0]}, input_dim={input_dim}")

    scaler_std = np.where(bundle["scaler_std"] == 0, 1.0, bundle["scaler_std"])
    features = ((raw_features - bundle["scaler_mean"]) / scaler_std).astype(np.float32)

    try:
        x = torch.tensor(features).unsqueeze(0).to(bundle["device"])
        with torch.no_grad():
            logit = float(bundle["model"](x).item())
    except Exception as exc:
        raise ApkScannerError("run_inference", str(exc))

    ml_risk = _sigmoid(logit)
    heuristic_risk = float(apk_analysis["heuristic_risk"])
    raw_combined_risk = float(max(ml_risk, (0.75 * ml_risk) + (0.25 * heuristic_risk)))
    metrics = bundle["metrics"]
    logit_threshold = float(metrics.get("best_val_threshold", DEFAULT_LOGIT_THRESHOLD))
    review_threshold = _sigmoid(logit_threshold)
    model_positive = logit >= logit_threshold
    strong_structural_support = heuristic_risk >= APK_HEURISTIC_BLOCK_THRESHOLD or not apk_analysis["valid_zip"]
    decision = (
        "BLOCKED"
        if model_positive and ml_risk >= APK_BLOCK_THRESHOLD and strong_structural_support
        else ("ALLOWED" if raw_combined_risk < DEFAULT_ALLOW_THRESHOLD else "UNCERTAIN")
    )
    risk = raw_combined_risk if decision == "BLOCKED" else min(raw_combined_risk, DEFAULT_UNSAFE_THRESHOLD - 0.01)
    predicted_label = "Malicious APK" if decision == "BLOCKED" else ("Suspicious APK" if decision == "UNCERTAIN" else "Likely Benign APK")
    risk_band = "high" if risk >= DEFAULT_UNSAFE_THRESHOLD else ("medium" if risk >= review_threshold else "low")

    reasons = [
        "static android package features scored by apk zero-day model",
        f"apk model threshold: {review_threshold:.3f}",
    ]
    if decision == "BLOCKED":
        reasons.append("apk model score and APK structural indicators both support blocking")
    elif decision == "UNCERTAIN":
        reasons.append("apk model score requires manual review")
    else:
        reasons.append("apk score is below the low-risk allow threshold")
    reasons.extend(apk_analysis["heuristic_reasons"])

    return {
        **current_model_identity(),
        "engine": "apk-ml",
        "apk_preprocessing_version": APK_PREPROCESSING_VERSION,
        "decision": decision,
        "static_prob": ml_risk,
        "behavior_risk": None,
        "fused_risk": risk,
        "apk_raw_combined_risk": raw_combined_risk,
        "apk_malware_prob": ml_risk,
        "apk_benign_prob": 1.0 - ml_risk,
        "apk_structural_risk": heuristic_risk,
        "apk_static_analysis": apk_analysis,
        "apk_logit": logit,
        "apk_logit_threshold": logit_threshold,
        "predicted_label": predicted_label,
        "confidence": risk if decision != "ALLOWED" else 1.0 - risk,
        "reasons": reasons,
        "issue_labels": ["android-package", "likely-malware"] if decision == "BLOCKED" else ["android-package", "manual-review"] if decision == "UNCERTAIN" else ["android-package"],
        "threat_summary": (
            "Likely malicious Android package based on static APK features."
            if decision == "BLOCKED"
            else "Low APK malware probability from the static model."
            if decision == "ALLOWED"
            else "Borderline Android package that should stay in manual review."
        ),
        "threat_family": None,
        "threat_type": "android-apk",
        "threat_label_source": "apk-static-ml",
        "threat_details": ["This checkpoint is a binary APK malware detector, not a family classifier."],
        "risk_band": risk_band,
        "scanner_stage": "apk_static",
        "scanner_warning": None,
        "review_threshold": review_threshold,
        "unsafe_threshold": DEFAULT_UNSAFE_THRESHOLD,
        "checkpoint_epoch": metrics.get("best_epoch"),
        "validation_roc_auc": metrics.get("ensemble_val_roc_auc") or metrics.get("best_val_roc_auc"),
        "test_roc_auc": metrics.get("ensemble_test_roc_auc") or metrics.get("test_metrics", {}).get("roc_auc"),
    }


def scan_file(file_path: str | Path, log_event: bool = True, **_: Any) -> dict[str, Any]:
    target = Path(file_path)
    if not target.exists() or not target.is_file():
        raise FileNotFoundError(f"Target file not found: {target}")

    try:
        result = _ml_scan(target)
    except Exception as exc:
        warning = f"[{exc.stage}] {exc}" if isinstance(exc, ApkScannerError) else str(exc)
        result = _heuristic_scan(target, warning=warning)

    payload = {
        **current_model_identity(),
        "path": str(target),
        "file_name": target.name,
        **result,
    }
    if log_event:
        return write_scan_event(payload)
    return payload


def ml_stack_status() -> dict[str, Any]:
    status: dict[str, Any] = {
        "model_name": MODEL_DISPLAY_NAME,
        "architecture_name": MODEL_ARCHITECTURE_NAME,
        "model_path": str(MODEL_PATH),
        "model_exists": MODEL_PATH.exists(),
        "metrics_path": str(METRICS_PATH),
        "metrics_exists": METRICS_PATH.exists(),
        "preprocessing_version": APK_PREPROCESSING_VERSION,
        "torch": False,
        "ready": False,
        "errors": [],
    }
    try:
        import torch  # noqa: F401

        status["torch"] = True
    except Exception as exc:
        status["errors"].append(f"torch: {exc}")

    if status["torch"] and status["model_exists"]:
        try:
            _load_model_bundle.cache_clear()
            bundle = _load_model_bundle()
            status["ready"] = True
            status["input_dim"] = bundle["input_dim"]
            status["hidden_dims"] = bundle["hidden_dims"]
            status["dropout"] = bundle["dropout"]
            status["device"] = str(bundle["device"])
            status["metrics"] = bundle["metrics"]
        except Exception as exc:
            status["errors"].append(str(exc))
    return status
