#!/usr/bin/env python3

import base64
import binascii
import hashlib
import html
import math
import re
import shutil
import string
import subprocess
import sys
from pathlib import Path

import numpy as np
from PIL import Image


PRINTABLE_BYTES = set(range(9, 14)) | set(range(32, 127))
TEXT_CHARS = set(bytes(string.printable, "ascii"))
METADATA_HINTS = (
    "adobe", "xmp", "rdf:", "icc", "srgb", "photoshop", "exif",
    "creator", "copyright", "http://ns.", "http://www.iec.ch",
    "hewlett-packard", "xml", "jfif", "iec61966", "reference viewing",
)
SIGNATURES = (
    (b"PK\x03\x04", "zip"),
    (b"\x89PNG\r\n\x1a\n", "png"),
    (b"\xff\xd8\xff", "jpg"),
    (b"%PDF-", "pdf"),
    (b"GIF87a", "gif"),
    (b"GIF89a", "gif"),
    (b"Rar!\x1a\x07\x00", "rar"),
    (b"7z\xbc\xaf\x27\x1c", "7z"),
)
COMMON_PASSPHRASES = (
    "password", "passphrase", "secret", "hidden", "message", "stego", "phasm",
    "test", "hello", "admin", "letmein", "qwerty", "123456", "12345678",
    "123456789", "1234567890", "000000", "111111", "abc123", "password123",
    "secret123", "test123", "hello123", "stego123", "phasm123", "project",
    "project123", "image", "photo", "decode", "extract", "great",
)


class Result:
    def __init__(self, kind, name, data, score=0.0, extension="txt", note=""):
        self.kind = kind
        self.name = name
        self.data = data
        self.score = score
        self.extension = extension
        self.note = note
        self.path = None

    @property
    def size(self):
        return len(self.data)


class Artifact:
    def __init__(self, kind, name, path, note=""):
        self.kind = kind
        self.name = name
        self.path = path
        self.note = note


class Finding:
    def __init__(self, level, title, detail):
        self.level = level
        self.title = title
        self.detail = detail


class Status:
    def __init__(self):
        self.readable_message_found = False
        self.likely_encrypted_or_protected = False
        self.suspected_tool = "Unknown"
        self.passphrase_required = False
        self.recommendation = "Review the generated report and candidate files."


def help_and_exit():
    script = Path(sys.argv[0]).name
    print("")
    print("Usage:")
    print(f"  python {script} scan <file> [output-dir]")
    print(f"  python {script} scan <file> [output-dir] --expected \"known text\"")
    print(f"  python {script} scan <file> [output-dir] --passphrase \"phasm passphrase\"")
    print(f"  python {script} scan <file> [output-dir] --wordlist passwords.txt")
    print(f"  python {script} scan <file> [output-dir] --guess-seed \"name or clue\"")
    print(f"  python {script} <file> [output-dir]")
    print("")
    print("Examples:")
    print(f"  python {script} scan unknown.png extracted")
    print(f"  python {script} suspicious.bin extracted")
    print("")
    print("Note:")
    print("  This tries common no-password extraction methods. It cannot decrypt")
    print("  password-protected, encrypted, compressed, or custom stego formats.")
    print("")
    sys.exit(0)


def printable_score(data):
    if not data:
        return 0.0
    sample = data[:4096]
    return sum(b in PRINTABLE_BYTES for b in sample) / len(sample)


def diversity_score(data):
    if not data:
        return 0.0
    sample = data[:4096]
    return len(set(sample)) / len(sample)


def most_common_score(data):
    if not data:
        return 1.0
    sample = data[:4096]
    counts = {}
    for byte in sample:
        counts[byte] = counts.get(byte, 0) + 1
    return max(counts.values()) / len(sample)


def longest_run_score(data):
    if not data:
        return 1.0
    sample = data[:4096]
    longest = 1
    current = 1
    previous = sample[0]
    for byte in sample[1:]:
        if byte == previous:
            current += 1
            longest = max(longest, current)
        else:
            current = 1
            previous = byte
    return longest / len(sample)


def letter_score(data):
    if not data:
        return 0.0
    sample = data[:4096]
    letters = sum((65 <= b <= 90) or (97 <= b <= 122) for b in sample)
    return letters / len(sample)


def looks_useful_text(data):
    if len(data) < 12:
        return False
    if printable_score(data) < 0.88:
        return False
    if diversity_score(data) < 0.08:
        return False
    if most_common_score(data) > 0.45:
        return False
    if longest_run_score(data) > 0.25:
        return False
    sample = data[:4096]
    letters = sum((65 <= b <= 90) or (97 <= b <= 122) for b in sample)
    spaces = sample.count(32)
    punctuation = sum(chr(b) in string.punctuation for b in sample)
    if letters / len(sample) < 0.35:
        return False
    if punctuation / len(sample) > 0.35:
        return False
    return spaces > 0 or len(data) >= 30


def is_metadata_text(data):
    text = data[:4096].decode("utf-8", errors="ignore").lower()
    return any(hint in text for hint in METADATA_HINTS)


def safe_name(value):
    return "".join(ch if ch.isalnum() or ch in "._-" else "_" for ch in value)


def extract_ascii_strings(data, min_len=24):
    candidates = []
    current = bytearray()

    for byte in data:
        if byte in TEXT_CHARS and byte not in (11, 12):
            current.append(byte)
        else:
            if len(current) >= min_len:
                candidates.append(bytes(current).strip())
            current.clear()

    if len(current) >= min_len:
        candidates.append(bytes(current).strip())

    return [item for item in candidates if len(item) >= min_len]


def trim_text_candidate(data):
    start = 0
    while start < len(data) and data[start] not in PRINTABLE_BYTES:
        start += 1

    end = start
    misses = 0
    last_good = start

    while end < len(data):
        byte = data[end]
        if byte in PRINTABLE_BYTES:
            misses = 0
            last_good = end + 1
        elif byte == 0 and end > start:
            break
        else:
            misses += 1
            if misses >= 16:
                break
        end += 1

    return data[start:last_good].strip()


def open_image(path):
    try:
        image = Image.open(path)
        image.load()
        return image.convert("RGBA") if image.mode not in ("L", "RGB", "RGBA") else image
    except Exception:
        return None


def write_result(output_dir, result, index):
    output_dir.mkdir(parents=True, exist_ok=True)
    name = safe_name(f"{index:03d}_{result.kind}_{result.name}")
    path = output_dir / f"{name}.{result.extension}"
    path.write_bytes(result.data)
    result.path = path


def write_text_artifact(output_dir, kind, name, text):
    output_dir.mkdir(parents=True, exist_ok=True)
    path = output_dir / f"artifact_{safe_name(name)}.txt"
    path.write_text(text, encoding="utf-8", errors="replace")
    return Artifact(kind, name, path)


def clean_previous_outputs(output_dir):
    output_dir.mkdir(parents=True, exist_ok=True)
    for path in output_dir.iterdir():
        generated = (
            re.match(r"^\d{3}_", path.name)
            or path.name.startswith("artifact_")
            or re.match(r"^(strings|lsb|decoded|carved|appended)_", path.name)
        )
        if path.is_file() and generated:
            path.unlink()
    for name in ("scan_report.txt", "scan_report.html"):
        report = output_dir / name
        if report.exists():
            report.unlink()


def add_result(results, seen, result):
    digest = hashlib.sha256(result.data[:8192]).hexdigest()
    key = (result.kind, digest)
    if key in seen:
        return
    seen.add(key)
    results.append(result)


def is_readable_result(result):
    return result.kind in {
        "text",
        "decoded-base64",
        "decoded-hex",
        "appended-text",
        "image-lsb",
        "phasm-message",
    }


def scan_file_strings(data, results, metadata, seen):
    for index, candidate in enumerate(extract_ascii_strings(data), start=1):
        if is_metadata_text(candidate):
            metadata.append(candidate)
            continue
        if looks_useful_text(candidate):
            add_result(
                results,
                seen,
                Result("text", f"strings_{index}", candidate, printable_score(candidate)),
            )


def decode_base64_text(candidate):
    compact = re.sub(rb"\s+", b"", candidate)
    if len(compact) < 24 or len(compact) % 4 != 0:
        return None
    if not re.fullmatch(rb"[A-Za-z0-9+/]+={0,2}", compact):
        return None
    try:
        decoded = base64.b64decode(compact, validate=True)
    except binascii.Error:
        return None
    return decoded if looks_useful_text(decoded) else None


def decode_hex_text(candidate):
    compact = re.sub(rb"\s+", b"", candidate)
    if len(compact) < 32 or len(compact) % 2 != 0:
        return None
    if not re.fullmatch(rb"[0-9A-Fa-f]+", compact):
        return None
    try:
        decoded = bytes.fromhex(compact.decode("ascii"))
    except ValueError:
        return None
    return decoded if looks_useful_text(decoded) else None


def scan_encoded_text(data, results, seen):
    for index, candidate in enumerate(extract_ascii_strings(data, min_len=24), start=1):
        decoded = decode_base64_text(candidate)
        if decoded:
            add_result(
                results,
                seen,
                Result("decoded-base64", f"base64_{index}", decoded, printable_score(decoded)),
            )

        decoded = decode_hex_text(candidate)
        if decoded:
            add_result(
                results,
                seen,
                Result("decoded-hex", f"hex_{index}", decoded, printable_score(decoded)),
            )

        for match_index, match in enumerate(
            re.finditer(rb"(?<![A-Za-z0-9+/])[A-Za-z0-9+/]{24,}={0,2}(?![A-Za-z0-9+/=])", candidate),
            start=1,
        ):
            decoded = decode_base64_text(match.group(0))
            if decoded:
                add_result(
                    results,
                    seen,
                    Result("decoded-base64", f"base64_{index}_{match_index}", decoded, printable_score(decoded)),
                )

        for match_index, match in enumerate(
            re.finditer(rb"(?<![0-9A-Fa-f])(?:[0-9A-Fa-f]{2}){16,}(?![0-9A-Fa-f])", candidate),
            start=1,
        ):
            decoded = decode_hex_text(match.group(0))
            if decoded:
                add_result(
                    results,
                    seen,
                    Result("decoded-hex", f"hex_{index}_{match_index}", decoded, printable_score(decoded)),
                )


def carve_embedded_files(data, results, seen):
    for signature, extension in SIGNATURES:
        start = 0
        count = 0
        while True:
            offset = data.find(signature, start)
            if offset < 0:
                break
            start = offset + 1
            if offset == 0:
                continue

            count += 1
            carved = data[offset:]
            note = f"found signature at byte offset {offset}"
            add_result(
                results,
                seen,
                Result("carved-file", f"{extension}_offset_{offset}_{count}", carved, 0.0, extension, note),
            )
            if count >= 10:
                break


def scan_appended_payload(data, results, seen):
    endings = []
    if data.startswith(b"\xff\xd8\xff"):
        endings.append((b"\xff\xd9", "after_jpeg_eoi"))
    if data.startswith(b"\x89PNG\r\n\x1a\n"):
        endings.append((b"IEND\xaeB`\x82", "after_png_iend"))
    if data.startswith((b"GIF87a", b"GIF89a")):
        endings.append((b"\x3b", "after_gif_end"))

    for marker, name in endings:
        offset = data.rfind(marker)
        if offset < 0:
            continue
        payload = data[offset + len(marker):].strip(b"\x00\r\n\t ")
        if len(payload) < 12:
            continue
        if looks_useful_text(payload):
            add_result(results, seen, Result("appended-text", name, payload, printable_score(payload)))
        else:
            add_result(results, seen, Result("appended-binary", name, payload, 0.0, "bin"))


def shannon_entropy(values):
    if len(values) == 0:
        return 0.0
    counts = np.bincount(values.astype(np.uint8).reshape(-1), minlength=256)
    probs = counts[counts > 0] / values.size
    return float(-np.sum(probs * np.log2(probs)))


def bit_balance(bits):
    if bits.size == 0:
        return 0.0
    return float(np.mean(bits))


def transition_rate(bits):
    if bits.size < 2:
        return 0.0
    return float(np.mean(bits[1:] != bits[:-1]))


def analyze_image_statistics(input_path, output_dir, findings, artifacts):
    image = open_image(input_path)
    if image is None:
        return

    arr = np.asarray(image)
    if arr.ndim == 2:
        arr = arr[:, :, np.newaxis]
    channels = arr.shape[2]
    channel_names = ["r", "g", "b", "a"][:channels]
    lines = []
    lines.append(f"Image size: {image.width} x {image.height}")
    lines.append(f"Mode: {image.mode}")
    lines.append("")

    suspicious_lsb = []
    for channel in range(channels):
        values = arr[:, :, channel].astype(np.uint8)
        entropy = shannon_entropy(values)
        lines.append(f"Channel {channel_names[channel]} entropy: {entropy:.3f} bits")
        for bit_plane in range(8):
            bits = ((values.reshape(-1) >> bit_plane) & 1).astype(np.uint8)
            balance = bit_balance(bits)
            transitions = transition_rate(bits)
            lines.append(
                f"  bit {bit_plane}: ones={balance:.3f}, transitions={transitions:.3f}"
            )
            if bit_plane == 0 and 0.47 <= balance <= 0.53 and 0.45 <= transitions <= 0.55:
                suspicious_lsb.append(channel_names[channel])

    if suspicious_lsb:
        findings.append(
            Finding(
                "possible",
                "LSB randomness looks high",
                "The lowest bit plane is close to random in channel(s): "
                + ", ".join(suspicious_lsb)
                + ". This can happen naturally, but it is also common in LSB steganography.",
            )
        )
    else:
        findings.append(
            Finding(
                "low",
                "No strong LSB randomness signal",
                "Basic bit-balance checks did not show a strong simple LSB signal.",
            )
        )

    artifacts.append(write_text_artifact(output_dir, "analysis", "image_statistics", "\n".join(lines)))


def save_bitplane_artifacts(input_path, output_dir, artifacts):
    image = open_image(input_path)
    if image is None:
        return

    arr = np.asarray(image)
    if arr.ndim == 2:
        arr = arr[:, :, np.newaxis]
    channels = arr.shape[2]
    channel_names = ["r", "g", "b", "a"][:channels]

    max_dim = 700
    for channel in range(min(channels, 3)):
        values = arr[:, :, channel].astype(np.uint8)
        bits = ((values & 1) * 255).astype(np.uint8)
        bit_img = Image.fromarray(bits)
        bit_img.thumbnail((max_dim, max_dim))
        path = output_dir / f"artifact_bitplane0_{channel_names[channel]}.png"
        bit_img.save(path)
        artifacts.append(Artifact("visual", f"bitplane0_{channel_names[channel]}", path, "White pixels are LSB=1."))


def parse_png_chunks(data):
    if not data.startswith(b"\x89PNG\r\n\x1a\n"):
        return []
    chunks = []
    offset = 8
    while offset + 8 <= len(data):
        length = int.from_bytes(data[offset:offset + 4], "big")
        chunk_type = data[offset + 4:offset + 8].decode("ascii", errors="replace")
        chunks.append((offset, chunk_type, length))
        offset += 12 + length
        if chunk_type == "IEND" or offset > len(data):
            break
    return chunks


def parse_jpeg_markers(data):
    if not data.startswith(b"\xff\xd8"):
        return []
    names = {
        0xD8: "SOI", 0xD9: "EOI", 0xDA: "SOS", 0xDB: "DQT", 0xC0: "SOF0",
        0xC2: "SOF2", 0xC4: "DHT", 0xDD: "DRI", 0xFE: "COM",
    }
    markers = []
    offset = 0
    while offset < len(data) - 1:
        if data[offset] != 0xFF:
            offset += 1
            continue
        while offset < len(data) and data[offset] == 0xFF:
            offset += 1
        if offset >= len(data):
            break
        marker = data[offset]
        offset += 1
        name = names.get(marker, f"APP{marker - 0xE0}" if 0xE0 <= marker <= 0xEF else f"0xFF{marker:02X}")
        if marker in (0xD8, 0xD9) or 0xD0 <= marker <= 0xD7:
            markers.append((offset - 2, name, 0))
            if marker == 0xD9:
                break
            continue
        if offset + 2 > len(data):
            break
        length = int.from_bytes(data[offset:offset + 2], "big")
        markers.append((offset - 2, name, length))
        if marker == 0xDA:
            eoi = data.find(b"\xff\xd9", offset + length)
            if eoi >= 0:
                markers.append((eoi, "EOI", 0))
            break
        offset += length
    return markers


def analyze_file_structure(data, output_dir, findings, artifacts):
    lines = []
    if data.startswith(b"\x89PNG\r\n\x1a\n"):
        chunks = parse_png_chunks(data)
        lines.append("PNG chunks:")
        for offset, chunk_type, length in chunks:
            lines.append(f"  offset={offset} type={chunk_type} length={length}")
        if chunks and chunks[-1][1] == "IEND":
            end = chunks[-1][0] + chunks[-1][2] + 12
            trailing = len(data) - end
            if trailing > 0:
                findings.append(Finding("possible", "PNG trailing data", f"{trailing} bytes exist after IEND."))
        artifacts.append(write_text_artifact(output_dir, "analysis", "png_structure", "\n".join(lines)))
        return

    if data.startswith(b"\xff\xd8"):
        markers = parse_jpeg_markers(data)
        lines.append("JPEG markers:")
        for offset, name, length in markers:
            lines.append(f"  offset={offset} marker={name} length={length}")
        eoi = data.rfind(b"\xff\xd9")
        if eoi >= 0 and eoi + 2 < len(data):
            findings.append(Finding("possible", "JPEG trailing data", f"{len(data) - eoi - 2} bytes exist after EOI."))
        artifacts.append(write_text_artifact(output_dir, "analysis", "jpeg_structure", "\n".join(lines)))
        return


def run_command(command, timeout=25):
    try:
        completed = subprocess.run(
            command,
            capture_output=True,
            text=True,
            errors="replace",
            timeout=timeout,
            check=False,
        )
    except Exception as exc:
        return f"Could not run {' '.join(command)}: {exc}"

    output = completed.stdout.strip()
    error = completed.stderr.strip()
    if error:
        output = output + ("\n\nSTDERR:\n" if output else "STDERR:\n") + error
    return output or f"No output. Exit code: {completed.returncode}"


def find_tool(*names):
    for name in names:
        path = shutil.which(name)
        if path:
            return path
    local_bins = [
        Path.home() / ".cargo" / "bin",
        Path.home() / ".local" / "bin",
    ]
    suffixes = ["", ".exe"] if sys.platform == "win32" else [""]
    for directory in local_bins:
        for name in names:
            for suffix in suffixes:
                path = directory / f"{name}{suffix}"
                if path.exists():
                    return str(path)
    return None


def check_external_tools(input_path, output_dir, artifacts, findings):
    tools = ["phasm", "phasm-cli", "exiftool", "binwalk", "steghide", "zsteg", "outguess", "foremost", "strings"]
    lines = []
    runnable = {}
    for tool in tools:
        path = shutil.which(tool)
        status = path if path else "not found"
        runnable[tool] = path
        lines.append(f"{tool}: {status}")
    artifacts.append(write_text_artifact(output_dir, "analysis", "external_tools", "\n".join(lines)))

    if input_path.suffix.lower() in (".jpg", ".jpeg") and not any(
        runnable.get(tool) for tool in ("phasm", "phasm-cli", "steghide", "outguess", "binwalk", "exiftool")
    ):
        findings.append(
            Finding(
                "possible",
                "JPEG-specific extraction tools are missing",
                "This file is a JPEG. Messages hidden in JPEG DCT coefficients or with tools like Phasm, steghide, or outguess "
                "usually cannot be recovered by pixel-LSB scanning. Install the Phasm CLI, steghide, outguess, binwalk, or exiftool for deeper JPEG checks.",
            )
        )

    if input_path.suffix.lower() in (".jpg", ".jpeg") and not (runnable.get("phasm") or runnable.get("phasm-cli")):
        findings.append(
            Finding(
                "possible",
                "Phasm CLI is not installed",
                "For images created at phasm.app, install the official CLI with: "
                "powershell -c \"irm https://github.com/cgaffga/phasmcore/releases/latest/download/phasm-cli-installer.ps1 | iex\"",
            )
        )

    commands = []
    if runnable.get("exiftool"):
        commands.append(("exiftool", [runnable["exiftool"], "-a", "-u", "-g1", str(input_path)]))
    if runnable.get("binwalk"):
        commands.append(("binwalk", [runnable["binwalk"], str(input_path)]))
    if runnable.get("steghide"):
        commands.append(("steghide-info", [runnable["steghide"], "info", str(input_path), "-p", ""]))
    if runnable.get("zsteg") and input_path.suffix.lower() in (".png", ".bmp"):
        commands.append(("zsteg", [runnable["zsteg"], str(input_path)]))
    if runnable.get("strings"):
        commands.append(("strings", [runnable["strings"], str(input_path)]))

    for name, command in commands:
        output = run_command(command)
        if len(output) > 50000:
            output = output[:50000] + "\n\n[truncated]"
        artifacts.append(write_text_artifact(output_dir, "external", f"tool_{name}", output))


def image_arrays(image):
    arr = np.asarray(image)
    if arr.ndim == 2:
        arr = arr[:, :, np.newaxis]
    elif arr.ndim == 3:
        arr = arr[:, :, : min(arr.shape[2], 4)]
    else:
        return []

    arrays = [("rows", arr)]
    arrays.append(("cols", np.swapaxes(arr, 0, 1)))
    arrays.append(("rows_reversed", arr[::-1, :, :]))
    arrays.append(("cols_reversed", np.swapaxes(arr, 0, 1)[::-1, :, :]))
    return arrays


def bytes_from_bits(bits, bit_order):
    usable = bits[: (len(bits) // 8) * 8].astype(np.uint8)
    if usable.size == 0:
        return b""
    return np.packbits(usable, bitorder=bit_order).tobytes()


def scan_lsb_bytes(name, bits, results, seen, max_strings=3):
    for bit_order in ("little", "big"):
        data = bytes_from_bits(bits, bit_order)
        strings = extract_ascii_strings(data, min_len=30)
        found = 0
        for index, candidate in enumerate(strings, start=1):
            if not looks_useful_text(candidate) or is_metadata_text(candidate):
                continue
            found += 1
            add_result(
                results,
                seen,
                Result("image-lsb", f"{name}_{bit_order}_{index}", candidate, printable_score(candidate)),
            )
            if found >= max_strings:
                break

        trimmed = trim_text_candidate(data)
        if looks_useful_text(trimmed) and not is_metadata_text(trimmed):
            add_result(
                results,
                seen,
                Result("image-lsb", f"{name}_{bit_order}_trimmed", trimmed, printable_score(trimmed)),
            )


def scan_image_lsb(input_path, results, seen):
    image = open_image(input_path)
    if image is None:
        return

    arr = np.asarray(image)
    channels = arr.shape[2] if arr.ndim == 3 else 1
    channel_names = ["r", "g", "b", "a"][:channels]

    for traversal_name, view in image_arrays(image):
        flat = view.reshape(-1, channels)
        for bit_plane in range(8):
            for channel in range(channels):
                bits = ((flat[:, channel] >> bit_plane) & 1).astype(np.uint8)
                scan_lsb_bytes(
                    f"{traversal_name}_bit{bit_plane}_{channel_names[channel]}",
                    bits,
                    results,
                    seen,
                )

            bits = ((flat[:, :channels].reshape(-1) >> bit_plane) & 1).astype(np.uint8)
            scan_lsb_bytes(f"{traversal_name}_bit{bit_plane}_channels_interleaved", bits, results, seen)

            if channels >= 3:
                bgr = flat[:, [2, 1, 0]].reshape(-1)
                bits = ((bgr >> bit_plane) & 1).astype(np.uint8)
                scan_lsb_bytes(f"{traversal_name}_bit{bit_plane}_bgr_interleaved", bits, results, seen)


def write_report(output_path, input_path, results, metadata, findings=None, artifacts=None, status=None):
    findings = findings or []
    artifacts = artifacts or []
    report = output_path / "scan_report.txt"
    lines = []
    lines.append(f"Input: {input_path}")
    lines.append(f"Hidden-message candidates: {len(results)}")
    lines.append(f"Metadata strings ignored: {len(metadata)}")
    lines.append(f"Analysis artifacts: {len(artifacts)}")
    lines.append("")

    if status:
        lines.append("Final status:")
        lines.append(f"- Readable message found: {'Yes' if status.readable_message_found else 'No'}")
        lines.append(f"- Likely encrypted/protected: {'Yes' if status.likely_encrypted_or_protected else 'No'}")
        lines.append(f"- Tool suspected: {status.suspected_tool}")
        lines.append(f"- Passphrase required: {'Yes' if status.passphrase_required else 'No'}")
        lines.append(f"- Recommendation: {status.recommendation}")
        lines.append("")

    if findings:
        lines.append("Assessment:")
        for finding in findings:
            lines.append(f"- [{finding.level}] {finding.title}: {finding.detail}")
        lines.append("")

    if results:
        lines.append("Candidates:")
        for result in results:
            note = f", {result.note}" if result.note else ""
            lines.append(
                f"- {result.path.name}: {result.kind}, {result.size} bytes, score {result.score:.2f}{note}"
            )
    else:
        lines.append("No readable hidden-message candidates found.")
        lines.append("This does not prove the file is clean.")

    if metadata:
        lines.append("")
        lines.append("Metadata examples:")
        for item in metadata[:10]:
            preview = item.decode("utf-8", errors="ignore").replace("\r", " ").replace("\n", " ")
            lines.append(f"- {preview[:140]}")

    if artifacts:
        lines.append("")
        lines.append("Artifacts:")
        for artifact in artifacts:
            lines.append(f"- {artifact.path.name}: {artifact.kind} {artifact.note}")

    report.write_text("\n".join(lines), encoding="utf-8")
    return report


def confidence_for_result(result):
    if result.kind in ("decoded-base64", "decoded-hex", "appended-text"):
        return "high"
    if result.kind == "carved-file":
        return "high"
    if result.kind == "image-lsb" and result.size >= 40:
        return "medium"
    if result.kind == "text":
        return "possible"
    return "low"


def html_escape(value):
    return html.escape(str(value), quote=True)


def preview_text(data, limit=500):
    text = data[:limit].decode("utf-8", errors="replace")
    return text.replace("\r", "")


def write_html_report(output_path, input_path, results, metadata, findings, artifacts, status=None):
    report = output_path / "scan_report.html"
    cards = []
    if results:
        for result in results:
            rel = result.path.name if result.path else ""
            preview = ""
            if result.extension == "txt":
                preview = f"<pre>{html_escape(preview_text(result.data))}</pre>"
            note = f"<p class='note'>{html_escape(result.note)}</p>" if result.note else ""
            cards.append(
                "<section class='card'>"
                f"<div class='pill {confidence_for_result(result)}'>{confidence_for_result(result)}</div>"
                f"<h3>{html_escape(result.kind)}: {html_escape(result.name)}</h3>"
                f"<p><a href='{html_escape(rel)}'>{html_escape(rel)}</a> | {result.size} bytes | score {result.score:.2f}</p>"
                f"{note}{preview}"
                "</section>"
            )
    else:
        cards.append(
            "<section class='card'>"
            "<div class='pill low'>none</div>"
            "<h3>No readable hidden-message candidates found</h3>"
            "<p>This does not prove the file is clean. It may use encryption, compression, password protection, or a custom method.</p>"
            "</section>"
        )

    finding_html = []
    for finding in findings:
        finding_html.append(
            "<li>"
            f"<span class='pill {html_escape(finding.level)}'>{html_escape(finding.level)}</span> "
            f"<strong>{html_escape(finding.title)}</strong><br>{html_escape(finding.detail)}"
            "</li>"
        )

    artifact_html = []
    for artifact in artifacts:
        rel = artifact.path.name
        if artifact.path.suffix.lower() in (".png", ".jpg", ".jpeg"):
            artifact_html.append(
                "<section class='artifact'>"
                f"<h3>{html_escape(artifact.name)}</h3>"
                f"<a href='{html_escape(rel)}'><img src='{html_escape(rel)}' alt='{html_escape(artifact.name)}'></a>"
                f"<p>{html_escape(artifact.note)}</p>"
                "</section>"
            )
        else:
            artifact_html.append(
                "<li>"
                f"<a href='{html_escape(rel)}'>{html_escape(artifact.name)}</a> "
                f"({html_escape(artifact.kind)}) {html_escape(artifact.note)}"
                "</li>"
            )

    metadata_html = []
    for item in metadata[:20]:
        metadata_html.append(f"<li><code>{html_escape(preview_text(item, 180))}</code></li>")

    html_doc = f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <title>Hidden Message Scan Report</title>
  <style>
    body {{ margin: 0; font-family: Segoe UI, Arial, sans-serif; background: #f5f6f8; color: #20242a; }}
    header {{ background: #1f2937; color: white; padding: 24px 32px; }}
    main {{ padding: 24px 32px; max-width: 1180px; margin: 0 auto; }}
    h1, h2, h3 {{ margin-top: 0; }}
    .grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(240px, 1fr)); gap: 16px; }}
    .stat, .card, .artifact {{ background: white; border: 1px solid #d8dde6; border-radius: 8px; padding: 16px; box-shadow: 0 1px 2px rgba(0,0,0,.04); }}
    .pill {{ display: inline-block; padding: 3px 8px; border-radius: 999px; font-size: 12px; font-weight: 700; text-transform: uppercase; }}
    .high {{ background: #dcfce7; color: #166534; }}
    .medium, .possible {{ background: #fef3c7; color: #92400e; }}
    .low, .none {{ background: #e5e7eb; color: #374151; }}
    pre {{ white-space: pre-wrap; background: #111827; color: #f9fafb; padding: 12px; border-radius: 6px; max-height: 260px; overflow: auto; }}
    code {{ background: #eef2f7; padding: 2px 4px; border-radius: 4px; }}
    img {{ max-width: 100%; image-rendering: pixelated; border: 1px solid #d8dde6; }}
    a {{ color: #0f5bb5; }}
    li {{ margin-bottom: 10px; }}
  </style>
</head>
<body>
<header>
  <h1>Hidden Message Scan Report</h1>
  <p>{html_escape(input_path)}</p>
</header>
<main>
  <section class="grid">
    <div class="stat"><h2>{len(results)}</h2><p>candidate files</p></div>
    <div class="stat"><h2>{len(metadata)}</h2><p>metadata strings ignored</p></div>
    <div class="stat"><h2>{len(artifacts)}</h2><p>analysis artifacts</p></div>
  </section>

  <h2>Final Status</h2>
  <section class="card">
    <p><strong>Readable message found:</strong> {html_escape('Yes' if status and status.readable_message_found else 'No')}</p>
    <p><strong>Likely encrypted/protected:</strong> {html_escape('Yes' if status and status.likely_encrypted_or_protected else 'No')}</p>
    <p><strong>Tool suspected:</strong> {html_escape(status.suspected_tool if status else 'Unknown')}</p>
    <p><strong>Passphrase required:</strong> {html_escape('Yes' if status and status.passphrase_required else 'No')}</p>
    <p><strong>Recommendation:</strong> {html_escape(status.recommendation if status else 'Review the generated report.')}</p>
  </section>

  <h2>Assessment</h2>
  <ul>{''.join(finding_html) if finding_html else '<li>No extra findings.</li>'}</ul>

  <h2>Candidates</h2>
  {''.join(cards)}

  <h2>Visual And Analysis Artifacts</h2>
  <div class="grid">{''.join(item for item in artifact_html if item.startswith('<section'))}</div>
  <ul>{''.join(item for item in artifact_html if item.startswith('<li>'))}</ul>

  <h2>Metadata Ignored</h2>
  <ul>{''.join(metadata_html) if metadata_html else '<li>No metadata strings were filtered.</li>'}</ul>
</main>
</body>
</html>
"""
    report.write_text(html_doc, encoding="utf-8")
    return report


def verify_expected_text(data, results, expected_text, findings):
    if not expected_text:
        return
    expected = expected_text.encode("utf-8")
    expected_lower = expected_text.lower()

    locations = []
    if expected in data:
        locations.append("raw file bytes")
    try:
        encoded = base64.b64encode(expected)
        if encoded in data:
            locations.append("raw base64 text")
    except Exception:
        pass

    for result in results:
        text = result.data.decode("utf-8", errors="ignore").lower()
        if expected_lower in text:
            locations.append(result.path.name if result.path else result.name)

    if locations:
        findings.append(
            Finding(
                "high",
                "Expected text found",
                "The known text was found in: " + ", ".join(locations),
            )
        )
    else:
        findings.append(
            Finding(
                "low",
                "Expected text was not found",
                "The known message was not found in raw bytes, base64, or recovered candidates. "
                "That suggests an unsupported stego method, encryption/compression, or JPEG recompression damage.",
            )
        )


def decode_with_phasm(input_path, output_path, passphrase, results, seen, findings, artifacts):
    if not passphrase:
        return

    phasm = find_tool("phasm", "phasm-cli")
    if not phasm:
        findings.append(
            Finding(
                "possible",
                "Phasm decode skipped",
                "A passphrase was provided, but the Phasm CLI was not found. Install it with: "
                "powershell -c \"irm https://github.com/cgaffga/phasmcore/releases/latest/download/phasm-cli-installer.ps1 | iex\"",
            )
        )
        return

    extract_dir = output_path / "phasm_attachments"
    extract_dir.mkdir(parents=True, exist_ok=True)
    command = [phasm, "decode", str(input_path), "-p", passphrase, "--extract", str(extract_dir), "--quiet"]
    try:
        completed = subprocess.run(
            command,
            capture_output=True,
            text=True,
            errors="replace",
            timeout=180,
            check=False,
        )
    except Exception as exc:
        findings.append(Finding("low", "Phasm decode failed to run", str(exc)))
        return

    output = (completed.stdout or "").strip()
    error = (completed.stderr or "").strip()
    safe_command = [phasm, "decode", str(input_path), "-p", "<redacted>", "--extract", str(extract_dir), "--quiet"]
    log = "Command: " + " ".join(safe_command) + "\n"
    log += f"Exit code: {completed.returncode}\n\nSTDOUT:\n{output}\n\nSTDERR:\n{error}\n"
    artifacts.append(write_text_artifact(output_path, "external", "tool_phasm_decode", log))

    if completed.returncode != 0:
        findings.append(
            Finding(
                "low",
                "Phasm decode did not recover a message",
                error or output or "The passphrase may be wrong, the file may not be a Phasm image, or the image may have been recompressed.",
            )
        )
        return

    message = output.encode("utf-8")
    if message:
        add_result(
            results,
            seen,
            Result("phasm-message", "decoded_message", message, 1.0, "txt", "Decoded by the official Phasm CLI."),
        )
        findings.append(Finding("high", "Phasm message decoded", "The official Phasm CLI recovered a message."))

    for attachment in extract_dir.glob("*"):
        if attachment.is_file():
            data = attachment.read_bytes()
            extension = attachment.suffix[1:] if attachment.suffix else "bin"
            add_result(
                results,
                seen,
                Result("phasm-attachment", attachment.stem, data, 1.0, extension, "Attachment extracted by Phasm CLI."),
            )


def try_phasm_passphrase(phasm, input_path, output_path, passphrase):
    extract_dir = output_path / "phasm_attachments"
    extract_dir.mkdir(parents=True, exist_ok=True)
    command = [phasm, "decode", str(input_path), "-p", passphrase, "--extract", str(extract_dir), "--quiet"]
    completed = subprocess.run(
        command,
        capture_output=True,
        text=True,
        errors="replace",
        timeout=180,
        check=False,
    )
    return completed.returncode, (completed.stdout or "").strip(), (completed.stderr or "").strip(), extract_dir


def add_phasm_output(output, extract_dir, results, seen, findings):
    message = output.encode("utf-8")
    if message:
        add_result(
            results,
            seen,
            Result("phasm-message", "decoded_message", message, 1.0, "txt", "Decoded by the official Phasm CLI."),
        )
        findings.append(Finding("high", "Phasm message decoded", "The official Phasm CLI recovered a message."))

    for attachment in extract_dir.glob("*"):
        if attachment.is_file():
            data = attachment.read_bytes()
            extension = attachment.suffix[1:] if attachment.suffix else "bin"
            add_result(
                results,
                seen,
                Result("phasm-attachment", attachment.stem, data, 1.0, extension, "Attachment extracted by Phasm CLI."),
            )


def decode_with_phasm_wordlist(input_path, output_path, wordlist_path, results, seen, findings, artifacts, limit=500):
    if not wordlist_path:
        return False

    path = Path(wordlist_path)
    if not path.exists():
        findings.append(Finding("low", "Wordlist not found", str(path)))
        return False

    phasm = find_tool("phasm", "phasm-cli")
    if not phasm:
        findings.append(Finding("possible", "Wordlist skipped", "Phasm CLI is not installed."))
        return False

    attempts = 0
    log_lines = [f"Wordlist: {path}", f"Limit: {limit}", "Passphrases are not written to this log."]
    with path.open("r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            candidate = line.strip()
            if not candidate:
                continue
            attempts += 1
            try:
                returncode, output, error, extract_dir = try_phasm_passphrase(phasm, input_path, output_path, candidate)
            except Exception as exc:
                log_lines.append(f"Attempt {attempts}: error {exc}")
                continue

            if returncode == 0:
                log_lines.append(f"Success on attempt {attempts}.")
                artifacts.append(write_text_artifact(output_path, "external", "tool_phasm_wordlist", "\n".join(log_lines)))
                add_phasm_output(output, extract_dir, results, seen, findings)
                findings.append(Finding("high", "Wordlist passphrase matched", f"Phasm decoded successfully on attempt {attempts}."))
                return True

            if attempts >= limit:
                break

    log_lines.append(f"Tried {attempts} passphrase(s). No match.")
    artifacts.append(write_text_artifact(output_path, "external", "tool_phasm_wordlist", "\n".join(log_lines)))
    findings.append(Finding("low", "Wordlist did not recover message", f"Tried {attempts} passphrase(s)."))
    return False


def passphrase_variants(seed):
    seed = seed.strip()
    if not seed:
        return []
    bases = []
    compact = re.sub(r"\s+", "", seed)
    slug = re.sub(r"[^A-Za-z0-9]+", "", seed)
    for value in (seed, compact, slug, seed.lower(), compact.lower(), slug.lower(), seed.title(), compact.title()):
        if value and value not in bases:
            bases.append(value)

    variants = []
    suffixes = ["", "1", "12", "123", "1234", "2024", "2025", "2026", "!", "@123", "#123"]
    for base in bases:
        for suffix in suffixes:
            value = base + suffix
            if value and value not in variants:
                variants.append(value)
    return variants


def generate_passphrase_guesses(input_path, expected_text=None, extra_seeds=None, limit=30):
    guesses = []
    if limit <= 0:
        return guesses

    def add(value):
        if value and value not in guesses:
            guesses.append(value)

    for value in COMMON_PASSPHRASES:
        add(value)
        if len(guesses) >= limit:
            return guesses

    seeds = [
        input_path.stem,
        input_path.parent.name,
        input_path.parent.parent.name if input_path.parent.parent else "",
    ]
    if expected_text:
        words = re.findall(r"[A-Za-z0-9]{3,}", expected_text)
        seeds.extend(words[:20])
        seeds.append(expected_text)
    if extra_seeds:
        seeds.extend(extra_seeds)

    for seed in seeds:
        for value in passphrase_variants(str(seed)):
            add(value)
            if len(guesses) >= limit:
                return guesses

    return guesses[:limit]


def decode_with_phasm_guesses(input_path, output_path, guesses, results, seen, findings, artifacts):
    if not guesses:
        return False

    phasm = find_tool("phasm", "phasm-cli")
    if not phasm:
        findings.append(Finding("possible", "Mandatory passphrase guessing skipped", "Phasm CLI is not installed."))
        return False

    log_lines = [
        f"Generated guesses: {len(guesses)}",
        "Passphrases are not written to this log.",
    ]
    for attempt, candidate in enumerate(guesses, start=1):
        try:
            returncode, output, error, extract_dir = try_phasm_passphrase(phasm, input_path, output_path, candidate)
        except Exception as exc:
            log_lines.append(f"Attempt {attempt}: error {exc}")
            continue

        if returncode == 0:
            log_lines.append(f"Success on generated guess attempt {attempt}.")
            artifacts.append(write_text_artifact(output_path, "external", "tool_phasm_guesses", "\n".join(log_lines)))
            add_phasm_output(output, extract_dir, results, seen, findings)
            findings.append(Finding("high", "Generated passphrase guess matched", f"Phasm decoded successfully on generated guess attempt {attempt}."))
            return True

    log_lines.append(f"Tried {len(guesses)} generated passphrase guess(es). No match.")
    artifacts.append(write_text_artifact(output_path, "external", "tool_phasm_guesses", "\n".join(log_lines)))
    findings.append(Finding("low", "Generated passphrase guesses did not recover message", f"Tried {len(guesses)} generated guess(es)."))
    return False


def build_status(input_path, results, findings, passphrase=None, wordlist_path=None):
    status = Status()
    status.readable_message_found = any(is_readable_result(result) for result in results)

    finding_text = " ".join((finding.title + " " + finding.detail).lower() for finding in findings)
    is_jpeg = input_path.suffix.lower() in (".jpg", ".jpeg")
    phasm_related = "phasm" in finding_text or bool(passphrase) or bool(wordlist_path)

    if phasm_related:
        status.suspected_tool = "Phasm / JPEG stego"
        status.passphrase_required = not status.readable_message_found
        status.likely_encrypted_or_protected = not status.readable_message_found
    elif is_jpeg and not status.readable_message_found:
        status.suspected_tool = "Phasm / JPEG stego or clean JPEG"
        status.passphrase_required = True
        status.likely_encrypted_or_protected = True
    elif status.readable_message_found:
        status.suspected_tool = "Simple/no-password stego"
        status.passphrase_required = False
        status.likely_encrypted_or_protected = False

    if status.readable_message_found:
        status.recommendation = "Open the candidate files listed below."
    elif status.passphrase_required:
        status.recommendation = "A passphrase is required. Provide --passphrase or try --wordlist with likely passwords."
    elif status.likely_encrypted_or_protected:
        status.recommendation = "Use a matching decoder/tool or a passphrase/wordlist if available."
    else:
        status.recommendation = "No readable message was found with supported no-password methods."
    return status


def scan(
    input_file,
    output_dir,
    expected_text=None,
    passphrase=None,
    wordlist_path=None,
    wordlist_limit=500,
    guess_seeds=None,
    guess_limit=30,
):
    input_path = Path(input_file)
    output_path = Path(output_dir)

    if not input_path.exists():
        print("File not found:", input_path)
        sys.exit(1)

    clean_previous_outputs(output_path)
    data = input_path.read_bytes()
    results = []
    metadata = []
    findings = []
    artifacts = []
    seen = set()

    analyze_file_structure(data, output_path, findings, artifacts)
    analyze_image_statistics(input_path, output_path, findings, artifacts)
    save_bitplane_artifacts(input_path, output_path, artifacts)
    check_external_tools(input_path, output_path, artifacts, findings)

    scan_file_strings(data, results, metadata, seen)
    scan_encoded_text(data, results, seen)
    carve_embedded_files(data, results, seen)
    scan_appended_payload(data, results, seen)
    scan_image_lsb(input_path, results, seen)
    decode_with_phasm(input_path, output_path, passphrase, results, seen, findings, artifacts)
    if not any(result.kind == "phasm-message" for result in results):
        decode_with_phasm_wordlist(
            input_path,
            output_path,
            wordlist_path,
            results,
            seen,
            findings,
            artifacts,
            wordlist_limit,
        )
    if input_path.suffix.lower() in (".jpg", ".jpeg") and not any(result.kind == "phasm-message" for result in results):
        guesses = generate_passphrase_guesses(input_path, expected_text, guess_seeds, guess_limit)
        decode_with_phasm_guesses(input_path, output_path, guesses, results, seen, findings, artifacts)

    results.sort(key=lambda item: (item.score, item.size), reverse=True)
    for index, result in enumerate(results, start=1):
        write_result(output_path, result, index)

    verify_expected_text(data, results, expected_text, findings)
    status = build_status(input_path, results, findings, passphrase, wordlist_path)

    report = write_report(output_path, input_path, results, metadata, findings, artifacts, status)
    html_report = write_html_report(output_path, input_path, results, metadata, findings, artifacts, status)
    scan_summary = {
        "input_path": str(input_path),
        "output_dir": str(output_path),
        "report_path": str(report),
        "html_report_path": str(html_report),
        "candidate_count": len(results),
        "metadata_ignored_count": len(metadata),
        "artifact_count": len(artifacts),
        "readable_message_found": bool(status.readable_message_found),
        "likely_encrypted_or_protected": bool(status.likely_encrypted_or_protected),
        "suspected_tool": status.suspected_tool,
        "passphrase_required": bool(status.passphrase_required),
        "recommendation": status.recommendation,
        "candidates": [
            {
                "kind": result.kind,
                "name": result.name,
                "size": result.size,
                "score": float(result.score),
                "extension": result.extension,
                "note": result.note,
                "path": str(result.path) if result.path else None,
                "file_name": result.path.name if result.path else None,
            }
            for result in results[:20]
        ],
        "findings": [
            {
                "level": finding.level,
                "title": finding.title,
                "detail": finding.detail,
            }
            for finding in findings
        ],
        "artifacts": [
            {
                "kind": artifact.kind,
                "name": artifact.name,
                "path": str(artifact.path),
                "file_name": artifact.path.name,
                "note": artifact.note,
            }
            for artifact in artifacts
        ],
    }

    if not results:
        print("No readable hidden-message candidates found.")
        print("This does not prove the file is clean. It may use encryption, compression, or another stego method.")
        print(f"Final status: readable={'yes' if status.readable_message_found else 'no'}, protected={'yes' if status.likely_encrypted_or_protected else 'no'}, passphrase_required={'yes' if status.passphrase_required else 'no'}")
        print(f"Report: {report}")
        print(f"HTML report: {html_report}")
        return scan_summary

    print("Possible hidden-message candidates:")
    for result in results[:20]:
        print(f"  {result.path} ({result.kind}, {result.size} bytes, score {result.score:.2f})")
    print(f"Report: {report}")
    print(f"HTML report: {html_report}")
    return scan_summary


def main():
    if len(sys.argv) < 2 or sys.argv[1] in {"-h", "--help", "help"}:
        help_and_exit()

    args = sys.argv[1:]
    expected_text = None
    passphrase = None
    wordlist_path = None
    wordlist_limit = 500
    guess_seeds = []
    guess_limit = 30
    if "--expected" in args:
        idx = args.index("--expected")
        if idx + 1 >= len(args):
            print("Missing value after --expected")
            sys.exit(1)
        expected_text = args[idx + 1]
        del args[idx:idx + 2]
    if "--passphrase" in args:
        idx = args.index("--passphrase")
        if idx + 1 >= len(args):
            print("Missing value after --passphrase")
            sys.exit(1)
        passphrase = args[idx + 1]
        del args[idx:idx + 2]
    if "-p" in args:
        idx = args.index("-p")
        if idx + 1 >= len(args):
            print("Missing value after -p")
            sys.exit(1)
        passphrase = args[idx + 1]
        del args[idx:idx + 2]
    if "--wordlist" in args:
        idx = args.index("--wordlist")
        if idx + 1 >= len(args):
            print("Missing value after --wordlist")
            sys.exit(1)
        wordlist_path = args[idx + 1]
        del args[idx:idx + 2]
    if "--wordlist-limit" in args:
        idx = args.index("--wordlist-limit")
        if idx + 1 >= len(args):
            print("Missing value after --wordlist-limit")
            sys.exit(1)
        try:
            wordlist_limit = int(args[idx + 1])
        except ValueError:
            print("--wordlist-limit must be a number")
            sys.exit(1)
        del args[idx:idx + 2]
    while "--guess-seed" in args:
        idx = args.index("--guess-seed")
        if idx + 1 >= len(args):
            print("Missing value after --guess-seed")
            sys.exit(1)
        guess_seeds.append(args[idx + 1])
        del args[idx:idx + 2]
    if "--guess-limit" in args:
        idx = args.index("--guess-limit")
        if idx + 1 >= len(args):
            print("Missing value after --guess-limit")
            sys.exit(1)
        try:
            guess_limit = int(args[idx + 1])
        except ValueError:
            print("--guess-limit must be a number")
            sys.exit(1)
        del args[idx:idx + 2]

    if args[0] == "scan":
        if len(args) < 2:
            help_and_exit()
        input_file = args[1]
        output_dir = args[2] if len(args) >= 3 else "extracted"
    else:
        input_file = args[0]
        output_dir = args[1] if len(args) >= 2 else "extracted"

    scan(input_file, output_dir, expected_text, passphrase, wordlist_path, wordlist_limit, guess_seeds, guess_limit)


if __name__ == "__main__":
    main()
