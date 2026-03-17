from __future__ import annotations

import os
from pathlib import Path
from uuid import uuid4

from fastapi import FastAPI, File, HTTPException, UploadFile
from fastapi.middleware.cors import CORSMiddleware

STAGING_DIR = Path(os.environ.get("SANDBOX_STAGING_DIR", r"C:\\Sandbox_Staging"))
MAX_FILE_SIZE_BYTES = 1024 * 1024 * 1024  # 1 GB

app = FastAPI(title="Sandbox Upload API", version="1.0.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


def ensure_staging_dir() -> None:
    STAGING_DIR.mkdir(parents=True, exist_ok=True)


def safe_unique_path(original_name: str) -> Path:
    file_name = Path(original_name).name or "upload.bin"
    target = STAGING_DIR / file_name
    if not target.exists():
        return target

    stem = Path(file_name).stem
    suffix = Path(file_name).suffix
    return STAGING_DIR / f"{stem}_{uuid4().hex[:8]}{suffix}"


@app.on_event("startup")
def on_startup() -> None:
    ensure_staging_dir()


@app.get("/api/health")
def health() -> dict[str, str]:
    return {"status": "ok"}


@app.post("/api/scan/upload")
async def upload_to_sandbox(file: UploadFile = File(...)) -> dict[str, str | int]:
    ensure_staging_dir()

    if not file.filename:
        raise HTTPException(status_code=400, detail="Missing filename")

    target_path = safe_unique_path(file.filename)
    total = 0

    try:
        with target_path.open("wb") as out:
            while True:
                chunk = await file.read(1024 * 1024)
                if not chunk:
                    break
                total += len(chunk)
                if total > MAX_FILE_SIZE_BYTES:
                    raise HTTPException(status_code=413, detail="File too large")
                out.write(chunk)
    except HTTPException:
        if target_path.exists():
            target_path.unlink(missing_ok=True)
        raise
    except Exception as exc:
        if target_path.exists():
            target_path.unlink(missing_ok=True)
        raise HTTPException(status_code=500, detail=f"Upload failed: {exc}")
    finally:
        await file.close()

    return {
        "status": "queued",
        "file_name": target_path.name,
        "staging_path": str(target_path),
        "size_bytes": total,
    }
