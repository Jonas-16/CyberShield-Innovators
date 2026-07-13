# Backend (FastAPI) - Cloud Scanner API

This API is the backend/cloud side of CyberShield Innovators. The frontend can run on a user
laptop and upload files here over HTTP. The backend stores each upload, runs the scanner, records
the result, and exposes it back to the frontend.

By default, uploaded files are stored in:

```text
cloud/backend/app/uploads
```

You can override that with:

```powershell
$env:CLOUD_UPLOAD_DIR="D:\CyberShieldUploads"
```

## Run

```powershell
cd cloud\backend
pip install -r requirements.txt
uvicorn app.main:app --reload --host 0.0.0.0 --port 8000
```

Use `127.0.0.1` instead of `0.0.0.0` if frontend and backend are on the same laptop.

## Endpoints

- `GET /api/health`
- `GET /api/scan/ml-status`
- `GET /api/scan/config`
- `POST /api/scan/upload`
  - `multipart/form-data`
  - field name: `file`
- `GET /api/scan/latest`
- `GET /api/scan/logs`
- `GET /api/scan/results/{file_name}`
- `GET /api/scan/reports/{report_id}/{asset_name}`
- `GET /api/scan/files/{file_name}`
- `DELETE /api/scan/files/{file_name}`

## Frontend config

Set the Vite env variable in `user/Frontend/.env`.

Same laptop:

```env
VITE_BACKEND_URL=http://127.0.0.1:8000
```

Two-laptop demo:

```env
VITE_BACKEND_URL=http://BACKEND_LAPTOP_IP:8000
```

## Scanner Notes

- Upload triggers backend scanning and stores a result payload in memory.
- Image scans also create a cleaned PNG with metadata stripped, the image re-encoded, and
  RGB least-significant bits cleared to remove common embedded payloads. The hidden-message
  decoder still runs, but decoded data is secondary and shown only when requested. Reports are saved under
  `cloud/Decoder/reports` and exposed through the report endpoint above.
- `POST /api/scan/upload` returns a queued/processing result immediately while scanning runs in the background.
- The frontend polls `GET /api/scan/results/{file_name}` and `GET /api/scan/latest`.
- If ML dependencies (`torch`, `ember`) are unavailable, scanner falls back to a heuristic engine and returns a warning in `scan_result.scanner_warning`.

## ML Setup (Windows, pinned)

Recommended:
- Use a dedicated virtual environment.
- Use Python 3.11 (64-bit) for highest compatibility with binary packages.

### Option 1: one-command setup script

```powershell
cd cloud\backend
powershell -ExecutionPolicy Bypass -File .\scripts\setup_ml_windows.ps1
```

### Option 2: manual setup

```powershell
cd cloud\backend
python -m venv .venv-ml
.\.venv-ml\Scripts\Activate.ps1
python -m pip install --upgrade pip
pip install -r requirements.txt
pip install -r requirements-ml.txt
```

### Verify ML readiness

Start API:

```powershell
cd cloud\backend
uvicorn app.main:app --reload --host 127.0.0.1 --port 8000
```

Check:
- `http://127.0.0.1:8000/api/scan/ml-status`

`ready: true` means model files and ML libraries are all available.
