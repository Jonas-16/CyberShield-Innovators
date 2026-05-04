# Backend (FastAPI) - CyberShield Innovators

This FastAPI backend handles:

- remote file uploads
- scan job creation and polling
- scanner routing
- latest-result lookup
- scan history retrieval
- optional file approve / reject / delete flows for sandbox sessions

Manual uploads are stored in:

```text
path/to/your/manual-upload-directory
```

Scan history is written to:

```text
cloud/Backend/app/reports/scan_events.jsonl
```

## Run

```powershell
cd cloud/Backend
pip install -r requirements.txt
uvicorn app.main:app --reload --host 127.0.0.1 --port 8000
```

## Endpoints

- `GET /api/health`
- `GET /api/scan/ml-status`
- `GET /api/scan/config`
- `POST /api/scan/upload`
  - `multipart/form-data`
  - field name: `file`
- `GET /api/scan/jobs/{scan_id}`
- `GET /api/scan/jobs/{scan_id}/report`
- `GET /api/scan/results/{file_name}`
- `GET /api/scan/logs`
- `GET /api/scan/latest`
- `DELETE /api/scan/jobs/{scan_id}`
- `GET /api/scan/files/{file_name}`
- `POST /api/scan/files/{file_name}/approve`
- `POST /api/scan/files/{file_name}/reject`
- `DELETE /api/scan/files/{file_name}`

## Supported File Types

- Images: `.jpg`, `.jpeg`, `.png`, `.bmp`, `.tif`, `.tiff`, `.webp`
- Executables: `.exe`
- Unsupported file types are ignored

Routing is handled by:

```text
cloud/Backend/app/scanner.py
```

Scanner entry points:

- `cloud/Backend/app/stg_scanner.py`
- `cloud/Backend/app/zd_scanner.py`

## Frontend config

Set optional Vite env variable in `user/Frontend/.env`:

```env
VITE_BACKEND_URL=http://<LAPTOP_2_IP>:8000
```

## Scanner Notes

- Remote uploads are scanned in the background and tracked by `scan_id`.
- `/api/scan/jobs/{scan_id}` is the primary polling endpoint for the frontend.
- `/api/scan/latest` returns the newest active scan job or latest session scan.
- Image results are normalized so stego detections do not appear as `Safe`.
- If `.exe` ML dependencies are unavailable, the scanner falls back to a heuristic engine and returns a warning in `scan_result.scanner_warning`.
- The `.exe` stack is pre-warmed on startup and cached to reduce repeated initialization overhead.

## ML Setup (Windows, pinned)

Recommended:

- Use a dedicated virtual environment.
- Use Python 3.11 (64-bit) for highest compatibility with binary packages.

### Option 1: one-command setup script

```powershell
cd cloud/Backend
powershell -ExecutionPolicy Bypass -File .\scripts\setup_ml_windows.ps1
```

### Option 2: manual setup

```powershell
cd cloud/Backend
python -m venv .venv-ml
.\.venv-ml\Scripts\Activate.ps1
python -m pip install --upgrade pip
pip install -r requirements.txt
pip install -r requirements-ml.txt
```

### Verify ML readiness

Start API:

```powershell
uvicorn app.main:app --reload --host 127.0.0.1 --port 8000
```

Check:

- `http://127.0.0.1:8000/api/scan/ml-status`

`ready: true` means model files and ML libraries are all available.
