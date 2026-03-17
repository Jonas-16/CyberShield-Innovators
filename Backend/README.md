# Backend (FastAPI) - Sandbox Upload

This API receives files from your frontend scan page and writes them to `C:\Sandbox_Staging`.
Your `sandbox_monitor.py` watches that folder, so this queues files into sandbox processing.

## Run

```powershell
cd Backend
pip install -r requirements.txt
uvicorn app.main:app --reload --host 127.0.0.1 --port 8000
```

## Endpoints

- `GET /api/health`
- `GET /api/scan/ml-status`
- `POST /api/scan/upload`
  - `multipart/form-data`
  - field name: `file`
- `GET /api/scan/results/{file_name}`
- `GET /api/scan/files/{file_name}`
- `DELETE /api/scan/files/{file_name}`

## Frontend config

Set optional Vite env variable in `Frontend/.env`:

```env
VITE_BACKEND_URL=http://127.0.0.1:8000
```

## Scanner Notes

- Upload now triggers backend scanning and stores a result payload in memory.
- If ML dependencies (`torch`, `ember`) are unavailable, scanner falls back to a heuristic engine and returns a warning in `scan_result.scanner_warning`.

## ML Setup (Windows, pinned)

Recommended:
- Use a dedicated virtual environment.
- Use Python 3.11 (64-bit) for highest compatibility with binary packages.

### Option 1: one-command setup script

```powershell
cd Backend
powershell -ExecutionPolicy Bypass -File .\scripts\setup_ml_windows.ps1
```

### Option 2: manual setup

```powershell
cd Backend
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
