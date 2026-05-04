# CyberShield Innovators

CyberShield Innovators is a malware and steganography scanning system built around a two-laptop demo flow:

- `user/Frontend/`: React + Vite client UI used on Laptop 1
- `cloud/Backend/`: FastAPI API and scan worker used on Laptop 2
- `cloud/sandbox/`: optional Windows Sandbox monitor for local Windows Sandbox review sessions

## What It Does

- Uploads a file from Laptop 1 to Laptop 2
- Scans image files with the steganography scanner
- Scans `.exe` files with the zero-day / malware scanner
- Tracks each remote scan as a scan job with a `scan_id`
- Records scan events in `cloud/Backend/app/reports/scan_events.jsonl`

## Supported File Routing

- Images: `.jpg`, `.jpeg`, `.png`, `.bmp`, `.tif`, `.tiff`, `.webp`
  - Routed to `cloud/Backend/app/stg_scanner.py`
- Executables: `.exe`
  - Routed to `cloud/Backend/app/zd_scanner.py`
- Everything else
  - Ignored

The stable top-level router used by the app is:

```text
cloud/Backend/app/scanner.py
```

## Main Paths

- Project root: `path/to/your/CyberShield-Innovators`
- User app: `path/to/your/CyberShield-Innovators/user/Frontend`
- Cloud backend: `path/to/your/CyberShield-Innovators/cloud/Backend`
- Cloud sandbox tools: `path/to/your/CyberShield-Innovators/cloud/sandbox`
- Scan event log: `cloud/Backend/app/reports/scan_events.jsonl`
## Two-Laptop Demo Setup

### Laptop 2: backend + scanning worker

```powershell
cd cloud/Backend
pip install -r requirements.txt
uvicorn app.main:app --host 0.0.0.0 --port 8000
```

Find Laptop 2's LAN IP address and use that in the frontend config on Laptop 1.

### Laptop 1: frontend client

Create `user/Frontend/.env`:

```env
VITE_BACKEND_URL=http://<LAPTOP_2_IP>:8000
```

Then run:

```powershell
cd user/Frontend
npm install
npm run dev -- --host 0.0.0.0 --port 5174
```

The client on Laptop 1 uploads files to Laptop 2, polls job status, and displays the final report.

## Optional Windows Sandbox Flow

If you still want the original local Windows Sandbox monitor flow for experiments, you can start it from the `cloud/sandbox/` folder. It is no longer required for the main two-laptop demo architecture.

## Core API Endpoints

- `GET /api/health`
- `GET /api/scan/ml-status`
- `GET /api/scan/config`
- `POST /api/scan/upload`
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

## Frontend Pages

- `Dashboard`
  - last scan, files scanned, threats blocked, current activity
- `Scan Page`
  - manual upload flow and scan details
- `Result Page`
  - current result, risk summary, save/delete actions
- `Logs Page`
  - recent scan history for both image and `.exe` results

## Current Behavior Notes

- `POST /api/scan/upload` creates a remote scan job and returns a `scan_id`
- `GET /api/scan/jobs/{scan_id}` returns queued, processing, completed, or failed status
- `GET /api/scan/jobs/{scan_id}/report` returns a client-friendly report payload
- `/api/scan/latest` returns the most recent scan job in the current backend session
- Image results are normalized so `Stego` predictions map to `Suspicious`
- The `.exe` scanner caches its model stack after startup to reduce repeated initialization overhead
- The backend can still support Windows Sandbox review sessions when the optional monitor is used

## Scanner Files

- Stable router: `cloud/Backend/app/scanner.py`
- Image scanner export: `cloud/Backend/app/stg_scanner.py`
- Executable scanner export: `cloud/Backend/app/zd_scanner.py`
- Refactor package work-in-progress: `cloud/Backend/app/scanners/`

## Development Notes

- The scanner package under `cloud/Backend/app/scanners/` exists for cleanup and maintainability work
- The running app should continue to route through `cloud/Backend/app/scanner.py`
- If the frontend looks stale after backend/frontend restarts, refresh the browser once
