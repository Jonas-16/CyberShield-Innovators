# CyberShield Innovators

CyberShield Innovators is a malware and steganography scanning system with three connected parts:

- `Backend/`: FastAPI API for uploads, scanner routing, result lookup, and scan history
- `Frontend/`: React + Vite UI with Dashboard, Scan, Result, and Logs pages
- `sandbox/`: Windows Sandbox monitor that intercepts supported downloads from your configured download watch folder

## What It Does

- Scans uploaded and downloaded image files with the steganography scanner
- Scans uploaded and downloaded `.exe` files with the zero-day / malware scanner
- Ignores unsupported file types
- Sends intercepted downloads into a Windows Sandbox review session
- Records scan events in `Backend/app/reports/scan_events.jsonl`

## Supported File Routing

- Images: `.jpg`, `.jpeg`, `.png`, `.bmp`, `.tif`, `.tiff`, `.webp`
  - Routed to `Backend/app/stg_scanner.py`
- Executables: `.exe`
  - Routed to `Backend/app/zd_scanner.py`
- Everything else
  - Ignored

The stable top-level router used by the app is:

```text
Backend/app/scanner.py
```

## Main Paths

- Project root: `path/to/your/CyberShield-Innovators`
- Manual uploads: `path/to/your/manual-upload-directory`
- Download watch folder: `path/to/your/download-watch-directory`
- Sandbox session root: `path/to/your/sandbox-session-root/sessions`
- Sandbox logs: `path/to/your/sandbox-log-file`
- Scan event log: `Backend/app/reports/scan_events.jsonl`
## Run The Full Stack

Start everything from the `sandbox` folder:

```powershell
cd path/to/your/CyberShield-Innovators/sandbox
powershell -ExecutionPolicy Bypass -File .\scripts\Start-BackendAndSandbox.ps1
```

This launches:

- the FastAPI backend on `http://127.0.0.1:8000`
- the sandbox monitor
- the Vite frontend dev server

Stop everything:

```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\Stop-BackendAndSandbox.ps1
```

Check stack health:

```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\Check-StackHealth.ps1
```

## Core API Endpoints

- `GET /api/health`
- `GET /api/scan/ml-status`
- `GET /api/scan/config`
- `POST /api/scan/upload`
- `GET /api/scan/results/{file_name}`
- `GET /api/scan/logs`
- `GET /api/scan/latest`
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

- Manual uploads are scanned in the background and exposed through `/api/scan/results/{file_name}`
- `/api/scan/latest` returns active manual uploads while they are still processing
- Image results are normalized so `Stego` predictions map to `Suspicious`
- The `.exe` scanner caches its model stack after startup to reduce repeated scan setup time
- The backend pre-warms ML stacks on startup
- Sandbox review sessions now try to exit from inside the guest before the host forces shutdown

## Scanner Files

- Stable router: `Backend/app/scanner.py`
- Image scanner export: `Backend/app/stg_scanner.py`
- Executable scanner export: `Backend/app/zd_scanner.py`
- Refactor package work-in-progress: `Backend/app/scanners/`

## Development Notes

- The scanner package under `Backend/app/scanners/` exists for cleanup and maintainability work
- The running app should continue to route through `Backend/app/scanner.py`
- If the frontend looks stale after backend/frontend restarts, refresh the browser once
