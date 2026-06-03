# CyberShield Innovators

CyberShield Innovators is a two-part malware and steganography scanning demo. A user-side
React app uploads files to a FastAPI backend, where dedicated scanner modules analyze each
supported file type and return a structured verdict for the UI.

## Project Layout

- `user/Frontend/` - React + Vite UI for uploading files and viewing scan results.
- `user/watcher/` - optional user-device folder watcher that uploads supported files automatically.
- `cloud/backend/` - FastAPI scanner service, ML scanner code, model artifacts, and result APIs.
- `cloud/sandbox/` - optional legacy Windows Sandbox tooling for local download interception demos.

## Supported Scanners

- Image steganography scans for `.jpg`, `.jpeg`, `.jfif`, `.png`, `.bmp`, `.gif`, `.tif`, `.tiff`, and `.webp`.
- Windows executable zero-day scans for `.exe`.
- Android APK zero-day scans for `.apk`.

APK scanning uses `cloud/backend/app/scanners/apk/` with the model artifact in
`cloud/backend/app/models/apk_models/apk.pth`. APK results include model probabilities,
structural risk, evidence level, DEX count, certificate file count, and preprocessing metadata.

## Run The User UI

```powershell
cd user\Frontend
npm install
npm run dev
```

For a two-laptop demo, create `user/Frontend/.env`:

```env
VITE_BACKEND_URL=http://BACKEND_LAPTOP_IP:8000
```

## Run The Cloud Backend

```powershell
cd cloud\backend
pip install -r requirements.txt
uvicorn app.main:app --reload --host 0.0.0.0 --port 8000
```

Use `--host 127.0.0.1` when the frontend and backend are on the same laptop.

Check scanner readiness after startup:

```text
http://127.0.0.1:8000/api/scan/ml-status
```

The response reports readiness for the steganography, executable zero-day, and APK scanners.
