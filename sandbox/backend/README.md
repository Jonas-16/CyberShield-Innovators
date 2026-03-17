# Backend (FastAPI) - Sandbox Upload

This API receives files from your frontend scan page and writes them into `C:\Sandbox_Staging`.
Your `sandbox_monitor.py` watches that folder, so upload to backend triggers sandbox flow.

## Run

```powershell
cd backend
pip install -r requirements.txt
uvicorn app.main:app --reload --host 127.0.0.1 --port 8000
```

## Endpoint

- `POST /api/scan/upload`
  - Content-Type: `multipart/form-data`
  - Field name: `file`

## Frontend request example

```javascript
const form = new FormData();
form.append("file", selectedFile);

const res = await fetch("http://127.0.0.1:8000/api/scan/upload", {
  method: "POST",
  body: form,
});

const data = await res.json();
```

## Configuration

Optional environment variable:
- `SANDBOX_STAGING_DIR` (default: `C:\Sandbox_Staging`)
