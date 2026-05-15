# Legacy Sandbox Upload Backend

This is an optional legacy helper for the Windows Sandbox prototype under `cloud/sandbox`.
The main cloud scanner API now lives in `cloud/backend`.

This helper receives files and writes them into `C:\Sandbox_Staging`.
`cloud/sandbox/sandbox_monitor.py` can watch that folder, so upload to this helper triggers the old sandbox flow.

## Run

```powershell
cd backend
pip install -r requirements.txt
uvicorn app.main:app --reload --host 127.0.0.1 --port 8000
```

Run this command from `cloud/sandbox` if you need this legacy helper.

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
