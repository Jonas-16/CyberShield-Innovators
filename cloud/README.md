# Cloud Device

This folder contains the files needed on the backend/cloud laptop.

- `backend/` - FastAPI scanner API, scanner routing, ML scanner code, and model files.
- `sandbox/` - optional legacy Windows Sandbox monitor for local interception demos.
- `Decoder/` - currently empty placeholder kept from the original project layout.

Run the scanner API:

```powershell
cd backend
pip install -r requirements.txt
uvicorn app.main:app --reload --host 0.0.0.0 --port 8000
```

The user device should point `VITE_BACKEND_URL` to this machine's IP address and port.
