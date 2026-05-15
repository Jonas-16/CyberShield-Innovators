# CyberShield Innovators

This repo is split by deployment target:

- `user/Frontend/` - files needed on the user device. This is the React + Vite UI that uploads files to the scanner API.
- `cloud/backend/` - files needed on the backend/cloud device. This is the FastAPI scanner service and ML scanner code.
- `cloud/sandbox/` - optional legacy Windows Sandbox tooling for local download interception demos.

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
