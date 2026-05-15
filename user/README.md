# User Device

This folder contains the files needed on the user laptop.

- `Frontend/` - React + Vite app for choosing files, uploading them to the backend API, and viewing scan results.

Run:

```powershell
cd Frontend
npm install
npm run dev
```

Set `Frontend/.env` for the backend location:

```env
VITE_BACKEND_URL=http://BACKEND_LAPTOP_IP:8000
```
