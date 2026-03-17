# Windows Local Download Interception Sandbox - Prototype v1

## What this does
- Watches `D:\Download` in real time.
- Waits for downloads to finish (file size stability checks).
- Moves files to `C:\Sandbox_VM_Input`.
- Simulates analysis for 3 seconds.
- Prompts user with `Allow` / `Reject` decision.
- `Allow`: moves file to `C:\Users\%USERNAME%\Downloads`.
- `Reject`: deletes file.
- Cleans sandbox folder and logs every action to `C:\Sandbox_Logs\sandbox.log`.

## Requirements
- Windows 10/11
- Python 3.10+

Install dependencies:

```powershell
pip install -r requirements.txt
```

## Run

Start backend and sandbox monitor together:

```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\Start-BackendAndSandbox.ps1
```

This opens:
- one PowerShell window for the FastAPI backend
- one PowerShell window for the sandbox monitor
- one PowerShell window for the frontend dev server

Stop all three together:

```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\Stop-BackendAndSandbox.ps1
```

Check health after launch:

```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\Check-StackHealth.ps1
```

The combined start script already runs this health check automatically after startup. Use the command above only if you want to re-check later.

If you only want the monitor by itself:

```powershell
python sandbox_monitor.py
```

The combined launcher runs all three together. If you want to run frontend by itself, use the `Frontend` folder with `npm run dev`.

The script auto-creates:
- `D:\Download`
- `C:\Sandbox_VM_Input`
- `C:\Sandbox_Logs`

## Configure app download folders
Set all target apps to download into `D:\Download`.

## Optional: Redirect the Windows Downloads Folder
If you want broader coverage for apps that save into the default Windows Downloads location, you can redirect the Downloads known folder to `D:\Download`.

Set Downloads to staging:

```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\Set-DownloadsToSandboxStaging.ps1
```

Restore Downloads back to the normal path:

```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\Restore-DownloadsDefault.ps1
```

Notes:
- This helps with many apps that use the default Downloads folder automatically.
- It does not guarantee interception for every app on the device.
- Apps that save to custom folders or private temp locations still need their own download path configured.

### Chrome
1. Open `chrome://settings/downloads`
2. Set `Location` to `D:\Download`
3. Optional: disable "Ask where to save each file before downloading"

### Edge
1. Open `edge://settings/downloads`
2. Set `Location` to `D:\Download`
3. Optional: disable "Ask me what to do with each download"

### Telegram Desktop
1. Open `Settings` -> `Advanced` -> `Download path`
2. Select `D:\Download`

### WhatsApp Desktop
1. Open `Settings` -> `Storage and data` (or equivalent downloads/storage section)
2. Set media/file download location to `D:\Download` if your version exposes this option
3. If your WhatsApp build does not expose a custom path, use Windows-level workaround:
   - Move your default Downloads folder to `D:\Download` temporarily or
   - Use per-app save-as prompts and manually select `D:\Download`

## Logs
Log file:
- `C:\Sandbox_Logs\sandbox.log`

Actions logged:
- `[TIMESTAMP] FILE_DETECTED`
- `[TIMESTAMP] FILE_MOVED_TO_SANDBOX`
- `[TIMESTAMP] USER_ALLOWED`
- `[TIMESTAMP] USER_REJECTED`
- `[TIMESTAMP] FILE_DELETED`
- `[TIMESTAMP] SANDBOX_CLEANED`

## Optional system tray support
If `pystray` and `Pillow` are installed (included in requirements), the app starts a tray icon with:
- `Start Monitoring`
- `Stop Monitoring`
- `Exit`

## Build executable with PyInstaller

```powershell
pyinstaller --onefile --windowed --name SandboxMonitor sandbox_monitor.py
```

Output executable:
- `dist\SandboxMonitor.exe`
