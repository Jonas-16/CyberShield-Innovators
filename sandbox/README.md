# Windows Sandbox Monitor

## What this does

- Watches your configured download watch folder in real time
- Ignores temporary and unsupported files
- Waits for downloads to stabilize before processing
- Moves supported files into `path/to/your/sandbox-session-root/sessions/<session>/in/<file>`
- Scans the file through the backend scanner routing
- Launches Windows Sandbox for manual review
- Lets the user approve or reject the sandboxed file
- Writes sandbox actions to `path/to/your/sandbox-log-file`

Supported files:

- images: `.jpg`, `.jpeg`, `.png`, `.bmp`, `.tif`, `.tiff`, `.webp`
- executables: `.exe`

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

The combined start script already runs this health check automatically after startup.

If you only want the monitor by itself:

```powershell
python sandbox_monitor.py
```

The script auto-creates:

- `path/to/your/download-watch-directory`
- `path/to/your/sandbox-session-root`
- `path/to/your/sandbox-log-directory`

Session folders are created under:

```text
path/to/your/sandbox-session-root/sessions
```

## Configure app download folders

Set target apps to download into your configured download watch folder.

## Optional: Redirect the Windows Downloads Folder

If you want broader coverage for apps that save into the default Windows Downloads location, you can redirect the Downloads known folder to your configured watch folder.

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

## Logs

Log file:

- `path/to/your/sandbox-log-file`

Actions logged include:

- `[TIMESTAMP] FILE_DETECTED`
- `[TIMESTAMP] FILE_MOVED_TO_SANDBOX`
- `[TIMESTAMP] SANDBOX_STARTED`
- `[TIMESTAMP] SANDBOX_STOPPED`
- `[TIMESTAMP] FILE_REMOVED_FROM_SANDBOX`
- `[TIMESTAMP] USER_ALLOWED`
- `[TIMESTAMP] USER_REJECTED`

## Optional system tray support

If `pystray` and `Pillow` are installed, the app starts a tray icon with:

- `Start Monitoring`
- `Stop Monitoring`
- `Exit`

## Build executable with PyInstaller

```powershell
pyinstaller --onefile --windowed --name SandboxMonitor sandbox_monitor.py
```

Output executable:

- `dist\SandboxMonitor.exe`
