$projectRoot = Split-Path -Parent $PSScriptRoot
$backendRoot = Join-Path $projectRoot "..\Backend"
$frontendRoot = Join-Path $projectRoot "..\Frontend"
$sandboxRoot = $projectRoot
$backendActivate = Join-Path $backendRoot ".venv-ml\Scripts\Activate.ps1"
$healthCheckScript = Join-Path $PSScriptRoot "Check-StackHealth.ps1"
$stackStatePath = Join-Path $PSScriptRoot "stack-state.json"
$backendTitle = "Cyber Shield Backend"
$sandboxTitle = "Cyber Shield Sandbox Monitor"
$frontendTitle = "Cyber Shield Frontend"

if (-not (Test-Path $backendRoot)) {
    throw "Backend folder not found: $backendRoot"
}

if (-not (Test-Path $frontendRoot)) {
    throw "Frontend folder not found: $frontendRoot"
}

if (-not (Test-Path $backendActivate)) {
    throw "Backend virtual environment activation script not found: $backendActivate"
}

if (-not (Test-Path $healthCheckScript)) {
    throw "Health check script not found: $healthCheckScript"
}

Write-Host "Starting backend window..."
$backendProcess = Start-Process powershell.exe -PassThru -ArgumentList @(
    "-NoExit",
    "-ExecutionPolicy", "Bypass",
    "-Command",
    "& { Set-Location '$backendRoot'; `$Host.UI.RawUI.WindowTitle = '$backendTitle'; . '$backendActivate'; python -m uvicorn app.main:app --reload --host 127.0.0.1 --port 8000 }"
)

Start-Sleep -Seconds 2

Write-Host "Starting sandbox monitor window..."
$sandboxProcess = Start-Process powershell.exe -PassThru -ArgumentList @(
    "-NoExit",
    "-ExecutionPolicy", "Bypass",
    "-Command",
    "& { Set-Location '$sandboxRoot'; `$Host.UI.RawUI.WindowTitle = '$sandboxTitle'; . '$backendActivate'; python sandbox_monitor.py }"
)

Start-Sleep -Seconds 2

Write-Host "Starting frontend window..."
$frontendProcess = Start-Process powershell.exe -PassThru -ArgumentList @(
    "-NoExit",
    "-ExecutionPolicy", "Bypass",
    "-Command",
    "& { Set-Location '$frontendRoot'; `$Host.UI.RawUI.WindowTitle = '$frontendTitle'; npm run dev }"
)

$stackState = @{
    backend = @{
        title = $backendTitle
        pid = $backendProcess.Id
    }
    sandbox = @{
        title = $sandboxTitle
        pid = $sandboxProcess.Id
    }
    frontend = @{
        title = $frontendTitle
        pid = $frontendProcess.Id
    }
    created_at = (Get-Date).ToString("s")
}

$stackState | ConvertTo-Json | Set-Content -Path $stackStatePath

Write-Host "Backend, sandbox monitor, and frontend launched."
Write-Host "Waiting for services to come up before running health check..."
Start-Sleep -Seconds 8
Write-Host ""
Write-Host "Stack health"
& $healthCheckScript

