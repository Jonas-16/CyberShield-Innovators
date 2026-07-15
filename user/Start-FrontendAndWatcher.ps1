$ErrorActionPreference = "Stop"

$UserRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
$WatcherDir = Join-Path $UserRoot "watcher"
$FrontendDir = Join-Path $UserRoot "Frontend"
$WatcherPython = Join-Path $WatcherDir ".venv\Scripts\python.exe"
$WatcherHealthUrl = "http://127.0.0.1:8765/api/health"
$WatcherOutLog = Join-Path $WatcherDir "watcher.out.log"
$WatcherErrLog = Join-Path $WatcherDir "watcher.err.log"
$startedWatcher = $null
$script:cleanupDone = $false

function Test-HttpOk {
    param([string]$Url)

    try {
        $response = Invoke-WebRequest -UseBasicParsing -Uri $Url -TimeoutSec 2
        return $response.StatusCode -ge 200 -and $response.StatusCode -lt 300
    } catch {
        return $false
    }
}

function Stop-StartedProcesses {
    if ($script:cleanupDone) {
        return
    }
    $script:cleanupDone = $true

    if ($startedWatcher -and -not $startedWatcher.HasExited) {
        Write-Host ""
        Write-Host "Stopping watcher process $($startedWatcher.Id)..."
        Stop-Process -Id $startedWatcher.Id -Force -ErrorAction SilentlyContinue
    }
}

function Stop-StaleWatcherPort {
    try {
        $connections = Get-NetTCPConnection -LocalPort 8765 -ErrorAction SilentlyContinue
        $processIds = $connections | Select-Object -ExpandProperty OwningProcess -Unique
        foreach ($processId in $processIds) {
            if ($processId -and $processId -ne $PID) {
                Write-Host "Stopping stale process on watcher port 8765: $processId"
                Stop-Process -Id $processId -Force -ErrorAction SilentlyContinue
            }
        }
        if ($processIds) {
            Start-Sleep -Seconds 1
        }
    } catch {
        Write-Warning "Could not inspect port 8765. Continuing with watcher startup."
    }
}

$cancelHandler = [ConsoleCancelEventHandler] {
    param($sender, $eventArgs)
    $eventArgs.Cancel = $true
    Stop-StartedProcesses
    exit 130
}

[Console]::add_CancelKeyPress($cancelHandler)

Write-Host "Starting CyberShield user app..."
Write-Host "Tip: for clean Ctrl+C shutdown, run this script directly instead of through npm.cmd."

if (Test-HttpOk -Url $WatcherHealthUrl) {
    Write-Host "Watcher is already running on 127.0.0.1:8765."
} else {
    if (-not (Test-Path -LiteralPath $WatcherPython)) {
        throw "Watcher Python environment is missing: $WatcherPython. Create it with: cd $WatcherDir; python -m venv .venv; .\.venv\Scripts\python.exe -m pip install -r requirements.txt"
    }
    Stop-StaleWatcherPort
    Write-Host "Starting folder watcher on 127.0.0.1:8765..."
    $startedWatcher = Start-Process `
        -FilePath $WatcherPython `
        -ArgumentList @("folder_watcher.py") `
        -WorkingDirectory $WatcherDir `
        -RedirectStandardOutput $WatcherOutLog `
        -RedirectStandardError $WatcherErrLog `
        -WindowStyle Hidden `
        -PassThru

    $ready = $false
    for ($i = 0; $i -lt 15; $i++) {
        Start-Sleep -Seconds 1
        if (Test-HttpOk -Url $WatcherHealthUrl) {
            $ready = $true
            break
        }
    }

    if ($ready) {
        Write-Host "Watcher is ready."
    } else {
        Write-Warning "Watcher did not answer yet. The frontend will still start, but folder monitoring may show offline."
        Write-Warning "Watcher logs: $WatcherErrLog"
    }
}

try {
    Write-Host "Starting frontend on http://127.0.0.1:5174 ..."
    Set-Location $FrontendDir
    $viteScript = Join-Path $FrontendDir "node_modules\vite\bin\vite.js"
    if (-not (Test-Path -LiteralPath $viteScript)) {
        throw "Vite is not installed. Run npm.cmd install inside $FrontendDir first."
    }
    & node $viteScript --host 0.0.0.0 --port 5174
} finally {
    Stop-StartedProcesses
    [Console]::remove_CancelKeyPress($cancelHandler)
}
