$stackStatePath = Join-Path $PSScriptRoot "stack-state.json"
$targets = @()

if (Test-Path $stackStatePath) {
    $stackState = Get-Content $stackStatePath | ConvertFrom-Json
    $targets = @(
        @{ Name = "Backend"; Pid = [int]$stackState.backend.pid; Title = $stackState.backend.title },
        @{ Name = "Sandbox Monitor"; Pid = [int]$stackState.sandbox.pid; Title = $stackState.sandbox.title },
        @{ Name = "Frontend"; Pid = [int]$stackState.frontend.pid; Title = $stackState.frontend.title }
    )
}
else {
    $targets = @(
        @{ Name = "Backend"; Pid = 0; Title = "Cyber Shield Backend" },
        @{ Name = "Sandbox Monitor"; Pid = 0; Title = "Cyber Shield Sandbox Monitor" },
        @{ Name = "Frontend"; Pid = 0; Title = "Cyber Shield Frontend" }
    )
}

Write-Host "Process windows"
foreach ($target in $targets) {
    $process = $null
    if ($target.Pid -gt 0) {
        $process = Get-Process -Id $target.Pid -ErrorAction SilentlyContinue
    }

    if ($process) {
        Write-Host "[OK] $($target.Name): running (PID $($process.Id))"
    }
    else {
        Write-Host "[FAIL] $($target.Name): not running"
    }
}

Write-Host ""
Write-Host "Service checks"

$backendOk = $false
for ($i = 0; $i -lt 5; $i++) {
    try {
        $backendHealth = Invoke-RestMethod -Uri "http://127.0.0.1:8000/api/health" -TimeoutSec 10
        if ($backendHealth.status -eq "ok") {
            Write-Host "[OK] Backend API: http://127.0.0.1:8000/api/health"
            $backendOk = $true
            break
        }
    }
    catch {
        Start-Sleep -Seconds 3
    }
}
if (-not $backendOk) {
    Write-Host "[FAIL] Backend API is not responding on http://127.0.0.1:8000/api/health"
}

$frontendPorts = 5173, 5174, 5175
$frontendOk = $false
$frontendHosts = "127.0.0.1", "localhost"

for ($attempt = 1; $attempt -le 6 -and -not $frontendOk; $attempt++) {
    foreach ($hostName in $frontendHosts) {
        foreach ($port in $frontendPorts) {
            try {
                $response = Invoke-WebRequest -Uri "http://${hostName}:$port" -TimeoutSec 5 -UseBasicParsing
                if ($response.StatusCode -ge 200 -and $response.StatusCode -lt 500) {
                    Write-Host "[OK] Frontend dev server: http://${hostName}:$port"
                    $frontendOk = $true
                    break
                }
            }
            catch {
            }
        }
        if ($frontendOk) { break }
    }
    if (-not $frontendOk -and $attempt -lt 6) {
        Start-Sleep -Seconds 2
    }
}

if (-not $frontendOk) {
    Write-Host "[FAIL] Frontend dev server is not responding on localhost/127.0.0.1 ports 5173, 5174, or 5175"
}

if (Test-Path "C:\Sandbox_Logs\sandbox.log") {
    $latestLog = Get-Content "C:\Sandbox_Logs\sandbox.log" -Tail 1 -ErrorAction SilentlyContinue
    if ($latestLog) {
        Write-Host "[OK] Sandbox log file found"
        Write-Host "Last log: $latestLog"
    }
    else {
        Write-Host "[OK] Sandbox log file found but currently empty"
    }
}
else {
    Write-Host "[FAIL] Sandbox log file not found at C:\Sandbox_Logs\sandbox.log"
}

