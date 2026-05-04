$stackStatePath = Join-Path $PSScriptRoot "stack-state.json"

if (-not (Test-Path $stackStatePath)) {
    Write-Host "No stack state file found. Nothing to stop."
    exit 0
}

$stackState = Get-Content $stackStatePath | ConvertFrom-Json
$rootIds = @(
    [int]$stackState.backend.pid,
    [int]$stackState.sandbox.pid,
    [int]$stackState.frontend.pid
) | Where-Object { $_ -gt 0 } | Select-Object -Unique

if (-not $rootIds) {
    Write-Host "No recorded processes found in stack state."
    Remove-Item $stackStatePath -Force -ErrorAction SilentlyContinue
    exit 0
}

function Get-DescendantProcessIds {
    param(
        [int[]]$RootIds,
        $AllProcesses
    )

    $descendants = New-Object System.Collections.Generic.List[int]
    $queue = New-Object System.Collections.Generic.Queue[int]

    foreach ($rootId in $RootIds) {
        $queue.Enqueue($rootId)
    }

    while ($queue.Count -gt 0) {
        $currentId = $queue.Dequeue()
        $children = $AllProcesses | Where-Object { $_.ParentProcessId -eq $currentId }
        foreach ($child in $children) {
            if (-not $descendants.Contains([int]$child.ProcessId)) {
                $descendants.Add([int]$child.ProcessId)
                $queue.Enqueue([int]$child.ProcessId)
            }
        }
    }

    return $descendants
}

$allProcesses = Get-CimInstance Win32_Process
$descendantIds = Get-DescendantProcessIds -RootIds $rootIds -AllProcesses $allProcesses

foreach ($childId in ($descendantIds | Sort-Object -Descending)) {
    Write-Host "Stopping child PID $childId"
    Stop-Process -Id $childId -Force -ErrorAction SilentlyContinue
}

foreach ($processId in ($rootIds | Sort-Object -Descending)) {
    Write-Host "Stopping root PID $processId"
    Stop-Process -Id $processId -Force -ErrorAction SilentlyContinue
}

Remove-Item $stackStatePath -Force -ErrorAction SilentlyContinue
Write-Host "Backend, sandbox monitor, and frontend stopped."
