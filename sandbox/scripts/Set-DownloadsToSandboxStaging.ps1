param(
  [string]$StagingPath = "D:\Download"
)

$ErrorActionPreference = "Stop"

$downloadsGuid = "{374DE290-123F-4565-9164-39C4925E467B}"
$shellFolders = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders"

New-Item -ItemType Directory -Force -Path $StagingPath | Out-Null
Set-ItemProperty -Path $shellFolders -Name $downloadsGuid -Value $StagingPath

# Ask Explorer to refresh known-folder paths for the current session.
Stop-Process -Name explorer -Force -ErrorAction SilentlyContinue
Start-Process explorer.exe

Write-Host "Downloads folder redirected to $StagingPath"
Write-Host "New downloads from apps that use the default Downloads known folder will now land there."
