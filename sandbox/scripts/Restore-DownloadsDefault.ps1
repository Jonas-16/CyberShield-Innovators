param(
  [string]$DefaultPath = "$env:USERPROFILE\Downloads"
)

$ErrorActionPreference = "Stop"

$downloadsGuid = "{374DE290-123F-4565-9164-39C4925E467B}"
$shellFolders = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders"

New-Item -ItemType Directory -Force -Path $DefaultPath | Out-Null
Set-ItemProperty -Path $shellFolders -Name $downloadsGuid -Value $DefaultPath

Stop-Process -Name explorer -Force -ErrorAction SilentlyContinue
Start-Process explorer.exe

Write-Host "Downloads folder restored to $DefaultPath"
