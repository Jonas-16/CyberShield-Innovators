param(
  [string]$VenvPath = ".venv-ml"
)

$ErrorActionPreference = "Stop"

Write-Host "Creating ML virtual environment at $VenvPath"
python -m venv $VenvPath

$pythonExe = Join-Path $VenvPath "Scripts\python.exe"
if (-not (Test-Path $pythonExe)) {
  throw "Virtual environment Python not found at $pythonExe"
}

Write-Host "Upgrading pip"
& $pythonExe -m pip install --upgrade pip

Write-Host "Installing backend base dependencies"
& $pythonExe -m pip install -r requirements.txt

Write-Host "Installing ML dependencies (torch + ember + lief stack)"
& $pythonExe -m pip install -r requirements-ml.txt

Write-Host "Verifying key imports"
& $pythonExe -c "import torch, numpy, lief; from ember.features import PEFeatureExtractor; print('ML stack OK')"

Write-Host "Done. Activate with:"
Write-Host "$VenvPath\Scripts\Activate.ps1"
