param (
    [int]$Port = 8000,
    [string]$HostBinding = "127.0.0.1",
    [switch]$CheckOnly
)

# PraHari Unified Server Launcher (PowerShell)
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location $ScriptDir

Write-Host "=========================================================" -ForegroundColor Cyan
Write-Host "  PraHari — The Digital Sentinel (Unified Server)" -ForegroundColor Cyan
Write-Host "=========================================================" -ForegroundColor Cyan

# 1. Virtual environment check
$PythonExe = Join-Path $ScriptDir "backend\.venv\Scripts\python.exe"
if (-not (Test-Path $PythonExe)) {
    Write-Host "[INFO] Initializing Python virtual environment..." -ForegroundColor Yellow
    python -m venv (Join-Path $ScriptDir "backend\.venv")
    & $PythonExe -m pip install --upgrade pip
    & $PythonExe -m pip install -r (Join-Path $ScriptDir "backend\requirements.txt")
}

# 2. Frontend dist check
$FrontendDist = Join-Path $ScriptDir "frontend\dist\index.html"
if (-not (Test-Path $FrontendDist)) {
    Write-Host "[INFO] Building frontend production bundle..." -ForegroundColor Yellow
    Push-Location (Join-Path $ScriptDir "frontend")
    npm ci
    npm run build
    Pop-Location
}

# 3. Port conflict detection
$Conflict = Get-NetTCPConnection -LocalPort $Port -ErrorAction SilentlyContinue
if ($Conflict) {
    Write-Host "[WARNING] Port $Port is currently in use by PID $($Conflict[0].OwningProcess)." -ForegroundColor Yellow
    Write-Host "[WARNING] Specify a different port using -Port <number> if desired." -ForegroundColor Yellow
}

if ($CheckOnly) {
    Write-Host "[SUCCESS] Preflight checks passed. PraHari environment is verified." -ForegroundColor Green
    exit 0
}

Write-Host ""
Write-Host "[INFO] PraHari starting on http://${HostBinding}:${Port}" -ForegroundColor Green
Write-Host "[INFO] Web Dashboard: http://${HostBinding}:${Port}/" -ForegroundColor Green
Write-Host "[INFO] REST API Docs: http://${HostBinding}:${Port}/docs" -ForegroundColor Green
Write-Host ""

& $PythonExe -m uvicorn app.main:app --app-dir (Join-Path $ScriptDir "backend") --host $HostBinding --port $Port
