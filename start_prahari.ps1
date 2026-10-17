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
# Only a LISTENER conflicts. Without -State Listen this also matches a
# client socket in TimeWait, which lingers for minutes after any request
# to the port and is owned by the kernel - so a routine health check made
# the launcher warn about a conflict that did not exist, and attribute it
# to "PID 0".
$Conflict = Get-NetTCPConnection -LocalPort $Port -State Listen -ErrorAction SilentlyContinue
if ($Conflict) {
    $ConflictPid = $Conflict[0].OwningProcess
    $Owner = (Get-Process -Id $ConflictPid -ErrorAction SilentlyContinue).ProcessName
    if ($Owner) { $Owner = "$Owner (PID $ConflictPid)" } else { $Owner = "PID $ConflictPid" }
    Write-Host "[WARNING] Port $Port is already being listened on by $Owner." -ForegroundColor Yellow
    Write-Host "[WARNING] That instance may predate the current source: PraHari runs" -ForegroundColor Yellow
    Write-Host "[WARNING] without --reload, so stop it before relying on a recent fix." -ForegroundColor Yellow
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
