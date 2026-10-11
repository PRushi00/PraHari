@echo off
setlocal
title PraHari — The Digital Sentinel

echo =========================================================
echo   PraHari — The Digital Sentinel (Unified Production)
echo =========================================================
echo.

cd /d "%~dp0"

REM 1. Check Python installation
where python >nul 2>nul
if %errorlevel% neq 0 (
    echo [ERROR] Python 3.10+ is required but not found in PATH.
    pause
    exit /b 1
)

REM 2. Activate or setup backend virtual environment
if not exist "backend\.venv\Scripts\python.exe" (
    echo [INFO] Creating Python virtual environment...
    python -m venv backend\.venv
    echo [INFO] Installing backend dependencies...
    backend\.venv\Scripts\python.exe -m pip install --upgrade pip
    backend\.venv\Scripts\python.exe -m pip install -r backend\requirements.txt
)

REM 3. Check if frontend build exists
if not exist "frontend\dist\index.html" (
    echo [INFO] Frontend build missing. Building frontend...
    cd frontend
    call npm ci
    call npm run build
    cd ..
)

echo.
echo [INFO] Starting PraHari Unified Server on http://127.0.0.1:8000 ...
echo [INFO] Press CTRL+C to terminate server.
echo.

backend\.venv\Scripts\python.exe -m uvicorn app.main:app --app-dir backend --host 127.0.0.1 --port 8000
