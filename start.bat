@echo off
setlocal
cd /d "%~dp0"

if exist ".venv\Scripts\python.exe" (
    ".venv\Scripts\python.exe" -m uvicorn app.main:app --reload --host 127.0.0.1 --port 8000
    exit /b %errorlevel%
)

where python >nul 2>nul
if errorlevel 1 (
    echo Python was not found. Create a virtual environment and install requirements.txt first.
    exit /b 1
)
python -m uvicorn app.main:app --reload --host 127.0.0.1 --port 8000
