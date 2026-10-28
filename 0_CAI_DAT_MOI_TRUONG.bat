@echo off
chcp 65001 >nul
title [CTI SYSTEM] CAI DAT MOI TRUONG PYTHON...
color 0B

echo ==============================================================================
echo   CAI DAT THU VIEN CHO HE THONG AGENTIC CTI DEFENSE
echo ==============================================================================
echo.

python --version >nul 2>nul
if %errorlevel% neq 0 (
    echo [LOI] May cua ban chua cai Python hoac chua them Python vao PATH!
    echo Vui long tai va cai dat Python 3.10 tro len tai: https://www.python.org/downloads/
    echo (Luu y: Nho tich vao o "Add Python to PATH" khi cai dat)
    echo.
    pause
    exit /b 1
)

echo Dang cai dat cac thu vien can thiet (FastAPI, Uvicorn, Pydantic, Requests)...
pip install -r "%~dp0requirements.txt"

echo.
echo ==============================================================================
echo   [HOAN TAT] DA CAI DAT THU VIEN THANH CONG!
echo   Bay gio ban chi can nhap dup file "1_BAT_HE_THONG.bat" de chay he thong.
echo ==============================================================================
echo.
pause
