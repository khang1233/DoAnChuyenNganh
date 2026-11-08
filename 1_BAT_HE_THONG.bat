@echo off
chcp 65001 >nul
title [CTI DEFENSE SYSTEM] TRUNG TAM DIEU KHIEN AN NINH MANG
color 0A

:: 1. Kiem tra Python
python --version >nul 2>&1
if errorlevel 1 goto no_python

:: 2. Chuyen vao thu muc goc va chay bo dieu khien he thong
cd /d "%~dp0"
python cti_core\system_ctl.py %*
exit /b %errorlevel%

:no_python
color 0C
echo ==============================================================================
echo   [LOI] MAY CHUA CO PYTHON HOAC CHUA THEM PYTHON VAO BIEN MOI TRUONG PATH!
echo ==============================================================================
echo Vui long cai dat Python 3.10 tro len tai: https://www.python.org/downloads/
echo Luu y: Nho tich chon vao o Add Python to PATH khi cai dat.
echo.
pause
exit /b 1
