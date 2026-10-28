@echo off
chcp 65001 >nul
title [CTI DEFENSE SYSTEM] KHOI DONG THANH CONG
color 0A

set "BASE_DIR=%~dp0"
set "OLLAMA_MODELS=%BASE_DIR%ollama_models"
set "OLLAMA_KEEP_ALIVE=24h"

:: 1. Kiem tra Ollama neu may co san thi chay ngam
where ollama >nul 2>nul
if %errorlevel% equ 0 (
    start /B "" ollama serve >nul 2>&1
) else if exist "%LOCALAPPDATA%\Programs\Ollama\ollama.exe" (
    start /B "" "%LOCALAPPDATA%\Programs\Ollama\ollama.exe" serve >nul 2>&1
)

:: 2. Khoi dong CTI Web Server va WAF Proxy
cd /d "%BASE_DIR%khang_sandbox_full_cti"
start /B "" python live_dashboard_app.py >nul 2>&1

:: 3. Cho server san sang
ping 127.0.0.1 -n 3 >nul

:: 4. Tu dong mo trinh duyet vao ngay Buoc 1 (Scan)
start "" "http://127.0.0.1:8765"

cls
echo ==============================================================================
echo   🚀 HE THONG AN NINH MANG TU HANH CTI AGENTIC DEFENSE (KHOI DONG THANH CONG)
echo ==============================================================================
echo.
echo   [OK] CTI Defense Engine & WAF Reverse Proxy dang hoat dong tai cong 8766.
echo   [OK] Da tu dong mo trinh duyet Web Dashboard.
echo.
echo   ==========================================================================
echo   👉 DUONG LINK TRUY CAP TRUC TIEP:
echo.
echo        http://127.0.0.1:8765
echo.
echo   ==========================================================================
echo.
echo   * BUOC 1 TREN WEB LA: [ QUET DU AN (SCAN CODEBASE) ]
echo     Chi can nhap duong dan thu muc hoac link Git, he thong se tu dong lam het.
echo.
echo   * DE TAT HE THONG: Nhap dup vao file "2_TAT_HE_THONG.bat"
echo ==============================================================================
echo.
pause
