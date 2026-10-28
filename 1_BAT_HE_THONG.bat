@echo off
chcp 65001 >nul
title [CTI SYSTEM] DANG KHOI DONG TOAN BO HE THONG...
color 0A

set "BASE_DIR=%~dp0"
set "OLLAMA_MODELS=%BASE_DIR%ollama_models"
set "OLLAMA_KEEP_ALIVE=24h"

echo ==============================================================================
echo   KHOI DONG HE THONG PHONG THU CTI VA AGENTIC SKILLS (5-STAGE WIZARD)
echo   - Web Dashboard : http://127.0.0.1:8765
echo   - WAF Proxy L7  : http://127.0.0.1:8766
echo   - Thu muc goc   : %BASE_DIR%
echo ==============================================================================
echo.

:: 1. Kiem tra Ollama neu may co san
where ollama >nul 2>nul
if %errorlevel% equ 0 (
    echo [1/3] Phat hien Ollama trong he thong, dang bat Ollama Server...
    start ">>> [1] OLLAMA GPU SERVER <<<" ollama serve
) else if exist "%LOCALAPPDATA%\Programs\Ollama\ollama.exe" (
    echo [1/3] Dang mo Ollama GPU Server tai LocalAppData...
    start ">>> [1] OLLAMA GPU SERVER <<<" "%LOCALAPPDATA%\Programs\Ollama\ollama.exe" serve
) else (
    echo [1/3] [THONG TIN] Khong phat hien Ollama (He thong chay che do CTI Rule va Agentic Skill tieu chuan).
)

:: 2. Khoi dong CTI Web Server va WAF Proxy
echo [2/3] Dang khoi dong CTI Defense Live Server va WAF Proxy (Cong 8765 / 8766)...
cd /d "%BASE_DIR%khang_sandbox_full_cti"
start ">>> [2] CTI DEFENSE SERVER <<<" python live_dashboard_app.py

:: 3. Cho server khoi dong va tu dong bat trinh duyet
echo [3/3] Dang cho he thong san sang...
ping 127.0.0.1 -n 4 >nul

echo.
echo Dang mo trinh duyet Web Dashboard tai: http://127.0.0.1:8765 ...
start "" "http://127.0.0.1:8765"

echo.
echo ==============================================================================
echo   [OK] HE THONG DA KHOI DONG THANH CONG!
echo   - Giao dien: http://127.0.0.1:8765
echo   - De TAT TOAN BO: Hay chay file 2_TAT_HE_THONG.bat
echo ==============================================================================
echo.
pause
