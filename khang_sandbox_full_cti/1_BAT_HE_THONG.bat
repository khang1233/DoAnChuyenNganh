@echo off
chcp 65001 >nul
title [CTI SYSTEM] DANG KHOI DONG TOAN BO HE THONG...
color 0A

echo ==============================================================================
echo   KHOI DONG HE THONG PHONG THU CTI VA LOCAL AI AGENT
echo   - Web Dashboard : http://127.0.0.1:8765
echo   - WAF Proxy L7  : http://127.0.0.1:8766
echo   - Ollama GPU    : http://127.0.0.1:11434
echo ==============================================================================
echo.

set "OLLAMA_MODELS=D:\mkhang\DoAnChuyenNganh\ollama_models"
set "OLLAMA_KEEP_ALIVE=24h"

echo [1/3] Dang mo Cua so Ollama GPU Server (Cong 11434)...
start ">>> [1] OLLAMA GPU SERVER <<<" "%LOCALAPPDATA%\Programs\Ollama\ollama.exe" serve

echo [2/3] Dang mo Cua so CTI Web Server va WAF Proxy (Cong 8765 / 8766)...
cd /d "D:\mkhang\DoAnChuyenNganh\khang_sandbox_full_cti"
start ">>> [2] CTI DEFENSE SERVER <<<" python live_dashboard_app.py

echo [3/3] Dang cho he thong khoi dong (5 giay)...
ping 127.0.0.1 -n 6 >nul

echo.
echo Dang mo trinh duyet Web Dashboard tai: http://127.0.0.1:8765 ...
start "" "http://127.0.0.1:8765"

echo.
echo ==============================================================================
echo   [OK] HE THONG DA DUOC BAT THANH CONG!
echo   - 2 Cua so Terminal dang chay truc tiep tren man hinh.
echo   - De TAT TOAN BO: Hay chay file 2_TAT_HE_THONG.bat
echo ==============================================================================
echo.
pause
