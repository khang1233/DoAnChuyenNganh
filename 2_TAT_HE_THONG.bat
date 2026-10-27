@echo off
chcp 65001 >nul
title [CTI SYSTEM] DANG TAT TOAN BO HE THONG...
color 0C

echo ==============================================================================
echo   DANG TAT TOAN BO HE THONG CTI VA GIAI PHONG 100% RAM / GPU...
echo ==============================================================================
echo.

echo [1/3] Dang dung cac tien trinh Ollama GPU Server...
taskkill /F /IM "ollama app.exe" /T >nul 2>&1
taskkill /F /IM "ollama.exe" /T >nul 2>&1
taskkill /F /IM "ollama_llama_server.exe" /T >nul 2>&1
echo       - Da dung toan bo tien trinh Ollama.

echo [2/3] Dang dung tien trinh Web Dashboard va Live WAF Proxy...
powershell -NoProfile -Command "$procs = Get-CimInstance Win32_Process | Where-Object { $_.CommandLine -match 'live_dashboard_app' }; if ($procs) { $procs | ForEach-Object { Stop-Process -Id $_.ProcessId -Force -ErrorAction SilentlyContinue } }"
echo       - Da dung tien trinh live_dashboard_app.py.

echo [3/3] Dang giai phong cac cong mang (8765, 8766, 11434)...
powershell -NoProfile -Command "$pids = (Get-NetTCPConnection -LocalPort 8765,8766,11434 -ErrorAction SilentlyContinue).OwningProcess; if ($pids) { Stop-Process -Id $pids -Force -ErrorAction SilentlyContinue }"
echo       - Da giai phong tat ca cong mang.

echo.
echo ==============================================================================
echo   [HOAN TAT] DA TAT SACH TOAN BO HE THONG!
echo   - Toan bo bo nho GPU va RAM da duoc giai phong 100%.
echo ==============================================================================
echo.
pause
