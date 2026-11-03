@echo off
chcp 65001 >nul
title [CTI DEFENSE SYSTEM] DANG TAT TOAN BO HE THONG...
color 0C

echo ==============================================================================
echo   DANG TAT TOAN BO HE THONG CTI VA GIAI PHONG 100%% RAM / GPU...
echo ==============================================================================
echo.

cd /d "%~dp0"

:: 1. Goi trinh dieu khien python dung sach se he thong
python khang_sandbox_full_cti\system_ctl.py stop
if errorlevel 1 goto fallback_kill
goto end

:fallback_kill
echo.
echo [*] Dang cuong che giai phong tien trinh va cong mang...
taskkill /F /IM "ollama.exe" /T >nul 2>&1
taskkill /F /IM "ollama_llama_server.exe" /T >nul 2>&1
powershell -NoProfile -Command "$procs = Get-CimInstance Win32_Process | Where-Object { $_.CommandLine -match 'live_dashboard_app' }; if ($procs) { $procs | ForEach-Object { Stop-Process -Id $_.ProcessId -Force -ErrorAction SilentlyContinue } }"
powershell -NoProfile -Command "$pids = (Get-NetTCPConnection -LocalPort 8765,8766,11434 -ErrorAction SilentlyContinue).OwningProcess; if ($pids) { Stop-Process -Id $pids -Force -ErrorAction SilentlyContinue }"
echo.
echo ==============================================================================
echo   [HOAN TAT] DA TAT SACH TOAN BO HE THONG!
echo ==============================================================================

:end
echo Nhap phim bat ky de dong cua so...
pause >nul
exit /b 0
