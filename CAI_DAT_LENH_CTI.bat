@echo off
chcp 65001 >nul
title [CTI DEFENSE] CAI DAT LENH TOAN CUC (GLOBAL CLI)
color 0B

echo ==============================================================================
echo   DANG CAI DAT LENH TOAN CUC 'cti' VA 'cti-defense' VAO MAY TINH...
echo ==============================================================================
echo.

cd /d "%~dp0"

:: 1. Cai dat qua npm link (neu may co Node.js)
where npm >nul 2>&1
if not errorlevel 1 (
    echo [*] Phat hien Node.js va npm, dang kich hoat npm link...
    call npm link
    echo [OK] Da dang ky lenh 'cti' va 'cti-defense' qua npm thanh cong!
    echo.
)

:: 2. Cai dat qua pip (neu may co Python)
where python >nul 2>&1
if not errorlevel 1 (
    echo [*] Phat hien Python, dang cai dat goi cti-defense cuc bo (pip install -e .)...
    python -m pip install -e . --no-deps >nul 2>&1
    echo [OK] Da dang ky lenh 'cti' va 'cti-defense' qua Python pip thanh cong!
    echo.
)

echo ==============================================================================
echo   [HOAN TAT] BAN DA CO THE DUNG LENH 'cti' O BAT KY DAU!
echo ==============================================================================
echo.
echo Cach dung rat don gian:
echo   1. Mo Terminal hoac CMD tai bat ky thu muc du an web nao ban muon bao ve
echo   2. Go lenh:
echo        cti scan   (De quet va cai dat bo ky nang phong thu truc tiep)
echo        cti        (De mo Web Dashboard quan ly truc quan cho du an do)
echo.
echo Nhap phim bat ky de ket thuc...
pause >nul
exit /b 0
