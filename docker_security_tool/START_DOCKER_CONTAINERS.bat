@echo off
chcp 65001 >nul
cd /d "%~dp0"
echo ==============================================================
echo   KHOI DONG DOCKER CONTAINER THAT (VULNERABLE & HARDENED)
echo ==============================================================
echo.
docker-compose up -d
echo.
echo Danh sach container dang chay:
docker ps
echo.
pause
