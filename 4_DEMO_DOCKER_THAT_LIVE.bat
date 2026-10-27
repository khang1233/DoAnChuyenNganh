@echo off
chcp 65001 >nul
cd /d "%~dp0docker_security_tool"
cls
echo ==============================================================================
echo   DEMO AN NINH TRUC TIEP VOI DOCKER ENGINE DANG CHAY THUC TE
echo   De tai: Xay dung cong cu kiem tra cau hinh va phat hien rui ro Docker
echo ==============================================================================
echo.
echo [BUOC 1] Kiem tra Docker Daemon & Khoi dong 2 Container bang Docker Compose...
docker-compose up -d
if %ERRORLEVEL% neq 0 (
    echo.
    echo [CANH BAO] Docker Desktop chua duoc bat hoac chua chay xong!
    echo Hay mo ung dung Docker Desktop tren man hinh roi chay lai file nay nhe!
    pause
    exit /b
)
echo.
echo ==============================================================================
echo [BUOC 2] DANH SACH CAC CONTAINER DANG CHAY TRUC TIEP TREN MAY (DOCKER PS):
echo ==============================================================================
docker ps
echo.
echo Nhan phim bat ky de chay TOOL QUET TRUC TIEP Container [vulnerable_app]...
pause >nul
echo.
echo ==============================================================================
echo [BUOC 3] TOOL DANG KET NOI DOCKER API DE QUET RUNTIME CUA [vulnerable_app]...
echo ==============================================================================
python docker_security_scanner.py vulnerable_app --ci
echo.
echo Nhan phim bat ky de QUET TIEP Container da duoc sua loi [hardened_app]...
pause >nul
echo.
echo ==============================================================================
echo [BUOC 4] TOOL QUET TRUC TIEP Container [hardened_app]...
echo ==============================================================================
python docker_security_scanner.py hardened_app --ci
echo.
echo ==============================================================================
echo   HOAN TAT DEMO THUC TE TRUC TIEP TREN DOCKER ENGINE!
echo ==============================================================================
pause
