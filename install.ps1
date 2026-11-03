# Autonomous CTI Defense - 1-Line Installer for Windows
$ErrorActionPreference = "Stop"

Write-Host "==============================================================================" -ForegroundColor Cyan
Write-Host "  DANG CAI DAT HE THONG AN NINH MANG TU HANH CTI AGENTIC DEFENSE (1-LINE SETUP)" -ForegroundColor Cyan
Write-Host "==============================================================================" -ForegroundColor Cyan
Write-Host ""

# 1. Kiem tra Python
$pyCmd = $null
if (Get-Command python -ErrorAction SilentlyContinue) {
    $pyCmd = "python"
} elseif (Get-Command py -ErrorAction SilentlyContinue) {
    $pyCmd = "py"
} elseif (Get-Command python3 -ErrorAction SilentlyContinue) {
    $pyCmd = "python3"
} else {
    Write-Host "[LOI] May cua ban chua cai dat Python (3.10+). Vui long cai Python va tich chon Add to PATH." -ForegroundColor Red
    exit 1
}

# 2. Thu muc cai dat he thong
$targetDir = "$HOME\.cti-defense"
Write-Host "[1/3] Dang tai / cap nhat ma nguon he thong tai: $targetDir..." -ForegroundColor Yellow

if (Test-Path "$targetDir\.git") {
    Push-Location $targetDir
    git pull origin main --quiet
    Pop-Location
} else {
    if (Test-Path $targetDir) {
        Remove-Item $targetDir -Recurse -Force
    }
    git clone https://github.com/khang1233/DoAnChuyenNganh.git $targetDir --quiet
}

# 3. Cai dat thu vien Python
Write-Host "[2/3] Dang cai dat cac thu vien an ninh mang Python..." -ForegroundColor Yellow
& $pyCmd -m pip install -r "$targetDir\requirements.txt" --quiet --disable-pip-version-check

# 4. Dang ky lenh cti toan cuc
Write-Host "[3/3] Dang ky lenh CLI toan cuc 'cti' va 'cti-defense'..." -ForegroundColor Yellow

# Thu chay npm link neu co Node.js
$hasNode = Get-Command npm -ErrorAction SilentlyContinue
if ($hasNode) {
    Push-Location $targetDir
    npm link --quiet 2>$null
    Pop-Location
}

# Tao them shim cmd truc tiep vao AppData\Roaming\npm de chay duoc ngay ca khi khong co npm
$npmDir = "$env:APPDATA\npm"
if (!(Test-Path $npmDir)) {
    New-Item -ItemType Directory -Path $npmDir -Force | Out-Null
}

$shimContent = @"
@ECHO off
GOTO start
:find_dp0
SET dp0=%~dp0
EXIT /b
:start
SETLOCAL
CALL :find_dp0
node "$targetDir\bin\cli.js" %*
"@

Set-Content -Path "$npmDir\cti.cmd" -Value $shimContent -Encoding ASCII
Set-Content -Path "$npmDir\cti-defense.cmd" -Value $shimContent -Encoding ASCII

# Kiem tra xem $npmDir co trong PATH chua
$userPath = [Environment]::GetEnvironmentVariable("Path", "User")
if ($userPath -notmatch [regex]::Escape($npmDir)) {
    [Environment]::SetEnvironmentVariable("Path", "$userPath;$npmDir", "User")
    $env:Path += ";$npmDir"
}

Write-Host ""
Write-Host "==============================================================================" -ForegroundColor Green
Write-Host "  CAI DAT THANH CONG 100%! HE THONG DA SAN SANG SU DUNG." -ForegroundColor Green
Write-Host "==============================================================================" -ForegroundColor Green
Write-Host ""
Write-Host "  TU BAY GIO, BAN CHI CAN MO CMD / POWERSHELL TAI BAT KY THU MUC DU AN NAO VA GO:" -ForegroundColor White
Write-Host ""
Write-Host "       cti" -ForegroundColor Cyan
Write-Host ""
Write-Host "  He thong se tu dong khoi dong may chu va mo duy nhat 1 Web Dashboard: http://127.0.0.1:8765" -ForegroundColor White
Write-Host "==============================================================================" -ForegroundColor Green
Write-Host ""
