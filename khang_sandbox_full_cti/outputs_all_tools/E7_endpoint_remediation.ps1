# =============================================================================
# KỊCH BẢN KHẮC PHỤC SỰ CỐ, DIỆT MÃ ĐỘC & HARDENING HỆ THỐNG TỰ ĐỘNG
# Chiến dịch: [CVE-2026-83548] SonicWall SMA1000 Appliances — SonicWall SMA1000 Appl
# Lỗ hổng liên quan: CVE-2026-83548
# Chức năng: Quét mã băm diệt tiến trình mã độc, cô lập file vào vùng cách ly,
# ngắt kết nối socket tới C2, khóa DNS Sinkhole và rà soát bản vá hệ thống.
# =============================================================================

# --- [1] WINDOWS POWERSHELL ACTIVE REMEDIATION & MALWARE CLEANUP (.ps1) ---
$MaliciousIPs = @("0.0.0.0")
$MaliciousDomains = @()
$MaliciousHashes = @()

# Bước 0: Rà quét tiến trình bộ nhớ, tính hash SHA256 và tiêu diệt ngay tiến trình mã độc:
Write-Host '[*] Đang rà soát tiến trình hệ thống theo bảng mã băm CTI độc hại...' -ForegroundColor Cyan
if ($MaliciousHashes.Count -gt 0) {
    Get-Process -ErrorAction SilentlyContinue | ForEach-Object {
        try {
            if ($_.Path -and (Test-Path $_.Path)) {
                $fHash = (Get-FileHash -Path $_.Path -Algorithm SHA256 -ErrorAction SilentlyContinue).Hash.ToLower()
                if ($MaliciousHashes -contains $fHash) {
                    Write-Host "[!] PHÁT HIỆN TIẾN TRÌNH MÃ ĐỘC: $($_.ProcessName) (PID: $($_.Id)) - Hash: $fHash" -ForegroundColor Red
                    Stop-Process -Id $_.Id -Force -ErrorAction SilentlyContinue
                    Write-Host "[+] ĐÃ TIÊU DIỆT THÀNH CÔNG TIẾN TRÌNH PID: $($_.Id)" -ForegroundColor Green
                }
            }
        } catch {}
    }
}

# Bước 0B: Săn lùng và cách ly (Quarantine) các file nhị phân độc hại trong các thư mục tạm:
$QuarantineFolder = 'C:\ProgramData\CTI_Quarantine'
if ($MaliciousHashes.Count -gt 0) {
    if (!(Test-Path $QuarantineFolder)) { New-Item -ItemType Directory -Path $QuarantineFolder -Force | Out-Null }
    $ScanLocations = @($env:TEMP, "$env:APPDATA\Local\Temp", 'C:\Users\Public', "$env:USERPROFILE\Downloads")
    foreach ($loc in $ScanLocations) {
        if (Test-Path $loc) {
            Get-ChildItem -Path $loc -File -Include *.exe,*.dll,*.ps1,*.bat -ErrorAction SilentlyContinue | ForEach-Object {
                $fHash = (Get-FileHash -Path $_.FullName -Algorithm SHA256 -ErrorAction SilentlyContinue).Hash.ToLower()
                if ($MaliciousHashes -contains $fHash) {
                    Write-Host "[!] CÁCH LY TỆP MÃ ĐỘC: $($_.FullName)" -ForegroundColor Red
                    icacls $_.FullName /deny 'Everyone:(X)' | Out-Null
                    Move-Item -Path $_.FullName -Destination "$QuarantineFolder\$($_.Name).locked" -Force -ErrorAction SilentlyContinue
                }
            }
        }
    }
}

# Bước 1: Kiểm tra có tiến trình nào đang kết nối tới IP C2 hay không và tự động tiêu diệt:
Get-NetTCPConnection -State Established -ErrorAction SilentlyContinue | Where-Object { $MaliciousIPs -contains $_.RemoteAddress } | ForEach-Object {
    $proc = Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue
    Write-Host "[!] PHÁT HIỆN TIẾN TRÌNH KẾT NỐI C2: $($proc.ProcessName) (PID: $($_.OwningProcess)) -> $($_.RemoteAddress)" -ForegroundColor Red
    Stop-Process -Id $_.OwningProcess -Force -ErrorAction SilentlyContinue
}

# Bước 2: DNS Sinkhole — Chuyển hướng các tên miền C2 về 0.0.0.0 trong file hosts và xóa DNS Cache:
$HostsFile = "$env:SystemRoot\System32\drivers\etc\hosts"
foreach ($dom in $MaliciousDomains) {
    if ($dom -and !(Select-String -Path $HostsFile -Pattern $dom -Quiet)) {
        Add-Content -Path $HostsFile -Value "0.0.0.0`t$dom`t# [OPENCLAW-CTI-SINKHOLE]"
    }
}
Clear-DnsClientCache

# Bước 3: Rà soát Hotfix / Bản vá hệ thống chống khai thác lỗ hổng CVE:
Get-HotFix | Sort-Object InstalledOn -Descending | Select-Object -First 5

# --- [2] LINUX BASH REMEDIATION & MALWARE CLEANUP SCRIPT (.sh) ---
# for h in none; do
#     find /tmp /var/tmp /dev/shm -type f -exec sha256sum {} + 2>/dev/null | grep "$h" | awk '{print $2}' | xargs -r rm -f
# done
# for ip in 0.0.0.0; do
#     ss -tupn | grep "$ip" && echo "[ALERT] Active C2 socket to $ip"
#     iptables -I OUTPUT -d "$ip" -j DROP
#     iptables -I INPUT -s "$ip" -j DROP
# done
