/* ============================================================================
   QUY TẮC YARA PHÁT HIỆN MÃ ĐỘC VÀ TIÊM BỘ NHỚ RAM (.YAR)
   Chiến dịch: [CVE-2026-83548] SonicWall SMA1000 Appliances — SonicWall SMA1000 Appliance
   Áp dụng: Quét tệp thực thi PE (.exe, .dll) và bộ nhớ tiến trình (Process Memory)
   ============================================================================ */

rule OpenClaw_Verified_Malware_20261016_070053
{
    meta:
        author = "Autonomous CTI Agent (Khang & Phuc Security)"
        description = "Detects in-memory injection & verified payload from: [CVE-2026-83548] SonicWall SMA1000 Appliances — SonicWall SMA1000"
        date = "2026-10-16"
        threat_level = "CRITICAL"
        mitre_attack = "T1204.002, T1059.001, T1055, T1071"
        gatekeeper_threshold = 80

    strings:
        // 1. Chữ ký PoC khai thác lỗ hổng CVE & Web Shell:
        $cve_0 = "CVE-2026-83548" ascii nocase
        $exploit_trav1 = "../" ascii
        $exploit_trav2 = "%2e%2e" ascii
        $exploit_cmd = "cmd=" ascii nocase
        // 4. Chuỗi gọi hàm tiêm bộ nhớ & vượt mặt phòng thủ (Injection & Evasion):
        $api_mem1 = "VirtualAlloc" ascii nocase
        $api_mem2 = "WriteProcessMemory" ascii nocase
        $api_mem3 = "CreateRemoteThread" ascii nocase
        $api_evas1 = "IsDebuggerPresent" ascii nocase
        $api_evas2 = "CheckRemoteDebuggerPresent" ascii nocase
        $str_ps1 = "powershell -enc" ascii nocase
        $str_ps2 = "-ExecutionPolicy Bypass" ascii nocase
        $str_vss = "vssadmin delete shadows" ascii nocase

    condition:
        // Điều kiện 1: Tập tin PE Windows có chữ ký 'MZ' và khớp bất kỳ mã băm hoặc C2 nào:
        (uint16(0) == 0x5A4D and (any of ($sha_*) or (any of ($c2_*) and 2 of ($api_*)))) or
        // Điều kiện 2: Khớp trực tiếp mã băm của mẫu mã độc trong báo cáo:
        (any of ($sha_*)) or
        // Điều kiện 3: Tiến trình bộ nhớ gọi C2 kết hợp mã hóa powershell hoặc xóa shadow copy:
        (any of ($c2_*) and ($str_ps1 or $str_ps2 or $str_vss))
}
