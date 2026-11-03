/* ============================================================================
   QUY TẮC YARA PHÁT HIỆN MÃ ĐỘC VÀ TIÊM BỘ NHỚ RAM (.YAR)
   Chiến dịch: Tricks from the Past deployed via signed ChatGPT and Claude binaries
   Áp dụng: Quét tệp thực thi PE (.exe, .dll) và bộ nhớ tiến trình (Process Memory)
   ============================================================================ */

rule OpenClaw_Verified_Malware_20261028_090141
{
    meta:
        author = "Autonomous CTI Agent (Khang & Phuc Security)"
        description = "Detects in-memory injection & verified payload from: Tricks from the Past deployed via signed ChatGPT and Claude binar"
        date = "2026-10-28"
        threat_level = "CRITICAL"
        mitre_attack = "T1204.002, T1059.001, T1055, T1071"
        gatekeeper_threshold = 80

    strings:
        // 2. Chữ ký mã băm nhị phân (Malware Hashes):
        $sha_0 = "b5c2d20623d4e6647d06a42864edd8629f82c5c384b243fdaeeeca24b3873d64" ascii nocase
        $sha_1 = "1d0d1368b4d53f3a6322cf40e84e63db" ascii nocase
        $sha_2 = "dcde1f56048fa18657dc4820397592f7" ascii nocase
        // 3. Hạ tầng C2 và Tên miền phát tán:
        $c2_ip_0 = "51.89.231.85" ascii wide
        $c2_ip_1 = "51.89.228.250" ascii wide
        $c2_dom_0 = "GitHub.io" ascii wide nocase
        $c2_dom_1 = "outlook.com" ascii wide nocase
        $c2_dom_2 = "digit.dedyn.io" ascii wide nocase
        $c2_dom_3 = "dedyn.io" ascii wide nocase
        $c2_dom_4 = "gpt-5-6.github.io" ascii wide nocase
        $c2_dom_5 = "opus-5-0.github.io" ascii wide nocase
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
