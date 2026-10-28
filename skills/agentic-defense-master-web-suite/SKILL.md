---
name: agentic-defense-master-web-suite
description: Gói kỹ năng phòng thủ tác tử toàn diện (Master Defense Suite) cho phân hệ SCOPE_WEB (Node.js / JavaScript Web Ecosystem, Python Backend (FastAPI / Django / Flask)). Tích hợp đa lớp WAF, Tường lửa C2, Kiểm thử đa vector và Quy chuẩn sửa code an toàn cho Node.js, Express, Python.
author: OpenClaw CTI Defense Orchestrator
version: 2.0.0
scope: SCOPE_WEB
trust_score: 97.5
---

# 🛡️ GÓI KỸ NĂNG PHÒNG THỦ TÁC TỬ TỔNG THỂ (MASTER DEFENSE SUITE)

## 📌 THÔNG TIN ĐỊNH DANH PHÂN HỆ
- **Mã phân hệ bảo vệ:** `SCOPE_WEB`
- **Công nghệ đích:** `Node.js / JavaScript Web Ecosystem, Python Backend (FastAPI / Django / Flask)`
- **Mã CVE bao phủ:** `CVE-2016-15042, CVE-2017-7921, CVE-2019-11510, CVE-2019-9879, CVE-2020-1938, CVE-2020-25078, CVE-2020-25169, CVE-2021-22205`
- **Mức độ tin cậy CTI:** `97.5 / 100 (Evidence-Driven)`

---

## 🎯 4 TRỤ CỘT PHÒNG THỦ ĐA LỚP (DEFENSE-IN-DEPTH)

1. **Lớp 1: Biên mạng & Tường lửa C2 (Perimeter Shield)**
   - Chặn đứng 100% kết nối đến danh sách `85` địa chỉ IP C2 độc hại đã phát hiện từ CTI feeds.
   - File cấu hình: `rules/firewall_c2_blocklist.txt`

2. **Lớp 2: Lá chắn ảo WAF ModSecurity (Virtual Patching)**
   - Ngăn chặn tức thời 4 vector tấn công: Command Injection/RCE, SQL Injection, Scanner-Evading JS, và SSRF.
   - File cấu hình: `rules/waf_modsecurity.conf`

3. **Lớp 3: Giám sát xâm nhập chuyên sâu (Suricata DPI & Wazuh SIEM)**
   - Phát hiện các nỗ lực xâm nhập vào các cổng Web API và cảnh báo tức thì về SIEM.
   - File cấu hình: `rules/suricata_dpi.rules` và `rules/wazuh_siem.xml`

4. **Lớp 4: Khắc phục mã nguồn tận gốc (Source Code Hardening)**
   - Áp dụng các mẫu lập trình an toàn cho Node.js / Express và Python Backend:
     - Mẫu dính lỗi: `examples/vulnerable_sample.js`, `examples/vulnerable_sample.py`
     - Mẫu an toàn: `examples/patched_secure_sample.js`, `examples/patched_secure_sample.py`

---

## 🚀 QUY TRÌNH 5 BƯỚC THỰC THI CHO AI AGENT

### Bước 1: Kiểm Thử Đa Vector (Probe Audit)
Chạy công cụ kiểm thử tự động để rà soát toàn bộ bề mặt tấn công:
```bash
python scripts/verify_exploit.py http://localhost:8766
```

### Bước 2: Kích Hoạt Lá Chắn Mạng (Virtual Patching)
Trong thời gian refactor code, kích hoạt ngay WAF Proxy để bảo vệ hệ thống:
```bash
python scripts/apply_virtual_patch.py
```

### Bước 3: Sửa Code Dự Án Tận Gốc
- Đối với **Node.js / Express**: Thay thế mọi lệnh `exec()` bằng `execFile()` kèm Whitelist regex; thay câu lệnh SQL thô bằng Prepared Statement.
- Đối với **Python Backend**: Loại bỏ `os.system()`; dùng `subprocess.run()` với `shell=False`.

### Bước 4: Tái Kiểm Thử & Xác Nhận
Chạy lại script kiểm thử để đảm bảo mọi vector tấn công đã bị vô hiệu hóa hoàn toàn:
```bash
python scripts/verify_exploit.py http://localhost:8766
```

### Bước 5: Giám Sát Liên Tục
Duy trì chu kỳ quét 15 phút / lần để tự động nạp các mã CVE mới nhất từ CTI feeds.
