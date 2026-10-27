# HỆ THỐNG CTI ĐA NGUỒN TỰ ĐỘNG HÓA & ĐÓNG GÓI KỸ NĂNG PHÒNG THỦ TÁC TỬ (AGENTIC DEFENSE SKILL)

Hệ thống tự động cào 7,450+ bài báo tình báo an ninh mạng (CTI), trích xuất 9,440+ chỉ số kỹ thuật (IOCs), tính toán độ tin cậy toán học **Trust Score** (>90đ, 0% False Positive) và đóng gói thành các **Bộ Kỹ Năng Tác Tử (Agentic Skill Package)** để AI Agent tự động vá mã nguồn hoặc nạp trực tiếp vào Tường lửa/WAF.

---

## 🚀 CÁCH ÁP DỤNG VÀO DỰ ÁN BẤT KỲ (CHỈ CẦN 1 BƯỚC)

Nếu bạn (hoặc bạn của bạn) có một dự án Web/App và muốn trợ lý AI (Cursor, Antigravity, Claude Code, Copilot) tự động bảo vệ hệ thống:

### Bước 1: Ném link GitHub này cho AI Agent hoặc Clone về máy
```bash
git clone https://github.com/khang1233/DoAnChuyenNganh.git
```

### Bước 2: Chạy lệnh kết nối tự động tới thư mục dự án của bạn
```bash
python DoAnChuyenNganh/apply_to_project.py --target /duong/dan/toi/du-an-cua-ban
```

### Kết quả tự động diễn ra:
1. **Tự động nhận diện công nghệ**: Tự phát hiện dự án của bạn dùng PHP, Node.js, Python hay Docker.
2. **Tự động nạp Skill**: Copy trọn bộ gói kỹ năng tác tử vào đúng thư mục AI của bạn:
   - `.gemini/skills/` (cho Google Antigravity)
   - `.cursor/rules/` (cho Cursor)
   - `defense_skills/` (cho Claude Code / Copilot / Developer)
3. **Tự động sinh hướng dẫn vá lỗi**: Tạo file `AGENT_REMEDIATION_GUIDE.md` trong dự án.
4. **AI Agent tự sửa mã nguồn**: Khi bạn mở Cursor/Antigravity trong dự án của mình, AI Agent sẽ tự động đọc `SKILL.md`, đối chiếu mã nguồn của bạn với mẫu `examples/vulnerable_sample.php` và tự động refactor code sang chuẩn an toàn `examples/patched_secure_sample.php`.

---

## 🛡️ CẤU TRÚC BỘ KỸ NĂNG PHÒNG THỦ TRÊN GITHUB (`skills/`)

Mỗi kỹ năng được đóng gói theo chuẩn thư mục tác tử quốc tế:
```
skills/agentic-defense-cve-2026-109618-php2shell/
├── manifest.json              # Metadata định danh, phiên bản, quyền thực thi
├── SKILL.md                   # BỘ NÃO: Prompt chỉ dẫn, YAML metadata, quy trình SOP
├── scripts/                   # TAY CHÂN: Công cụ Python Agent tự gọi bằng tool-call
│   ├── verify_exploit.py      # Tool kiểm thử xem máy chủ có bị dính lỗ hổng không
│   └── apply_virtual_patch.py # Tool nạp quy tắc WAF & Tường lửa tự động
├── rules/                     # CHỮ KÝ PHÒNG VỆ: Cấu hình nạp trực tiếp vào Engine
│   ├── waf_modsecurity.conf   # Quy tắc WAF ModSecurity v3 (chặn HTTP RCE)
│   ├── suricata_dpi.rules     # Quy tắc Suricata L4-L7 Deep Packet Inspection
│   ├── wazuh_siem.xml         # Quy tắc Wazuh SIEM giám sát Endpoint
│   └── firewall_c2_blocklist.txt # Danh sách IP C2 chặn trên OS
├── references/                # CƠ SỞ CHỨNG CỨ: Tri thức đối soát triệt tiêu ảo giác
│   ├── cti_verbatim_report.txt# Toàn văn bài báo gốc (Ctrl+F khớp 100%)
│   ├── stix21_bundle.json     # Dữ liệu chuẩn quốc tế OASIS STIX 2.1
│   ├── xai_audit_trail.json   # Vết giải trình xAI (Feature Attribution, Grounding)
│   └── trust_score_breakdown.json # Phân rã công thức toán học Trust Score
└── examples/                  # MẪU ĐỐI CHỨNG: Dành cho Developer & AI Agent
    ├── vulnerable_sample.php  # Mẫu code dính lỗi trước khi vá
    └── patched_secure_sample.php # Mẫu code đã được chuẩn hóa an toàn
```

---

## ⚙️ KHỞI CHẠY HỆ THỐNG TRỰC TIẾP (SOC DASHBOARD & TƯỜNG LỬA)

Nếu muốn bật bảng điều khiển trung tâm và kích hoạt Tường lửa / WAF trực tiếp:

1. **Khởi động 1-Click**:
   Chạy file `1_BAT_HE_THONG.bat` ở thư mục gốc:
   - **SOC Live Dashboard**: Mở trình duyệt truy cập `http://localhost:8765`
   - **WAF Reverse Proxy**: Lắng nghe tại `http://localhost:8766`
2. **Áp dụng Tường lửa OS**:
   - Trên Dashboard, tab **Tường lửa & WAF** -> Bấm **"Kích hoạt Tường lửa Windows"** để chặn ngay 9,440+ IP C2 ở tầng Kernel.
   - Bấm **"Khôi phục (Rollback)"** bất cứ khi nào muốn gỡ bỏ sạch sẽ.
3. **Tắt an toàn 1-Click**:
   Chạy file `2_TAT_HE_THONG.bat`.

---

## 📊 SỐ LIỆU ĐÃ KIỂM CHỨNG TRONG CƠ SỞ DỮ LIỆU
- **Tổng số bài báo toàn văn**: 7,373 / 7,450 bài (99.0% toàn văn nguyên bản).
- **Tổng số chỉ số kỹ thuật IOC**: 9,444 chỉ số (IP C2, DNS an toàn, CVE, SHA256).
- **Điểm toán học Trust Score**: Đạt trên 93.6 / 100 điểm, vượt qua bài kiểm toán vòng lặp kép (True Positive 100%, False Positive 0.0%).
