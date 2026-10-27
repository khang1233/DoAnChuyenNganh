# ĐỒ ÁN CHUYÊN NGÀNH: HỆ THỐNG CTI ĐA NGUỒN TỰ ĐỘNG HÓA & ĐÓNG GÓI KỸ NĂNG PHÒNG THỦ TÁC TỬ (AGENTIC DEFENSE SKILLS) VỚI GIẢI TRÌNH xAI

Hệ thống tình báo an ninh mạng (Cyber Threat Intelligence - CTI) tự động hóa toàn diện, tích hợp công cụ bóc tách thực thể kỹ thuật (IOCs), công cụ kiểm định độ tin cậy toán học (Trust Engine), cơ chế giải trình AI minh bạch (Explainable AI - xAI) và cơ chế đóng gói kỹ năng phòng thủ tác tử (**Agentic Defense Skill Package - `SKILL.md`**) cho các AI Coding Assistant và hệ thống phòng thủ đa tầng.

---

## 1. CÁC TÍNH NĂNG CỐT LÕI

- **Kho CTI Đa Nguồn Toàn Văn (99% Full Verbatim)**:
  - Tự động thu thập, chuẩn hóa từ 6 nguồn tình báo quốc tế: TheHackerNews, CISA US Gov, Kaspersky Securelist, SentinelOne Labs, Check Point Research, The DFIR Report.
  - Lưu trữ **7,373+ bài báo toàn văn nguyên bản** (giai đoạn 2024 - 2026), không cắt xén, cho phép tra cứu Ctrl+F khớp 100% văn bản gốc.
- **Học Tự Động & Trích Xuất Lai (Hybrid IOC Extraction)**:
  - Trích xuất và phân loại hơn **9,444+ chỉ số IOC kỹ thuật** (IP C2, DNS an toàn, CVE, SHA256, Defanged Domain).
  - Đối soát chéo với VirusTotal, AbuseIPDB, Shodan và CSDL SQLite nội bộ.
  - Phân loại rõ ràng: Địa chỉ IP độc hại (màu đỏ) vs. Địa chỉ IP hạ tầng công cộng / DNS an toàn (màu xanh lá cây, không chặn nhầm).
- **Thẩm Định Độ Tin Cậy Toán Học (Trust Engine)**:
  - Công thức tính điểm minh bạch:
    $$\text{Trust} = 0.35 \times S_{\text{Authority}} + 0.35 \times S_{\text{Consensus}} + 0.30 \times S_{\text{Evidence}} - S_{\text{FPRisk}}$$
  - Vượt qua kiểm thử vòng lặp kép (Dual-Loop Audit): **True Positive 100% & False Positive 0.0%**.
- **Giải Trình AI Minh Bạch Cấp Độ SOC Analyst (Explainable AI - xAI)**:
  - **Feature Attribution**: Phân tích đóng góp điểm số của từng yếu tố đầu vào.
  - **Grounding Citations**: Trích dẫn trực tiếp các đoạn văn bản chứng cứ trong bài báo gốc.
  - **Counterfactual Scenarios**: Phân tích phản thực tế ("Nếu IP là 8.8.8.8 thì quyết định đảo chiều như thế nào?").
  - **Causal Chain**: Chuỗi nhân quả 5 bước từ trích xuất thực thể đến đóng gói phòng thủ.
- **Phân Hệ Phạm Vi Mục Tiêu (Target Scopes)**:
  - **Scope A (Web & API Layer)**: Quét nhanh 15 phút/lần, bảo vệ OWASP Top 10, SQLi, RCE, Path Traversal.
  - **Scope B (Network & Perimeter C2)**: Quét 1 giờ/lần, theo dõi Botnet, C2 IP, DNS Sinkhole, Suricata DPI.
  - **Scope C (Endpoint & Identity)**: Quét 4 giờ/lần, phát hiện Webshell spawn, Ransomware, Wazuh SIEM, Sysmon.
  - **Scope D (Hardware, Firmware & Base Layer)**: Quét sâu tầng Base 24 giờ/lần, Firmware, BIOS/UEFI, ICS-CERT.
- **Đóng Gói Kỹ Năng Tác Tử (Agentic Defense Skill Package - `SKILL.md`)**:
  - Không chỉ dừng lại ở các dòng rule tĩnh cổ điển, hệ thống sinh ra file `SKILL.md` theo chuẩn tác tử AI.
  - Lập trình viên có thể nạp vào trợ lý AI (Google Antigravity, Cursor, Claude Code, GitHub Copilot) để tự động quét và sửa mã nguồn (Remediation SOP).

---

## 2. KIẾN TRÚC THƯ MỤC HỆ THỐNG

```
DoAnChuyenNganh/
├── 1_BAT_HE_THONG.bat                   # Kịch bản khởi động toàn bộ hệ thống
├── 2_TAT_HE_THONG.bat                   # Kịch bản tắt an toàn hệ thống
├── khang_sandbox_full_cti/
│   ├── live_dashboard_app.py            # FastAPI Web Server & SOC Dashboard (Port 8765)
│   ├── live_defense_orchestrator.py     # Điều phối viên phòng thủ & WAF Proxy (Port 8766)
│   ├── lam_automation_crawler.py        # Crawler đa nguồn trích xuất toàn văn 100%
│   ├── agentic_defense_skill_engine.py  # Động cơ thẩm định Trust Score, xAI & sinh SKILL.md
│   ├── phuc_core_ai_agent.py            # Trích xuất lai thực thể kỹ thuật (Hybrid IOCs)
│   ├── openclaw_firewall_bridge.py      # Cầu nối điều khiển tường lửa Windows Netsh
│   ├── enrich_all_corpus.py             # Kịch bản đa luồng làm giàu toàn bộ kho CTI
│   └── cti_multi_source_archive.sqlite  # CSDL SQLite chứa 7,450 bài báo và 9,444+ IOCs
├── ai-devsecops-agent/                  # Mô-đun tác tử AI DevSecOps chuyên sâu
├── docker_security_tool/                # Bộ công cụ quét và đánh giá bảo mật Docker
└── README.md
```

---

## 3. HƯỚNG DẪN KHỞI CHẠY VÀ SỬ DỤNG

### 3.1. Yêu cầu môi trường
- Hệ điều hành: Windows 10 / 11 / Windows Server
- Python 3.10 trở lên
- Quyền Administrator (để áp dụng quy tắc tường lửa Windows Netsh khi cần)

### 3.2. Khởi động nhanh (1-Click)
Chạy file batch ở thư mục gốc:
```cmd
1_BAT_HE_THONG.bat
```
Hệ thống sẽ tự động khởi động:
1. **SOC Live Dashboard**: Truy cập tại `http://localhost:8765`
2. **WAF Reverse Proxy Gateway**: Lắng nghe tại `http://localhost:8766`

### 3.3. Tắt hệ thống an toàn
```cmd
2_TAT_HE_THONG.bat
```

---

## 4. API ENDPOINTS CHÍNH

- `GET /api/articles`: Lấy danh sách bài báo CTI kèm thống kê IOC.
- `GET /api/articles/details/{article_id}`: Chi tiết bài báo, toàn văn, điểm Trust Score và vết giải trình xAI.
- `GET /api/master-defense-matrix?scope={scope_id}`: Ma trận phòng thủ tổng hợp theo phân hệ (Web, Network, Endpoint, Base).
- `GET /api/defense/skill/export?scope={scope_id}`: Xuất gói kỹ năng tác tử `SKILL_<scope>.md`.
- `POST /api/defense/tools/firewall-apply`: Áp dụng quy tắc chặn vào Windows Defender Firewall.
- `POST /api/defense/tools/firewall-rollback`: Khôi phục trạng thái tường lửa ban đầu.
