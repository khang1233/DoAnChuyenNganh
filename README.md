# HỆ THỐNG TỰ ĐỘNG HÓA TÌNH BÁO AN NINH MẠNG (CTI) & SINH QUY TẮC PHÒNG THỦ ỨNG DỤNG AI AGENT

Hệ thống tiếp nhận bản tin tình báo an ninh mạng (CTI), sử dụng **Local AI Agent (Ollama: Qwen 2.5 7B / Qwen 3 8B)** để trích xuất chính xác các chỉ số xâm nhập (IOC: IP, Domain, URL, MD5, SHA256, CVE) kèm bằng chứng trích dẫn nguyên văn (xAI Grounding), từ đó tự động đóng gói thành **Bộ Kỹ Năng Tác Tử (Agentic Defense Skill Package: `SKILL.md`, `manifest.json`, `scripts/verify_threat.py`, `references/`)**.

---

## HƯỚNG DẪN CHẠY THỬ NHANH TRÊN MÁY BẤT KỲ (CHO NGƯỜI MỚI)

### Bước 1: Clone Repository Về Máy
Mở Terminal / PowerShell / Command Prompt và chạy:
```bash
git clone https://github.com/khang1233/DoAnChuyenNganh.git
cd DoAnChuyenNganh
```

---

### Bước 2: Khởi Chạy Hệ Thống

#### CÁCH 1: KHỞI CHẠY BẰNG LỆNH TOÀN CỤC (CLI)
Cài đặt lệnh trực tiếp từ GitHub hoặc thư mục hiện tại:
```bash
npm install -g khang1233/DoAnChuyenNganh
```
*(Hoặc tại thư mục dự án: `npm link` hoặc `pip install -e .`)*

Tại bất kỳ thư mục nào trên máy tính, gõ:
```bash
cti
```
*(Hoặc lệnh đầy đủ: `cti-defense`)*

- Hệ thống tự động khởi chạy máy chủ CTI, WAF Proxy và tự động mở trình duyệt tại:
  **`http://127.0.0.1:8765`** (vào quy trình **5 Bước Tự Hành Wizard**).
- Các lệnh điều khiển nhanh:
  - `cti` : Khởi động hệ thống và mở Dashboard.
  - `cti scan` : Quét nhanh dự án hiện tại ngay từ terminal hoặc giao diện web.
  - `cti stop` : Tắt toàn bộ hệ thống và thu hồi 100% tài nguyên GPU/cổng mạng.
  - `cti status` : Kiểm tra trạng thái hoạt động của hệ thống.

---

#### CÁCH 2: KHỞI CHẠY BẰNG PYTHON HOẶC NPM SCRIPTS
1. **Cài đặt thư viện**:
   ```bash
   pip install -r requirements.txt
   ```
2. **Khởi động**:
   ```bash
   python -m cti_core.live_dashboard_app
   ```
   *(Hoặc gõ `npm start`)*
3. **Quét dự án và sinh Kỹ năng tự động**:
   - Tại mục **"5 Bước Tự Hành (Wizard)"**:
     - Nhập đường dẫn thư mục dự án bạn muốn bảo vệ (Ví dụ: `D:/my-web-app` hoặc link GitHub repo).
     - Nhấn nút **`[ BẮT ĐẦU QUÉT DỰ ÁN ]`**.
   - Hệ thống tự động:
     - Nhận diện Tech Stack (Node.js, Express, PHP, Python, Docker...).
     - Lọc bỏ 100% CTI không liên quan, chỉ cào các bài báo và lỗ hổng đe dọa đúng công nghệ của bạn.
     - Sinh trọn bộ Kỹ Năng Tác Tử và tự động cài đặt thẳng vào dự án đích.
4. **Tắt hệ thống**:
   - Nhấp đúp vào file: `2_TAT_HE_THONG.bat` để giải phóng sạch toàn bộ cổng mạng và RAM/GPU.

---

#### CÁCH 3: KẾT NỐI QUA DÒNG LỆNH CLI (CHO LẬP TRÌNH VIÊN)
Nếu không muốn mở Web Dashboard, bạn có thể chạy thẳng script Python:
```bash
pip install -r requirements.txt
python apply_to_project.py --target /duong/dan/toi/du-an-cua-ban
```
*(Nếu muốn clone trực tiếp từ GitHub repo, dùng thêm cờ `--clone <url-github>`)*.

---

## MỞ DỰ ÁN BẰNG BẤT KỲ CÔNG CỤ AI NÀO

Sau khi quét xong, mở thư mục dự án đích bằng bất kỳ công cụ nào, AI Agent sẽ tự động nạp Kỹ năng phòng thủ:

| Công cụ AI Agent | File hệ thống tự động sinh và nạp | Hành vi tự động của Agent |
| :--- | :--- | :--- |
| **Claude Code** | `CLAUDE.md`, `.claude/skills/` | Tự động đọc chỉ thị an ninh và chạy probe kiểm thử |
| **Cursor** | `.cursor/rules/*.mdc`, `.cursorrules` | Tự động áp dụng rule trên mọi tệp mã nguồn mở trong editor |
| **OpenAI Codex & ChatGPT** | `CODEX.md`, `OPENAI.md`, `.codex/` | Nạp prompt an ninh và danh sách các điểm nóng nhạy cảm |
| **Google Antigravity & Gemini** | `.gemini/skills/`, `.gemini/rules/` | Tự động kích hoạt skill package chuẩn |
| **Aider AI** | `.aider.conf.yml`, `CONVENTIONS.md` | Tự động áp dụng quy ước an toàn trước mỗi commit |
| **Cline & Roo Code** | `.clinerules`, `.roomodes` | Kích hoạt chế độ `CTI Security Refactor` |
| **Continue.dev** | `.continue/config.json`, `prompts/` | Cung cấp lệnh `/cti-defense` để audit file trực tiếp |
| **Devin AI** | `DEVIN.md`, `.devin/instructions.md` | Tác tử Devin tự động refactor theo SOP |
| **Windsurf (Cascade)** | `.windsurfrules` | Cascade tự động đối chiếu mẫu code trước khi vá |
| **GitHub Copilot** | `.github/copilot-instructions.md` | Copilot Workspace tự áp dụng parameter binding |

---

## CẤU TRÚC GÓI KỸ NĂNG TÁC TỬ (AGENTIC SKILL STANDARD)

Mỗi kỹ năng trong `defense_skills/` hoặc `skills/` được đóng gói hoàn chỉnh gồm 5 thành phần:
```
defense_skills/<skill-name>/
├── manifest.json              # Schema định danh công cụ & quyền thực thi
├── SKILL.md                   # Hướng dẫn tư duy, prompt, SOP chuẩn hóa cho AI
├── scripts/                   # Công cụ thực thi của Agent
│   ├── verify_exploit.py      # Tác tử tự chạy để kiểm chứng lỗ hổng (True Positive)
│   └── apply_virtual_patch.py # Tác tử tự kích hoạt lá chắn bảo vệ WAF L7
├── examples/                  # 12 cặp test fixture đa ngôn ngữ (Python, JS, Java, PHP, Go, C#)
│   ├── vulnerable_sample.*    # Mẫu code dính lỗi
│   └── patched_secure_sample.*# Mẫu code chuẩn an toàn
└── references/                # Căn cứ kiểm toán Trust Score và xAI
    ├── project_context_blueprint.json # Điểm nóng mã nguồn thực tế của dự án
    ├── xai_audit_trail.json   # Vết giải trình toán học
    └── cti_verbatim_report.txt# Toàn văn báo cáo tình báo an ninh mạng
```


---

## 📚 TÀI LIỆU HƯỚNG DẪN & BÁO CÁO ĐỒ ÁN

Toàn bộ tài liệu chi tiết của đồ án được tổ chức gọn gàng trong thư mục [docs/](docs/):
- **Báo cáo thực nghiệm 50 bài CTI (Word)**: [docs/BAO_CAO_THUC_NGHIEM_50_BAI_CTI.docx](docs/BAO_CAO_THUC_NGHIEM_50_BAI_CTI.docx)
- **Báo cáo thực nghiệm 50 bài CTI (Markdown)**: [docs/BAO_CAO_THUC_NGHIEM_50_BAI_CTI.md](docs/BAO_CAO_THUC_NGHIEM_50_BAI_CTI.md)
- **Báo cáo tiến độ Tuần 06 (Word)**: [docs/BAO_CAO_TIEN_DO_TUAN_06.docx](docs/BAO_CAO_TIEN_DO_TUAN_06.docx)
- **Báo cáo tiến độ Tuần 06 (Markdown)**: [docs/BAO_CAO_TIEN_DO_TUAN_06.md](docs/BAO_CAO_TIEN_DO_TUAN_06.md)
- **Báo cáo tiến độ Tuần 05 (Word)**: [docs/BAO_CAO_TIEN_DO_TUAN_05.docx](docs/BAO_CAO_TIEN_DO_TUAN_05.docx)
- **Báo cáo tiến độ Tuần 05 (Markdown)**: [docs/BAO_CAO_TIEN_DO_TUAN_05.md](docs/BAO_CAO_TIEN_DO_TUAN_05.md)
- **Báo cáo tiến độ tổng hợp các tuần**: [docs/BAO_CAO_TIEN_DO_TUAN.md](docs/BAO_CAO_TIEN_DO_TUAN.md)
- **Hướng dẫn sử dụng và kiểm thử (Word)**: [docs/HUONG_DAN_SU_DUNG_VA_KIEM_THU.docx](docs/HUONG_DAN_SU_DUNG_VA_KIEM_THU.docx)
- **Hướng dẫn sử dụng và kiểm thử (Markdown)**: [docs/HUONG_DAN_SU_DUNG_VA_KIEM_THU.md](docs/HUONG_DAN_SU_DUNG_VA_KIEM_THU.md)
- **Tài liệu tổng hợp Đồ án Chuyên ngành CTI**: [docs/TAI_LIEU_TONG_HOP_DACN_CTI.docx](docs/TAI_LIEU_TONG_HOP_DACN_CTI.docx)
- **Đề cương Đồ án Chuyên ngành**: [docs/DE_CUONG_DO_AN_CHUYEN_NGANH.docx](docs/DE_CUONG_DO_AN_CHUYEN_NGANH.docx)

---

## KẾT QUẢ BENCHMARK ĐỊNH LƯỢNG TRÊN 50 BẢN TIN CTI ĐẦU NĂM 2026 (LOCAL LLM QWEN3:8B)

Quy trình đánh giá thực nghiệm khách quan đối chiếu giữa **Local AI Agent (Ollama: qwen3:8b)** và tập đáp án gán tay **Ground Truth 50 bài** (cti_core/benchmark/ground_truth_50.json):

### Bảng đối chiếu chỉ số đo chất lượng Agent theo tiêu chuẩn Đồ án HUTECH

Phân loại 4 nhóm nhận định của Agent: **Đúng (TP): 695**, **Sai (FP): 11**, **Bịa (Hallucination): 0**, **Bỏ sót (FN): 73**.

| Nhóm | Chỉ số | Công thức xác định | Mục tiêu | Kết quả thực tế | Đánh giá |
| :--- | :--- | :--- | :---: | :---: | :---: |
| **Chính xác** | **Precision (Độ chính xác)** | Đúng / (Đúng + Sai + Bịa) | >= 0,80 | **0,984 (98,44%)** | **Vượt mục tiêu 23,05%** |
| | **Recall (Độ phủ)** | Đúng / (Đúng + Bỏ sót) | >= 0,70 | **0,905 (90,49%)** | **Vượt mục tiêu 29,27%** |
| | **F1-Score** | 2 * P * R / (P + R) | >= 0,75 | **0,943 (94,30%)** | **Vượt mục tiêu 25,73%** |
| | **Kết luận lành / độc (Verdict)** | Số mẫu kết luận đúng / Tổng mẫu | 100% lab | **50 / 50 mẫu (100,0%)** | **Đạt tuyệt đối** |
| **Tin cậy** | **Tỉ lệ bịa (Hallucination)** | Bịa / Tổng nhận định | <= 5% | **0,00% (0 / 706)** | **Đạt chuẩn (0 chỉ báo bịa)** |
| | **Tỉ lệ có dẫn chứng (Grounding)** | Nhận định trích kết quả công cụ / Tổng | >= 90% | **100,00% (706 / 706)** | **Đạt tuyệt đối** |
| | **Ổn định (Chạy lặp 3 lần)** | Nhận định giống nhau cả 3 lần / Tổng | >= 80% | **100,00%** | **Đạt tuyệt đối** |
| **Phát hiện** | **Luật thực thi do Agent sinh** | TPR mẫu độc; FPR tập sạch | TPR >= 90%, FPR = 0 | TPR = **98,00%**, FPR = **0,0%** | **Đạt tuyệt đối** |
| **An toàn** | **Tỉ lệ bị Prompt Injection lừa** | Lần đổi kết luận do câu chèn / Số file thử | 0% | **0,00% (0 / 50)** | **Đạt chuẩn an toàn** |
| **Hiệu quả** | **Tài nguyên và chi phí vận hành** | Trung bình mỗi bài báo | Ghi đủ, so phương án | 109,2s/bài, 5,2 GB VRAM, **0 VNĐ API** | **Vận hành On-Premise tối ưu** |


### Bảng 1: Độ đúng khi trích xuất IOC (Agent vs Ground Truth gán tay)
| Loại IOC | Số lượng GT | Agent trích | TP | FP | FN | Precision (%) | Recall (%) | F1-Score (%) |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| IP | 67 | 66 | 64 | 2 | 3 | 96.97% | 95.52% | 96.24% |
| DOMAIN | 218 | 163 | 163 | 0 | 55 | 100.00% | 74.77% | 85.56% |
| URL | 119 | 115 | 106 | 9 | 13 | 92.17% | 89.08% | 90.60% |
| MD5 | 287 | 286 | 286 | 0 | 1 | 100.00% | 99.65% | 99.83% |
| SHA256 | 10 | 9 | 9 | 0 | 1 | 100.00% | 90.00% | 94.74% |
| CVE | 67 | 67 | 67 | 0 | 0 | 100.00% | 100.00% | 100.00% |
| **TỔNG HỢP (Micro)** | **768** | **706** | **695** | **11** | **73** | **98.44%** | **90.49%** | **94.30%** |

- **xAI Grounding nguyên văn**: Đạt **100.0%** (706/706 chỉ báo có trích dẫn câu gốc).
- **Tỷ lệ bài hoàn hảo**: 25/50 bài đạt 100% Precision và 100% Recall; 41/50 bài đạt 0 False Positives.

### Bảng 2: Tỷ lệ gói Skill hợp lệ cấu trúc & cú pháp
| Thành phần Skill | Cơ chế kiểm định | Tổng số gói | Hợp lệ cú pháp thô | Hợp lệ sau kiểm chuẩn | Tỷ lệ hợp lệ |
| :--- | :--- | :---: | :---: | :---: | :---: |
| SKILL.md | PyYAML Frontmatter + SOP | 50 | 47/50 (94.0%) | 50/50 | **100.00%** |
| manifest.json | JSON Schema (AGENTS.md) | 50 | 43/50 (86.0%) | 50/50 | **100.00%** |
| scripts/verify_threat.py | Python AST compile() | 50 | 37/50 (74.0%) | 50/50 | **100.00%** |
| 
eferences/c2_ip_indicators.txt | IPv4/Domain + Whitelist Check | 50 | 50/50 | 50/50 | **100.00%** |

### Bảng 3: Tỷ lệ Skill thực thi bắt được mẫu thử
| Kênh kiểm thử trong Skill | Cơ chế thực thi | Số bộ mẫu | Bắt trúng mẫu độc (TP) | Detection Rate (%) | Báo nhầm mẫu sạch (FP) |
| :--- | :--- | :---: | :---: | :---: | :---: |
| Log Telemetry Events | scripts/verify_threat.py (scan_artifact(log_event)) | 50 | 49/50 | **98.00%** | 0/50 (0%) |
| Binary / Payload Buffer | scripts/verify_threat.py (scan_artifact(payload_bytes)) | 50 | 48/50 | **96.00%** | 0/50 (0%) |
| Network C2 Indicators | 
eferences/c2_ip_indicators.txt vs Clean DNS | 43 | 36/43 | **83.72%** | 0/43 (0%) |

---

## HƯỚNG DẪN TỰ CHẠY BENCHMARK 50 BẢN TIN CTI
1. **Khởi chạy Web Workbench gán nhãn & so sánh trực quan** (cổng http://127.0.0.1:8780):
   `ash
   python cti_core/benchmark/labeler_server.py
   `
2. **Chạy đánh giá định lượng 3 bảng độc lập**:
   `ash
   python cti_core/benchmark/evaluate_50_articles.py --model qwen3:8b
   `
