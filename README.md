# HỆ THỐNG TỰ ĐỘNG HÓA TÌNH BÁO AN NINH MẠNG (CTI) & ĐÓNG GÓI KỸ NĂNG TÁC TỬ (AGENTIC DEFENSE SKILLS)

Hệ thống tự động phân tích mã nguồn dự án mục tiêu, đối soát với kho tri thức tình báo an ninh mạng (CTI), thẩm định độ tin cậy toán học **Trust Score** (>90đ, 0% False Positive) và đóng gói thành các **Bộ Kỹ Năng Tác Tử (Agentic Skill Package)** hỗ trợ chuẩn bản địa cho **15 nền tảng AI Coding Agent lớn nhất thế giới** (Claude Code, Cursor, Codex, Antigravity, Aider, Devin, Windsurf, Copilot...).

---

## HƯỚNG DẪN CHẠY THỬ NHANH TRÊN MÁY BẤT KỲ (CHO NGƯỜI MỚI)

### Bước 1: Clone Repository Về Máy
Mở Terminal / PowerShell / Command Prompt và chạy:
```bash
git clone https://github.com/khang1233/DoAnChuyenNganh.git
cd DoAnChuyenNganh
```

---

### Bước 2: Chọn Cách Khởi Chạy

#### CÁCH 1: KHỞI CHẠY BẰNG LỆNH GLOBAL QUA NPM (TIỆN LỢI NHẤT — GÕ TÊN TỪ BẤT KỲ ĐÂU)
Chỉ cần chạy lệnh liên kết 1 lần duy nhất:
```bash
npm link
```
*(Hoặc cài đặt toàn cục: `npm install -g .`)*

Từ lần sau trở đi, tại bất kỳ thư mục nào trên máy tính (Terminal, PowerShell, CMD), bạn chỉ cần gõ tên:
```bash
cti-defense
```
*(Hoặc viết tắt: `cti`)*

- Hệ thống sẽ **tự động khởi chạy** máy chủ CTI, WAF Proxy và **tự động mở trình duyệt** tại:
  **`http://127.0.0.1:8765`** (vào ngay **Bước 1: Quét Dự Án**).
- Các lệnh điều khiển nhanh:
  - `cti-defense` hoặc `cti` : Khởi động hệ thống và mở Dashboard.
  - `cti stop` : Tắt toàn bộ hệ thống và giải phóng cổng mạng.
  - `cti status` : Kiểm tra trạng thái hệ thống (Online / Offline).

---

#### CÁCH 2: KHỞI CHẠY BẰNG FILE BATCH 1-CLICK (KHÔNG CẦN CÀI NPM)
1. **Cài đặt thư viện (chỉ cần làm 1 lần đầu)**:
   - Nhấp đúp vào file: `0_CAI_DAT_MOI_TRUONG.bat` (hoặc gõ `pip install -r requirements.txt`).
2. **Bật toàn bộ hệ thống**:
   - Nhấp đúp vào file: `1_BAT_HE_THONG.bat`.
   - Hệ thống sẽ tự động bật Live Server, WAF Proxy cổng 8766 và **tự động mở trình duyệt** tại:
     **`http://127.0.0.1:8765`**
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

#### CÁCH 2: KẾT NỐI QUA DÒNG LỆNH CLI (CHO LẬP TRÌNH VIÊN)
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
