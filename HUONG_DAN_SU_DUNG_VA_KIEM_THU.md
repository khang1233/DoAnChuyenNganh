# TÀI LIỆU HƯỚNG DẪN SỬ DỤNG VÀ KỊCH BẢN KIỂM THỬ HỆ THỐNG
## HỆ THỐNG AN NINH MẠNG TỰ HÀNH TỪ TÌNH BÁO MỐI ĐE DỌA CTI (AUTONOMOUS CTI AGENTIC DEFENSE)

---

## 1. GIỚI THIỆU TỔNG QUAN

Hệ thống **Autonomous CTI Agentic Defense** là giải pháp an ninh mạng tự hành thế hệ mới dành cho lập trình viên và kỹ sư DevSecOps. Hệ thống giải quyết bài toán cốt lõi: **Biến các thông tin an ninh mạng thô từ báo cáo quốc tế (CTI) thành các hành động phòng thủ thực thi tức thời trên mã nguồn dự án**.

### 1.1. Các Thành Phần Chính
- **Bộ Cào và Lọc Tình Báo Tự Động (CTI Multi-Source Engine)**: Tự động thu thập dữ liệu an ninh mạng từ các nguồn uy tín thế giới (TheHackerNews, CISA US-CERT, Check Point Research, BleepingComputer, The DFIR Report).
- **Bộ Quét Mã Nguồn Chuyên Sâu (Codebase Inspector)**: Đọc cây AST, phân tích phiên bản Runtime môi trường (Python 3.14, Node.js 20+, PHP 8.2), định vị các điểm nóng nhạy cảm (Sensitive Sinks: exec, eval, system).
- **Tác Tử AI So Khớp & Đóng Gói Kỹ Năng (Threat Matcher & Agentic Skill Synthesizer)**: Đối chiếu ngữ cảnh dự án với kho tri thức, kích hoạt cảnh báo đỏ khi phát hiện lỗi trùng phiên bản, và tự động sinh gói kỹ năng phòng thủ đa nền tảng (SKILL.md, rules, scripts).
- **Lá Chắn Mạng Trực Tiếp (WAF Reverse Proxy & Firewall)**: Kích hoạt ModSecurity WAF và Tường lửa Windows Blocklist ngăn chặn ngay lập tức các địa chỉ IP C2 độc hại.
- **Tự Động Vá Mã Nguồn & Tái Kiểm Thử (Auto-Remediation & Verification)**: Tự động chuẩn hóa mã nguồn, triệt tiêu lỗ hổng (True Positive = 0) và đảm bảo không gây gián đoạn nghiệp vụ (False Positive = 0.0%).

### 1.2. Các Cổng Mạng Và Địa Chỉ Truy Cập Mặc Định
- **Giao diện Web Quản trị (Dashboard)**: http://127.0.0.1:8765
- **WAF Reverse Proxy L7 (Lá chắn bảo vệ)**: http://127.0.0.1:8766
- **Ollama GPU Server (Nếu có)**: http://127.0.0.1:11434

---

## 2. YÊU CẦU MÔI TRƯỜNG VÀ CÀI ĐẶT

### 2.1. Yêu Cầu Phần Cứng & Phần Mềm
- **Hệ điều hành**: Windows 10 / Windows 11 (hỗ trợ cả Linux và macOS).
- **Python**: Phiên bản 3.10 trở lên (khuyến nghị Python 3.10 đến 3.14).
  Lưu ý quan trọng: Khi cài đặt Python, bắt buộc phải tích chọn vào ô "Add Python to PATH".
- **Node.js**: Phiên bản 16 trở lên (dùng để liên kết lệnh dòng lệnh cti).
- **RAM**: Tối thiểu 4 GB (khuyến nghị 8 GB trở lên).

### 2.2. Các Bước Cài Đặt Ban Đầu (Chỉ thực hiện 1 lần duy nhất)

#### Bước 1: Mở cửa sổ dòng lệnh CMD
Nhấn phím Windows + R, gõ cmd, rồi chuyển vào thư mục chứa đồ án:
```bash
cd /d D:\mkhang\DoAnChuyenNganh
```

#### Bước 2: Cài đặt các gói thư viện Python cần thiết
Chạy lệnh sau để cài đặt toàn bộ phụ thuộc:
```bash
pip install -r requirements.txt
```

#### Bước 3: Đăng ký lệnh CLI toàn cục trên máy tính
Chạy lệnh liên kết:
```bash
npm link
```
Sau khi chạy xong lệnh này, lệnh cti và cti-defense đã được cài đặt vào hệ thống toàn cục của Windows. Bạn có thể mở CMD ở bất kỳ thư mục nào trên máy tính và gõ cti để sử dụng.

---

## 3. HƯỚNG DẪN KHỞI ĐỘNG VÀ VẬN HÀNH

Hệ thống hỗ trợ 2 phương thức vận hành linh hoạt:

### Cách 1: Sử Dụng Lệnh Dòng Lệnh CLI (Khuyến nghị)
Bạn chỉ cần mở CMD ngay tại **thư mục dự án bạn muốn bảo vệ** (ví dụ: target_projects\My_Website hoặc bất kỳ dự án web nào trên máy tính của bạn):
```bash
cti
```
(Hoặc có thể gõ cti-defense)

**Hệ thống sẽ tự động**:
1. Nhận diện đường dẫn thư mục hiện tại của bạn.
2. Khởi động Web Dashboard và WAF Reverse Proxy chạy ngầm.
3. In ra thông tin trạng thái và đường link truy cập.
4. Tự động mở trình duyệt Web tại http://127.0.0.1:8765.

**Cách tắt hệ thống**:
- Nhấn tổ hợp phím Ctrl + C tại cửa sổ CMD đang chạy; hoặc:
- Mở một CMD mới và gõ:
```bash
cti stop
```

### Cách 2: Sử Dụng File Batch 1-Click
- **Bật hệ thống**: Click đúp chuột vào file 1_BAT_HE_THONG.bat ở thư mục gốc. Hệ thống tự kiểm tra môi trường, bật server và mở trình duyệt.
- **Tắt hệ thống**: Click đúp chuột vào file 2_TAT_HE_THONG.bat. Hệ thống sẽ giải phóng toàn bộ tiến trình, giải phóng bộ nhớ RAM, GPU và đóng các cổng mạng 8765, 8766 ngay lập tức.

---

## 4. KỊCH BẢN KIỂM THỬ DÀNH CHO TESTER (STEP-BY-STEP)

Dưới đây là 5 kịch bản kiểm thử mẫu để bạn bè / tester kiểm tra toàn diện chức năng của hệ thống:

### KỊCH BẢN 1: QUY TRÌNH PHÒNG THỦ TỰ HÀNH 5 BƯỚC (WIZARD FLOW)
**Mục tiêu**: Kiểm tra tính năng phân tích mã nguồn lần đầu, trích xuất lỗ hổng và sinh bộ kỹ năng phòng thủ.

- **Bước 1**: Mở trình duyệt tại http://127.0.0.1:8765. Giao diện tự động mở mục 5 Bước Tự Hành (Wizard) và khóa vào thư mục dự án mục tiêu.
- **Bước 2**: Nhấn nút [ BẮT ĐẦU QUÉT DỰ ÁN ].
  Quan sát: Terminal hiển thị tiến trình Tác tử AI đọc cây cú pháp AST, nhận diện ngôn ngữ, framework và các Sensitive Sinks (exec, eval, system).
- **Bước 3**: Xem kết quả phân tích tại Bước 2:
  Kiểm tra: Hệ thống hiển thị Ngôn ngữ, Framework, Phiên bản Runtime (ví dụ: Python 3.14, PHP 8.2), danh sách các dòng code nhạy cảm và Phân hệ bảo vệ (Scope A: Web & API Layer).
- **Bước 4**: Nhấn nút chuyển sang Bước 3 (Cào báo CTI). Chọn mốc thời gian (1 năm, 3 năm hoặc 5 năm). Nhấn [ BẮT ĐẦU CÀO & ĐỐI CHIẾU ].
  Quan sát: Live Stream nhật ký tác tử AI phân tích, đối chiếu chéo; nếu phát hiện bài báo khớp đúng phiên bản runtime của dự án, hệ thống sẽ kích hoạt dòng cảnh báo đỏ khẩn cấp và hiển thị các chỉ số IOC (IP C2, CVE, Domain).
- **Bước 5**: Nhấn nút chuyển sang Bước 4 (Sinh Bộ Kỹ Năng).
  Quan sát: Hệ thống tự động sinh gói kỹ năng agentic-defense-master-web-suite trực tiếp vào thư mục dự án và đồng bộ tới 15 nền tảng AI Agent (Claude, Cursor, Gemini, Copilot...).
- **Bước 6**: Chuyển sang Bước 5 (Kiểm thử & Vá mã nguồn):
  1. Bấm nút kiểm thử [ Chạy Thử Probe Kiểm Tra Lỗ Hổng ]: Terminal trả về kết quả True Positive (xác nhận endpoint có lỗi RCE).
  2. Bấm nút [ Kích Hoạt Lá Chắn WAF & Firewall ]: Bật lá chắn mạng tức thời.
  3. Bấm nút [ Tự Động Vá Mã Nguồn ]: Hệ thống tự sửa code PHP/JS sang cơ chế Whitelist an toàn và tái kiểm thử xác nhận True Positive = 0.

### KỊCH BẢN 2: KIỂM THỬ LƯU TRỮ VÀ NHẬN DIỆN DỰ ÁN ĐÃ BẢO VỆ
**Mục tiêu**: Kiểm tra khả năng tự động ghi nhớ trạng thái dự án thông qua tệp .cti_defense.json.

- **Bước 1**: Sau khi hoàn thành Kịch bản 1, tắt hệ thống bằng cti stop hoặc 2_TAT_HE_THONG.bat.
- **Bước 2**: Mở CMD tại chính thư mục dự án đó và gõ cti.
- **Bước 3**: Quan sát giao diện Web khi mở lên:
  - Hệ thống nhận diện tệp .cti_defense.json.
  - Hiển thị banner màu xanh lá: [DỰ ÁN ĐÃ BẢO VỆ] kèm tên dự án, phân hệ Scope, tên kỹ năng tác tử và thời gian cấu hình.
  - Tự động chuyển thẳng vào Kho Kỹ Năng Tác Tử (Agentic Skills) hoặc Bảng Điểm IOC, không bắt quét lại từ đầu.
- **Bước 4**: Thử nghiệm nút [ Quét Lại Dự Án ] trên banner để kiểm tra tính năng Reset và cấu hình lại.

### KỊCH BẢN 3: KIỂM THỬ TÍNH ĐỘC LẬP KHI CHUYỂN DỰ ÁN MỚI
**Mục tiêu**: Kiểm tra hệ thống có xử lý độc lập giữa các dự án khác nhau trên cùng một máy hay không.

- **Bước 1**: Tạo một thư mục rỗng mới hoặc mở một thư mục dự án khác (ví dụ: target_projects\demo_vulnerable_php_app).
- **Bước 2**: Mở CMD tại thư mục đó và gõ cti.
- **Bước 3**: Quan sát giao diện Web:
  - Hệ thống phát hiện thư mục này chưa có cấu hình bảo vệ.
  - Tự động mở mục Wizard Bước 1 và khóa đúng vào đường dẫn của thư mục mới này.
  - Người dùng có thể tiến hành quét và sinh bộ kỹ năng độc lập cho riêng dự án mới mà không ảnh hưởng tới dự án cũ.

### KỊCH BẢN 4: KIỂM THỬ LÁ CHẮN WAF REVERSE PROXY L7
**Mục tiêu**: Xác minh WAF Proxy L7 chặn đứng payload tấn công khai thác.

- **Bước 1**: Đảm bảo hệ thống đang bật (WAF đang hoạt động tại cổng 8766).
- **Bước 2**: Mở trình duyệt và truy cập gói tin bình thường:
  http://127.0.0.1:8766/
  Kết quả: Trang web hiển thị phản hồi bình thường.
- **Bước 3**: Gửi một gói tin mang vector tấn công Remote Code Execution hoặc SQL Injection:
  http://127.0.0.1:8766/?cmd=cat%20/etc/passwd
  Kết quả: WAF Reverse Proxy L7 chặn đứng ngay lập tức với mã lỗi 403 Forbidden và thông báo tấn công bị từ chối.

### KỊCH BẢN 5: KIỂM THỬ TRỢ LÝ TRÒ CHUYỆN AI AGENT
**Mục tiêu**: Kiểm tra khả năng tra cứu chỉ số an ninh mạng bằng ngôn ngữ tự nhiên.

- **Bước 1**: Nhấp vào tab Chat AI Agent trên thanh điều hướng đầu trang.
- **Bước 2**: Bấm các nút câu hỏi mẫu có sẵn hoặc nhập nội dung tùy ý:
  - "Kiểm tra mức độ nguy hiểm của IP 43.134.165.205"
  - "Liệt kê các lỗ hổng CVE nguy hiểm nhất trong kho bài báo"
- **Bước 3**: Quan sát phản hồi của AI Agent:
  - Phản hồi bằng tiếng Việt chuẩn mực, có căn cứ trích dẫn rõ ràng từ 5 nguồn dữ liệu tình báo CTI (OTX, AbuseIPDB, Shodan, Abuse.ch, GreyNoise).

---

## 5. BẢNG TIÊU CHUẨN ĐÁNH GIÁ CHẤT LƯỢNG (EVALUATION MATRIX)

Khi nghiệm thu hoặc kiểm thử đồ án, tester có thể đối chiếu theo bảng tiêu chí sau:

| Tiêu Chí | Yêu Cầu Đạt Chuẩn | Trạng Thái Hệ Thống |
| :--- | :--- | :--- |
| Tính Tự Hành (Autonomous) | Tự động hóa từ cào báo đến phân tích, cấu hình WAF và vá code không cần can thiệp thủ công | ĐẠT (100% Khép kín) |
| Bảo Vệ Ngữ Cảnh Dự Án | Tự động nhận diện cây AST, phiên bản runtime (Python, Node, PHP) và Sensitive Sinks | ĐẠT (Độ sâu chi tiết từng dòng code) |
| Lưu Trữ Cấu Hình | Nhớ trạng thái dự án bằng .cti_defense.json, mở ngay màn hình bảo vệ khi tái khởi động | ĐẠT (Tự động chuyển view) |
| Độ Chính Xác Đối Soát xAI | True Positive = 100%, False Positive = 0.0%, Whitelist RFC1918 an toàn | ĐẠT (Xác minh qua script probe) |
| Lá Chắn Mạng Trực Tiếp | WAF Reverse Proxy L7 cổng 8766 chặn đứng RCE, SQLi, Path Traversal | ĐẠT (Mã phản hồi 403 Forbidden) |
| Giao Diện & Trải Nghiệm | 100% Monospace chuẩn Cyber Terminal, không sử dụng emoji/icon, tiếng Việt dễ hiểu | ĐẠT (Chuẩn mực học thuật) |

---

## 6. XỬ LÝ SỰ CỐ THƯỜNG GẶP (TROUBLESHOOTING)

1. Lỗi 'python' is not recognized as an internal or external command:
   - Nguyên nhân: Khi cài đặt Python chưa tích chọn "Add Python to PATH".
   - Khắc phục: Tải lại bộ cài Python từ python.org, chọn Modify -> tích chọn Add Python to environment variables.
2. Lỗi cổng 8765 hoặc 8766 đang bị chiếm dụng:
   - Khắc phục: Chạy lệnh cti stop hoặc click đúp vào 2_TAT_HE_THONG.bat. Hệ thống sẽ tự động quét và giải phóng các cổng bị kẹt.
3. Không có kết nối Internet khi cào bài báo mới:
   - Giải pháp: Hệ thống đã được tích hợp sẵn CSDL sao lưu ngoại tuyến (cti_multi_source_archive_full_corpus.sqlite) gồm hơn 200 bài báo và hàng ngàn chỉ số IOC thực tế. Khi mất mạng, hệ thống tự động sử dụng kho dữ liệu cục bộ để phân tích mà không bị gián đoạn.

---
Tài liệu được biên soạn phục vụ công tác kiểm thử và đánh giá Đồ Án Chuyên Ngành An Ninh Mạng.
