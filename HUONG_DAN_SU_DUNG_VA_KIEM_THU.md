# TÀI LIỆU HƯỚNG DẪN SỬ DỤNG VÀ KỊCH BẢN KIỂM THỬ HỆ THỐNG
## HỆ THỐNG AN NINH MẠNG TỰ HÀNH TỪ TÌNH BÁO MỐI ĐE DỌA CTI (AUTONOMOUS CTI AGENTIC DEFENSE)

---

## 1. GIỚI THIỆU TỔNG QUAN

Hệ thống Autonomous CTI Agentic Defense là giải pháp an ninh mạng tự hành thế hệ mới dành cho lập trình viên và kỹ sư DevSecOps. Hệ thống giải quyết bài toán cốt lõi: Biến các thông tin an ninh mạng thô từ báo cáo quốc tế (CTI) thành các hành động phòng thủ thực thi tức thời trên mã nguồn dự án.

Toàn bộ hệ thống được gom trọn vẹn vào DUY NHẤT 1 TRANG WEB QUẢN TRỊ TRUNG TÂM:
http://127.0.0.1:8765

Người dùng và tester không cần phải mở nhiều trang web hay nhớ nhiều cổng mạng phức tạp. Mọi hoạt động từ quét mã nguồn, cào bài báo CTI, sinh gói kỹ năng tác tử, trò chuyện với AI Agent đến việc kích hoạt và kiểm thử lá chắn WAF đều được tích hợp đầy đủ ngay trong 1 giao diện web duy nhất này.

### 1.1. Các Thành Phần Chính Được Tích Hợp
- Bộ Cào và Lọc Tình Báo Tự Động (CTI Multi-Source Engine): Tự động thu thập dữ liệu an ninh mạng từ các nguồn uy tín thế giới (TheHackerNews, CISA US-CERT, Check Point Research, BleepingComputer, The DFIR Report).
- Bộ Quét Mã Nguồn Chuyên Sâu (Codebase Inspector): Đọc cây AST, phân tích phiên bản Runtime môi trường (Python 3.14, Node.js 20+, PHP 8.2), định vị các điểm nóng nhạy cảm (Sensitive Sinks: exec, eval, system).
- Tác Tử AI So Khớp & Đóng Gói Kỹ Năng (Threat Matcher & Agentic Skill Synthesizer): Đối chiếu ngữ cảnh dự án với kho tri thức, kích hoạt cảnh báo đỏ khi phát hiện lỗi trùng phiên bản, và tự động sinh gói kỹ năng phòng thủ đa nền tảng (SKILL.md, rules, scripts).
- Bảng Điều Khiển & Kiểm Thử WAF Tích Hợp (Embedded WAF Console): Đã tích hợp sẵn màn hình console và các nút bắn gói tin thử nghiệm trực tiếp trên giao diện web để xác minh khả năng chặn đứng payload độc hại (mã 403 Forbidden). Cổng mạng 8766 chỉ là cổng socket proxy chạy ngầm bên dưới của WAF, hệ thống tự động quản lý ngầm mà người dùng không cần phải mở hay quản lý riêng.
- Tự Động Vá Mã Nguồn & Tái Kiểm Thử (Auto-Remediation & Verification): Tự động chuẩn hóa mã nguồn, triệt tiêu lỗ hổng (True Positive = 0) và đảm bảo không gây gián đoạn nghiệp vụ (False Positive = 0.0%).

### 1.2. Địa Chỉ Truy Cập Duy Nhất Của Hệ Thống
- Địa chỉ Web Quản Trị Trung Tâm: http://127.0.0.1:8765
(Khởi động tự động bằng lệnh dòng lệnh cti tại bất kỳ thư mục dự án nào)

---

## 2. HƯỚNG DẪN CÀI ĐẶT 1 DÒNG LỆNH DUY NHẤT (QUICK INSTALL)

Hệ thống hỗ trợ cài đặt siêu tốc bằng 1 dòng lệnh duy nhất (tương tự như 9router hoặc các công cụ AI CLI hiện đại):

### Cách 1: Cài đặt toàn cục qua NPM (Khuyến nghị chuẩn quốc tế)
Mở CMD hoặc PowerShell tại bất kỳ đâu trên máy tính và chạy duy nhất 1 dòng lệnh:
```bash
npm install -g github:khang1233/DoAnChuyenNganh
```
Sau khi cài đặt xong, hệ thống đã được đăng ký toàn cục. Bạn chỉ cần mở CMD tại bất kỳ thư mục dự án nào và gõ:
```bash
cti
```
(Hệ thống sẽ tự động khởi động server và mở Web Dashboard duy nhất).

### Cách 2: Cài đặt 1 dòng lệnh bằng PowerShell (Dành cho Windows)
Mở PowerShell và dán duy nhất 1 dòng lệnh sau:
```powershell
irm https://raw.githubusercontent.com/khang1233/DoAnChuyenNganh/main/install.ps1 | iex
```
Lệnh này sẽ tự động tải mã nguồn, cài đặt các thư viện cần thiết và đăng ký lệnh cti vào hệ thống. Sau đó, bạn chỉ cần gõ:
```bash
cti
```

### Cách 3: Nếu bạn đã tải sẵn thư mục đồ án về máy
Chỉ cần mở CMD trong thư mục đồ án và chạy duy nhất 1 lệnh:
```bash
npm link
```
Sau đó gõ:
```bash
cti
```
(Hệ thống tự động phát hiện và cài đặt các thư viện Python nếu máy bạn chưa có).

---

## 3. HƯỚNG DẪN KHỞI ĐỘNG VÀ VẬN HÀNH

Sau khi cài đặt, bạn có thể vận hành hệ thống cực kỳ đơn giản:

### Cách 1: Sử Dụng Lệnh Dòng Lệnh CLI (Khuyến nghị)
Bạn chỉ cần mở CMD ngay tại thư mục dự án bạn muốn bảo vệ (ví dụ: target_projects\My_Website hoặc bất kỳ dự án web nào trên máy tính của bạn):
```bash
cti
```
(Hoặc có thể gõ cti-defense)

Hệ thống sẽ tự động:
1. Nhận diện đường dẫn thư mục hiện tại của bạn.
2. Kiểm tra và tự động cài đặt thư viện Python nếu máy thiếu.
3. Khởi động Web Dashboard duy nhất và các tiến trình nền.
4. Tự động mở trình duyệt Web tại http://127.0.0.1:8765.

Cách tắt hệ thống:
- Nhấn tổ hợp phím Ctrl + C tại cửa sổ CMD đang chạy; hoặc:
- Mở một CMD mới và gõ:
```bash
cti stop
```

### Cách 2: Sử Dụng File Batch 1-Click
- Bật hệ thống: Click đúp chuột vào file 1_BAT_HE_THONG.bat ở thư mục gốc. Hệ thống tự kiểm tra môi trường, bật server và mở trình duyệt.
- Tắt hệ thống: Click đúp chuột vào file 2_TAT_HE_THONG.bat. Hệ thống sẽ giải phóng toàn bộ tiến trình, giải phóng bộ nhớ RAM, GPU và đóng các cổng mạng ngay lập tức.

---

## 4. KỊCH BẢN KIỂM THỬ DÀNH CHO TESTER (STEP-BY-STEP TRÊN 1 WEB DUY NHẤT)

Dưới đây là 5 kịch bản kiểm thử mẫu để bạn bè / tester kiểm tra toàn diện chức năng của hệ thống ngay trên giao diện Web duy nhất http://127.0.0.1:8765:

### KỊCH BẢN 1: QUY TRÌNH PHÒNG THỦ TỰ HÀNH TỪNG BƯỚC (WIZARD FLOW)
Mục tiêu: Kiểm tra màn hình khởi đầu tối giản (Landing Step 0), cơ chế tự động nhận diện phần cứng, đề xuất mô hình AI mạnh nhất khả thi và tần suất quét thích ứng theo thể loại dự án.

- Bước 1 (Màn hình Khởi đầu Step 0): Mở trình duyệt tại http://127.0.0.1:8765.
  Quan sát:
  - Giao diện ban đầu hiển thị tối giản, không gây rối mắt: Thanh đếm ngược quét ngầm được tạm ẩn để chờ cấu hình.
  - Hiển thị Thẻ Dự Án Mục Tiêu kèm đường dẫn thư mục hiện tại.
  - Hiển thị Thẻ Phần Cứng Máy Tính: Tên GPU, VRAM (ví dụ: AMD Radeon RX 6600 8GB VRAM hoặc NVIDIA/Intel/CPU), tên CPU và tổng dung lượng RAM.
- Bước 2: Nhấn nút to nổi bật ở chính giữa: [ BẮT ĐẦU QUÉT DỰ ÁN & THIẾT LẬP BẢO VỆ ].
  Quan sát:
  - Thanh Stepper 5 bước xuất hiện.
  - Terminal chạy Live Stream: Tác tử AI đọc cây AST, nhận diện ngôn ngữ, framework, các dòng nhạy cảm Sensitive Sinks (exec, eval, system) và phiên bản runtime.
- Bước 3 (Kết quả phân tích & Cấu hình thích ứng):
  Kiểm tra 3 khối thông tin quan trọng:
  1. Hồ sơ kiến trúc mã nguồn: Ngôn ngữ, Framework, Phiên bản runtime (Python, PHP, Node.js), Phân hệ bảo vệ tự động (Scope A: Web & API Layer).
  2. Bảng chọn Mô hình AI Thích ứng Phần cứng (Hardware-Aware Model Selector):
     - Hệ thống phân loại 3 Cấp độ (Tier): Mạnh nhất khả thi -> Cân bằng & tốc độ cao -> Tiết kiệm tài nguyên/CPU mode.
     - Tự động chọn sẵn mô hình mạnh nhất máy đó có thể chạy (ví dụ máy 8GB VRAM tự động chọn qwen2.5:7b hoặc qwen3:8b; máy mạnh hơn tự động chọn 14B; máy CPU tự động chọn 1.5B hoặc CTI Heuristic). Cho phép người dùng chuyển chọn mô hình tùy ý bằng 1 cú nhấp chuột.
  3. Tần suất quét CTI tự động thích ứng theo loại dự án (Project Type-Adaptive Cadence):
     - Tác tử AI tự động nhận diện đặc thù thể loại: Với Web Application (đối mặt trực tiếp Internet), hệ thống đề xuất mặc định Mỗi 6 giờ (kèm dropdown chọn nhanh các mốc demo như Mỗi 2 phút, 5 phút, 15 phút, 1 giờ, 24 giờ).
- Bước 4: Nhấn nút chuyển sang Bước 3 (Cào báo CTI). Chọn mốc thời gian (1 năm, 3 năm hoặc 5 năm). Nhấn [ BẮT ĐẦU CÀO & ĐỐI CHIẾU ].
  Quan sát: Live Stream tác tử AI đối chiếu AST với kho bài báo; nếu phát hiện bài báo khớp đúng phiên bản runtime của dự án, hệ thống sẽ kích hoạt dòng cảnh báo đỏ khẩn cấp và hiển thị các chỉ số IOC (IP C2, CVE, Domain).
- Bước 5: Nhấn nút chuyển sang Bước 4 (Sinh Bộ Kỹ Năng).
  Quan sát: Hệ thống tự động sinh gói kỹ năng agentic-defense-master-web-suite trực tiếp vào thư mục dự án và đồng bộ tới 15 nền tảng AI Agent (Claude, Cursor, Gemini, Copilot...).
- Bước 6: Chuyển sang Bước 5 (Kiểm thử & Vá mã nguồn):
  1. Bấm nút kiểm thử [ Chạy Thử Probe Kiểm Tra Lỗ Hổng ]: Terminal trả về kết quả True Positive (xác nhận endpoint có lỗi RCE).
  2. Bấm nút [ Kích Hoạt Lá Chắn WAF & Firewall ]: Bật lá chắn mạng tức thời.
  3. Bấm nút [ Tự Động Vá Mã Nguồn ]: Hệ thống tự sửa code PHP/JS sang cơ chế Whitelist an toàn và tái kiểm thử xác nhận True Positive = 0.

### KỊCH BẢN 2: KIỂM THỬ LƯU TRỮ VÀ NHẬN DIỆN DỰ ÁN ĐÃ BẢO VỆ
Mục tiêu: Kiểm tra khả năng tự động ghi nhớ trạng thái dự án thông qua tệp .cti_defense.json.

- Bước 1: Sau khi hoàn thành Kịch bản 1, tắt hệ thống bằng cti stop hoặc 2_TAT_HE_THONG.bat.
- Bước 2: Mở CMD tại chính thư mục dự án đó và gõ cti.
- Bước 3: Quan sát giao diện Web khi mở lên:
  - Hệ thống nhận diện tệp .cti_defense.json.
  - Hiển thị banner màu xanh lá: [DỰ ÁN ĐÃ BẢO VỆ] kèm tên dự án, phân hệ Scope, tên kỹ năng tác tử và thời gian cấu hình.
  - Tự động chuyển thẳng vào Kho Kỹ Năng Tác Tử (Agentic Skills) hoặc Bảng Điểm IOC, không bắt quét lại từ đầu.
- Bước 4: Thử nghiệm nút [ Quét Lại Dự Án ] trên banner để kiểm tra tính năng Reset và cấu hình lại.

### KỊCH BẢN 3: KIỂM THỬ TÍNH ĐỘC LẬP KHI CHUYỂN DỰ ÁN MỚI
Mục tiêu: Kiểm tra hệ thống có xử lý độc lập giữa các dự án khác nhau trên cùng một máy hay không.

- Bước 1: Tạo một thư mục rỗng mới hoặc mở một thư mục dự án khác (ví dụ: target_projects\demo_vulnerable_php_app).
- Bước 2: Mở CMD tại thư mục đó và gõ cti.
- Bước 3: Quan sát giao diện Web:
  - Hệ thống phát hiện thư mục này chưa có cấu hình bảo vệ.
  - Tự động mở mục Wizard Bước 1 và khóa đúng vào đường dẫn của thư mục mới này.
  - Người dùng có thể tiến hành quét và sinh bộ kỹ năng độc lập cho riêng dự án mới mà không ảnh hưởng tới dự án cũ.

### KỊCH BẢN 4: KIỂM THỬ LÁ CHẮN WAF TRỰC TIẾP TRÊN GIAO DIỆN WEB
Mục tiêu: Xác minh WAF chặn đứng payload tấn công mà không cần mở trang web khác.

- Bước 1: Ngay trên giao diện Web http://127.0.0.1:8765, nhấp vào tab 3. Kho Kỹ Năng Tác Tử (Agentic Skills) trên thanh điều hướng đầu trang.
- Bước 2: Cuộn xuống mục CONSOLE THỬ NGHIỆM TẤN CÔNG WAF THỰC TẾ, bạn sẽ thấy các nút bấm kiểm thử được tích hợp sẵn:
  - [ Thử Nghiệm Tấn Công RCE ] -> Gửi gói tin giả lập Remote Code Execution.
  - [ Thử Nghiệm Tấn Công SQLi ] -> Gửi gói tin giả lập SQL Injection.
  - [ Thử Nghiệm Path Traversal ] -> Gửi gói tin giả lập đọc trộm file hệ thống.
  - [ Thử Nghiệm Gói Tin Sạch (Clean Traffic) ] -> Gửi gói tin người dùng thông thường.
- Bước 3: Quan sát màn hình Console hiển thị kết quả kiểm thử ngay lập tức:
  - Với các gói tin tấn công: Máy chủ WAF phản hồi CHẶN ĐỨNG (403 FORBIDDEN - DROP PAYLOAD) kèm mã quy tắc ModSecurity vi phạm và thời gian xử lý (< 2ms).
  - Với gói tin sạch: Phản hồi THÔNG QUA (200 OK - CLEAN TRAFFIC) đảm bảo tính năng nghiệp vụ của ứng dụng hoạt động thông suốt.

### KỊCH BẢN 5: KIỂM THỬ TRỢ LÝ TRÒ CHUYỆN AI AGENT
Mục tiêu: Kiểm tra khả năng tra cứu chỉ số an ninh mạng bằng ngôn ngữ tự nhiên ngay trong giao diện Web.

- Bước 1: Nhấp vào tab Chat AI Agent trên thanh điều hướng đầu trang.
- Bước 2: Bấm các nút câu hỏi mẫu có sẵn hoặc nhập nội dung tùy ý:
  - "Kiểm tra mức độ nguy hiểm của IP 43.134.165.205"
  - "Liệt kê các lỗ hổng CVE nguy hiểm nhất trong kho bài báo"
- Bước 3: Quan sát phản hồi của AI Agent:
  - Phản hồi bằng tiếng Việt chuẩn mực, có căn cứ trích dẫn rõ ràng từ 5 nguồn dữ liệu tình báo CTI (OTX, AbuseIPDB, Shodan, Abuse.ch, GreyNoise).

---

## 5. BẢNG TIÊU CHUẨN ĐÁNH GIÁ CHẤT LƯỢNG (EVALUATION MATRIX)

Khi nghiệm thu hoặc kiểm thử đồ án, tester có thể đối chiếu theo bảng tiêu chí sau:

| Tiêu Chí | Yêu Cầu Đạt Chuẩn | Trạng Thái Hệ Thống |
| :--- | :--- | :--- |
| Tính Tự Hành (Autonomous) | Tự động hóa từ cào báo đến phân tích, cấu hình WAF và vá code không cần can thiệp thủ công | ĐẠT (100% Khép kín) |
| Bảo Vệ Ngữ Cảnh Dự Án | Tự động nhận diện cây AST, phiên bản runtime (Python, Node, PHP) và Sensitive Sinks | ĐẠT (Độ sâu chi tiết từng dòng code) |
| Lưu Trữ Cấu Hình | Nhớ trạng thái dự án bằng .cti_defense.json, mở ngay màn hình bảo vệ khi tái khởi động | ĐẠT (Tự động chuyển view) |
| Trải Nghiệm All-in-One | Toàn bộ tính năng từ quản lý, cào báo, chat AI đến kiểm thử WAF dồn gọn trong 1 Web duy nhất | ĐẠT (http://127.0.0.1:8765) |
| Độ Chính Xác Đối Soát xAI | True Positive = 100%, False Positive = 0.0%, Whitelist RFC1918 an toàn | ĐẠT (Xác minh qua script probe) |
| Lá Chắn WAF Tích Hợp | Đánh chặn trực tiếp RCE, SQLi, Path Traversal với mã 403 Forbidden hiển thị lên Console | ĐẠT (Tích hợp Console trên Web) |
| Giao Diện & Trải Nghiệm | 100% Monospace chuẩn Cyber Terminal, không sử dụng emoji/icon, tiếng Việt dễ hiểu | ĐẠT (Chuẩn mực học thuật) |

---

## 6. XỬ LÝ SỰ CỐ THƯỜNG GẶP (TROUBLESHOOTING)

1. Lỗi 'python' is not recognized as an internal or external command:
   - Nguyên nhân: Khi cài đặt Python chưa tích chọn "Add Python to PATH".
   - Khắc phục: Tải lại bộ cài Python từ python.org, chọn Modify -> tích chọn Add Python to environment variables.
2. Lỗi cổng mạng đang bị chiếm dụng:
   - Khắc phục: Chạy lệnh cti stop hoặc click đúp vào 2_TAT_HE_THONG.bat. Hệ thống sẽ tự động quét và giải phóng các cổng bị kẹt trong 1 giây.
3. Không có kết nối Internet khi cào bài báo mới:
   - Giải pháp: Hệ thống đã được tích hợp sẵn CSDL sao lưu ngoại tuyến (cti_multi_source_archive_full_corpus.sqlite) gồm hơn 200 bài báo và hàng ngàn chỉ số IOC thực tế. Khi mất mạng, hệ thống tự động sử dụng kho dữ liệu cục bộ để phân tích mà không bị gián đoạn.

---
Tài liệu được biên soạn phục vụ công tác kiểm thử và đánh giá Đồ Án Chuyên Ngành An Ninh Mạng.
