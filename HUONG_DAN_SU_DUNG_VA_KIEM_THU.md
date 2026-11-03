# TÀI LIỆU HƯỚNG DẪN SỬ DỤNG VÀ KỊCH BẢN KIỂM THỬ HỆ THỐNG
## HỆ THỐNG AN NINH MẠNG TỰ HÀNH TỪ TÌNH BÁO MỐI ĐE DỌA CTI (AUTONOMOUS CTI AGENTIC DEFENSE)

---

## 1. GIỚI THIỆU TỔNG QUAN

Hệ thống Autonomous CTI Agentic Defense là giải pháp an ninh mạng tự hành dành cho lập trình viên và kỹ sư an toàn thông tin. Hệ thống chuyển đổi các báo cáo tình báo an ninh mạng quốc tế thành các gói kỹ năng phòng thủ thực thi trực tiếp trên mã nguồn dự án.

Toàn bộ hệ thống được tích hợp vào duy nhất một trang web quản trị trung tâm:
http://127.0.0.1:8765

Người dùng không cần mở nhiều trang web hay quản lý nhiều cổng mạng độc lập. Mọi hoạt động từ quét mã nguồn, thu thập tin tức tình báo an ninh mạng, đóng gói bộ kỹ năng tác tử, tương tác với tác tử trí tuệ nhân tạo đến kích hoạt và kiểm thử lá chắn tường lửa ứng dụng web đều được gom trọn vẹn trong một giao diện duy nhất.

### 1.1. Các Phân Hệ Chính Được Tích Hợp
- Bộ thu thập và xử lý tình báo an ninh mạng đa nguồn: Tự động thu thập dữ liệu từ các tổ chức uy tín gồm TheHackerNews, CISA US-CERT, Check Point Research, BleepingComputer và The DFIR Report.
- Bộ phân tích mã nguồn chuyên sâu: Đọc cây cú pháp trừu tượng AST, nhận diện môi trường thực thi gồm phiên bản ngôn ngữ như Python 3.14, Node.js 20 hoặc PHP 8.2, định vị chính xác các điểm nhạy cảm trong mã nguồn như exec, eval, system, passthru.
- Tác tử trí tuệ nhân tạo so khớp và đóng gói kỹ năng: Đối chiếu ngữ cảnh dự án với kho tri thức an ninh mạng, kích hoạt cảnh báo đỏ khi phát hiện lỗ hổng trùng phiên bản thực thi của dự án và tự động xuất gói kỹ năng phòng thủ gồm tệp hướng dẫn SKILL.md, tệp luật ModSecurity, Suricata, Wazuh và kịch bản kiểm thử.
- Bảng điều khiển và kiểm thử lá chắn tích hợp: Tích hợp sẵn màn hình hiển thị trực tiếp và các nút phát gói tin kiểm thử trên giao diện web nhằm xác thực khả năng ngăn chặn mã độc của tường lửa ứng dụng web với mã phản hồi 403 Forbidden. Cổng dịch vụ 8766 vận hành như cổng chuyển tiếp nội bộ và được quản lý ngầm hoàn toàn.
- Cơ chế tự động sửa đổi mã nguồn và tái kiểm thử: Chuẩn hóa mã nguồn theo danh sách cho phép an toàn, đưa tỷ lệ phát hiện thực dương về 0 và duy trì tỷ lệ dương tính giả ở mức 0.0%.

### 1.2. Địa Chỉ Truy Cập Duy Nhất Của Hệ Thống
- Giao diện web quản trị trung tâm: http://127.0.0.1:8765
- Khởi động tự động bằng lệnh cti tại thư mục dự án bất kỳ trên máy tính.

---

## 2. HƯỚNG DẪN CÀI ĐẶT NHANH BẰNG MỘT DÒNG LỆNH

Hệ thống hỗ trợ cài đặt toàn cục tương tự các công cụ dòng lệnh hiện đại:

### Cách 1: Cài đặt toàn cục thông qua NPM
Mở cửa sổ dòng lệnh tại vị trí bất kỳ trên máy tính và thực thi lệnh sau:
```bash
npm install -g github:khang1233/DoAnChuyenNganh
```
Sau khi tiến trình cài đặt hoàn tất, hệ thống đã sẵn sàng trong môi trường toàn cục. Mở cửa sổ dòng lệnh tại thư mục dự án cần bảo vệ và gõ:
```bash
cti
```
Hệ thống tự động kích hoạt máy chủ dịch vụ và mở giao diện quản trị trung tâm trên trình duyệt.

### Cách 2: Cài đặt bằng PowerShell trên Windows
Mở PowerShell và thực thi lệnh sau:
```powershell
irm https://raw.githubusercontent.com/khang1233/DoAnChuyenNganh/main/install.ps1 | iex
```
Lệnh trên tự động tải mã nguồn, cài đặt các thư viện cần thiết và thiết lập lệnh cti vào biến môi trường hệ thống. Sau đó, khởi động bằng lệnh:
```bash
cti
```

### Cách 3: Cài đặt từ thư mục mã nguồn có sẵn
Nếu đã tải sẵn mã nguồn đồ án về máy tính, mở cửa sổ dòng lệnh tại thư mục gốc của đồ án và thực thi lệnh:
```bash
npm link
```
Sau đó khởi động hệ thống bằng lệnh:
```bash
cti
```
Hệ thống tự động kiểm tra và cài đặt bổ sung các thư viện Python cần thiết nếu môi trường chưa có.

---

## 3. HƯỚNG DẪN KHỞI ĐỘNG VÀ VẬN HÀNH

Sau khi cài đặt xong, người dùng có hai phương thức vận hành:

### Phương thức 1: Sử dụng giao diện dòng lệnh
Mở cửa sổ dòng lệnh ngay tại thư mục dự án cần bảo vệ và thực thi lệnh:
```bash
cti
```
Hệ thống tự động thực hiện các tác vụ:
- Xác định đường dẫn thư mục hiện tại của dự án.
- Kiểm tra tính đầy đủ của thư viện phụ thuộc.
- Kích hoạt giao diện web quản trị trung tâm và các tiến trình nền.
- Tự động mở trình duyệt web tại địa chỉ http://127.0.0.1:8765.

Để dừng hệ thống:
- Nhấn tổ hợp phím Ctrl + C tại cửa sổ dòng lệnh đang chạy; hoặc:
- Mở cửa sổ dòng lệnh mới và thực thi lệnh:
```bash
cti stop
```

### Phương thức 2: Sử dụng tập lệnh thực thi sẵn
- Khởi động hệ thống: Nhấp đúp chuột vào tệp 1_BAT_HE_THONG.bat tại thư mục gốc. Hệ thống tự kiểm tra môi trường, kích hoạt máy chủ và mở trình duyệt web.
- Dừng hệ thống: Nhấp đúp chuột vào tệp 2_TAT_HE_THONG.bat. Hệ thống lập tức giải phóng toàn bộ tiến trình, giải phóng bộ nhớ RAM và GPU, đồng thời đóng các cổng mạng.

---

## 4. KỊCH BẢN KIỂM THỬ HỆ THỐNG DÀNH CHO NGƯỜI ĐÁNH GIÁ

Các kịch bản dưới đây được thiết kế nhằm phục vụ việc kiểm thử toàn diện mọi chức năng của hệ thống ngay trên giao diện web duy nhất tại địa chỉ http://127.0.0.1:8765:

### Kịch Bản 1: Quy Trình Phòng Thủ Tự Hành Từng Bước Mượt Mà (Progressive Wizard Flow)
Mục tiêu: Đánh giá quy trình phòng thủ tự hành tuần tự 6 bước mượt mà, cơ chế tự động nhận diện phần cứng, đề xuất mô hình AI mạnh nhất khả thi và chu kỳ quét thích ứng theo thể loại dự án.

- Bước 1: Quét mã nguồn và nhận diện điểm mấu chốt kiến trúc:
  - Mở trình duyệt tại địa chỉ http://127.0.0.1:8765.
  - Giao diện mở trực tiếp tại Bước 1, hiển thị thẻ thông tin dự án mục tiêu và thẻ cấu hình phần cứng của máy tính gồm tên GPU, dung lượng VRAM, tên CPU và tổng dung lượng RAM.
  - Nút chuyển tiếp sang Bước 2 ban đầu ở trạng thái vô hiệu hóa và có màu tối nhằm bảo đảm người dùng không bỏ qua bước phân tích mã nguồn.
  - Nhấn nút [ BẮT ĐẦU QUÉT DỰ ÁN ].
  - Terminal chạy dòng dữ liệu thời gian thực ghi nhận tiến trình tác tử trí tuệ nhân tạo duyệt cây cú pháp AST, phân tích ngôn ngữ lập trình, khung phát triển, phiên bản môi trường thực thi và trích xuất các điểm nóng nhạy cảm như exec, eval, system, passthru.
  - Khi hoàn tất quét, tác tử AI đưa ra kết luận kiến trúc dự án và nút chuyển tiếp lập tức chuyển sang trạng thái kích hoạt với màu xanh dương sáng rõ. Nhấn nút này để chuyển sang Bước 2.

- Bước 2: Lựa chọn mô hình trí tuệ nhân tạo thích ứng phần cứng:
  - Hệ thống hiển thị bảng lựa chọn mô hình AI phân loại theo 3 cấp độ:
    1. Cấp độ Mạnh nhất khả thi: Hệ thống tự động chọn sẵn mô hình tối ưu nhất mà cấu hình máy tính hiện tại có thể vận hành ổn định. Ví dụ máy tính có GPU 8GB VRAM được tự động chọn mô hình Qwen 2.5:7B; máy tính có GPU cao cấp hơn được đề xuất mô hình 14B; máy tính chỉ có CPU được chuyển sang mô hình 1.5B hoặc CTI Heuristic.
    2. Cấp độ Cân bằng và tốc độ cao: Đề xuất các mô hình nhẹ hơn như Qwen 2.5:3B hoặc Mistral 7B nhằm tăng tốc độ phản hồi.
    3. Cấp độ Tiết kiệm tài nguyên: Đề xuất chế độ suy luận dựa trên tập luật CTI Heuristic nhằm giảm thiểu tối đa tài nguyên bộ nhớ.
  - Người dùng có thể giữ nguyên lựa chọn mặc định tối ưu hoặc nhấp chọn cấp độ mong muốn. Nhấn [ Tiếp tục sang Bước 3 ].

- Bước 3: Lựa chọn phân hệ phòng thủ:
  - Phân hệ phòng thủ do tác tử AI phát hiện từ Bước 1 được tự động đánh dấu chọn làm mặc định, ví dụ Phân hệ Ứng dụng Web và API (Scope A).
  - Hệ thống liệt kê đầy đủ các phân hệ an ninh khác gồm Phân hệ Mạng và Vành đai (Scope B), Phân hệ Máy chủ và Thiết bị đầu cuối (Scope C), Phân hệ Phần cứng nhúng và IoT (Scope D).
  - Cung cấp tùy chọn Toàn diện cho Tất cả các phân hệ (SCOPE_ALL) đối với người dùng có nhu cầu mở rộng phạm vi giám sát trên toàn bộ các lớp hạ tầng.
  - Người dùng xác nhận phân hệ và nhấn [ Tiếp tục sang Bước 4 ].

- Bước 4: Thiết lập chu kỳ quét ngầm và độ sâu dữ liệu tình báo:
  - Tần suất quét ngầm tự động thích ứng theo đặc thù dự án: Tác tử AI tự động đề xuất tần suất kiểm tra bài báo an ninh mạng phù hợp với loại hình dự án. Đối với ứng dụng web đối mặt Internet, hệ thống đề xuất chu kỳ mặc định là Mỗi 6 giờ, kèm danh sách chọn nhanh các mốc từ 2 phút, 5 phút, 15 phút, 1 giờ đến 7 ngày nhằm phục vụ mục đích kiểm thử.
  - Độ sâu dữ liệu tình báo: Cho phép chọn khoảng thời gian thu thập dữ liệu gồm 1 năm, 3 năm (mốc chuẩn khuyến nghị) hoặc 5 năm.
  - Nhấn [ Tiếp tục sang Bước 5 ].

- Bước 5: Thu thập báo cáo tình báo, đối soát mã nguồn và đóng gói kỹ năng tác tử:
  - Nhấn nút [ BẮT ĐẦU CÀO BÁO & ĐỐI CHIẾU ].
  - Tác tử AI thu thập dữ liệu bài báo tình báo, trích xuất các chỉ số nguy hại gồm địa chỉ IP máy chủ điều khiển C2, mã định danh lỗ hổng CVE và dấu hiệu mã độc.
  - Đối soát chéo với ngữ cảnh mã nguồn: Trường hợp phát hiện bài báo an ninh mạng khớp chính xác với phiên bản môi trường thực thi của dự án, hệ thống kích hoạt thanh cảnh báo đỏ khẩn cấp.
  - Tự động biên dịch và tạo lập bộ kỹ năng tác tử an ninh mạng hoàn chỉnh đặt trực tiếp vào thư mục dự án và khởi tạo tệp cấu hình .cti_defense.json.
  - Nhấn [ Tiếp tục sang Bước 6 ].

- Bước 6: Khắc phục mã nguồn, xem lịch sử tình báo và kiểm thử lá chắn:
  - Kiểm thử trước khi vá: Nhấn nút kiểm thử lỗ hổng, terminal trả về kết quả True Positive xác nhận sự tồn tại của lỗ hổng trên ứng dụng mục tiêu.
  - Kích hoạt lá chắn: Nhấn nút bật lá chắn tường lửa ứng dụng web để ngăn chặn ngay lập tức các lưu lượng khai thác.
  - Khắc phục mã nguồn: Nhấn nút tự động vá mã nguồn, hệ thống chuyển đổi mã nguồn dễ bị tổn thương sang cơ chế kiểm tra an toàn và tái kiểm thử xác nhận tỷ lệ True Positive giảm về 0.
  - Cung cấp liên kết chuyển nhanh đến các khu vực: Lịch sử tình báo đã xử lý, Bảng điểm chỉ số nguy hại IOC, Kho kỹ năng tác tử và Trợ lý trò chuyện an ninh mạng.

### Kịch Bản 2: Kiểm Thử Khả Năng Lưu Trữ Và Nhận Diện Dự Án Đã Bảo Vệ
Mục tiêu: Đánh giá cơ chế ghi nhớ trạng thái dự án thông qua tệp cấu hình .cti_defense.json.

- Bước 1: Sau khi hoàn thành Kịch bản 1, đóng hệ thống bằng lệnh cti stop hoặc tệp 2_TAT_HE_THONG.bat.
- Bước 2: Mở lại cửa sổ dòng lệnh tại chính thư mục dự án đó và thực thi lệnh cti.
- Bước 3: Quan sát giao diện web:
  - Hệ thống tự động đọc tệp .cti_defense.json.
  - Hiển thị thanh thông báo trạng thái màu xanh lá xác nhận dự án đã được bảo vệ kèm thông tin phân hệ an ninh mạng, tên bộ kỹ năng tác tử và thời điểm thiết lập.
  - Tự động hiển thị khu vực Kho kỹ năng tác tử hoặc Bảng điểm chỉ số an ninh mạng, không yêu cầu người dùng phải thực hiện lại quy trình quét ban đầu.
- Bước 4: Kiểm tra nút quét lại dự án trên thanh trạng thái để kiểm tra tính năng thiết lập lại cấu hình khi có nhu cầu.

### Kịch Bản 3: Kiểm Thử Tính Độc Lập Khi Chuyển Sang Dự Án Mới
Mục tiêu: Xác thực khả năng xử lý độc lập giữa các dự án khác nhau trên cùng một máy tính.

- Bước 1: Mở cửa sổ dòng lệnh tại một thư mục dự án khác chưa từng cấu hình bảo vệ.
- Bước 2: Thực thi lệnh cti.
- Bước 3: Quan sát giao diện web:
  - Hệ thống nhận diện thư mục mới này chưa có tệp cấu hình bảo vệ.
  - Giao diện tự động mở tại Bước 1 của quy trình phòng thủ và khóa chính xác đường dẫn vào thư mục mới.
  - Tiến trình quét mã nguồn, chọn mô hình AI, cấu hình phân hệ và đóng gói kỹ năng được thực hiện độc lập cho riêng dự án mới mà không làm ảnh hưởng đến cấu hình của các dự án trước đó.

### Kịch Bản 4: Kiểm Thử Lá Chắn Tường Lửa Ứng Dụng Web Trực Tiếp Trên Web
Mục tiêu: Xác thực khả năng ngăn chặn mã độc của tường lửa ứng dụng web mà không cần chuyển đổi ứng dụng ngoài.

- Bước 1: Trên thanh điều hướng đầu trang của giao diện web, chọn thẻ Kho Kỹ Năng Tác Tử.
- Bước 2: Di chuyển đến khu vực Bảng điều khiển thử nghiệm tấn công, giao diện tích hợp sẵn các nút kiểm thử:
  - Thử nghiệm tấn công thực thi mã từ xa RCE.
  - Thử nghiệm tấn công chèn mã SQL Injection.
  - Thử nghiệm tấn công duyệt thư mục trái phép Path Traversal.
  - Thử nghiệm gửi gói tin sạch thông thường.
- Bước 3: Quan sát kết quả trên màn hình điều khiển:
  - Đối với các gói tin tấn công: Hệ thống phản hồi trạng thái 403 Forbidden kèm tên quy tắc ModSecurity bị kích hoạt và thời gian xử lý dưới 2 mili-giây.
  - Đối với gói tin sạch: Hệ thống phản hồi trạng thái 200 OK bảo đảm dịch vụ nghiệp vụ của ứng dụng hoạt động bình thường.

### Kịch Bản 5: Kiểm Thử Trợ Lý Trí Tuệ Nhân Tạo An Ninh Mạng
Mục tiêu: Đánh giá khả năng tra cứu và phản hồi thông tin tình báo an ninh mạng bằng ngôn ngữ tự nhiên.

- Bước 1: Nhấp chọn thẻ Chat AI Agent trên thanh điều hướng.
- Bước 2: Chọn câu hỏi mẫu có sẵn hoặc nhập câu hỏi trực tiếp:
  - "Đánh giá mức độ nguy hiểm của địa chỉ IP 43.134.165.205"
  - "Tổng hợp các mã định danh lỗ hổng CVE nghiêm trọng nhất trong cơ sở dữ liệu tình báo"
- Bước 3: Quan sát nội dung phản hồi: Tác tử AI phản hồi bằng tiếng Việt chuẩn xác, trích dẫn minh bạch nguồn dữ liệu từ các kho tình báo an ninh mạng đã thu thập.

---

## 5. BẢNG TIÊU CHUẨN ĐÁNH GIÁ CHẤT LƯỢNG HỆ THỐNG

| Tiêu Chí Đánh Giá | Yêu Cầu Kỹ Thuật Đạt Chuẩn | Kết Quả Đánh Giá |
| :--- | :--- | :--- |
| Tính tự hành khép kín | Tự động hóa từ thu thập thông tin, phân tích mã nguồn, thiết lập tường lửa đến sửa đổi mã nguồn không cần can thiệp thủ công | ĐẠT |
| Nhận diện ngữ cảnh dự án | Phân tích sâu cây cú pháp AST, phiên bản môi trường thực thi và định vị chính xác các điểm nhạy cảm trong mã nguồn | ĐẠT |
| Lưu trữ trạng thái cấu hình | Ghi nhớ cấu hình thông qua tệp .cti_defense.json và tự động mở chế độ bảo vệ khi tái khởi động | ĐẠT |
| Trải nghiệm hợp nhất trên một giao diện | Hợp nhất toàn bộ các chức năng quản trị, thu thập tin tức, trò chuyện và kiểm thử vào duy nhất một giao diện web | ĐẠT |
| Độ chính xác trong đối soát | Đưa tỷ lệ phát hiện thực dương về 0 sau khi vá và duy trì tỷ lệ dương tính giả ở mức 0.0% | ĐẠT |
| Hiệu năng lá chắn tường lửa | Ngăn chặn trực tiếp các dạng tấn công RCE, SQLi, Path Traversal với phản hồi 403 Forbidden hiển thị trực tiếp | ĐẠT |
| Chuẩn mực giao diện và văn bản | Giao diện chuẩn cyber terminal, không sử dụng biểu tượng cảm xúc, văn phong học thuật chuẩn mực | ĐẠT |

---

## 6. HƯỚNG DẪN XỬ LÝ SỰ CỐ KỸ THUẬT

1. Trường hợp không nhận diện lệnh python:
   - Nguyên nhân: Chưa kích hoạt tùy chọn thêm Python vào biến môi trường PATH trong quá trình cài đặt.
   - Khắc phục: Mở trình cài đặt Python, chọn Modify và tích chọn mục Add Python to environment variables.
2. Trường hợp cổng mạng bị chiếm dụng:
   - Khắc phục: Thực thi lệnh cti stop hoặc nhấp đúp chuột vào tệp 2_TAT_HE_THONG.bat để hệ thống tự động giải phóng toàn bộ tiến trình và cổng mạng.
3. Trường hợp mất kết nối mạng khi thu thập dữ liệu:
   - Cơ chế xử lý: Hệ thống tích hợp sẵn kho dữ liệu tình báo an ninh mạng ngoại tuyến với hơn 200 báo cáo chuyên sâu và hàng ngàn chỉ số nguy hại thực tế, bảo đảm việc phân tích và đóng gói kỹ năng diễn ra bình thường ngay cả khi không có kết nối Internet.

---
Tài liệu được biên soạn phục vụ công tác kiểm thử và đánh giá Đồ Án Chuyên Ngành An Ninh Mạng.
