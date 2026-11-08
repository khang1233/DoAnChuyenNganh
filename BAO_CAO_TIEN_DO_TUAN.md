# BÁO CÁO TIẾN ĐỘ THỰC HIỆN ĐỒ ÁN CHUYÊN NGÀNH THEO TỪNG TUẦN

- **Tên đề tài**: Tự động hóa quy trình CTI và sinh quy tắc phòng thủ ứng dụng AI Agent
- **Giảng viên hướng dẫn**: Thầy Đinh Phương Nam
- **Nhóm sinh viên thực hiện**:
  - Nguyễn Phi Phúc - MSSV: 2387701131 - Lớp: 23DATA1 - Nhóm trưởng
  - Trần Minh Khang - MSSV: 2387700027 - Lớp: 23DATA1 - Thành viên
  - Nguyễn Nhật Lâm - MSSV: 2387700036 - Lớp: 23DATA1 - Thành viên
- **Ngành**: An toàn thông tin
- **Chuyên ngành**: An toàn thông tin

---

## TUẦN 1: TỪ 12/10/2026 ĐẾN 18/10/2026

### 1. Nội dung công việc thực hiện
- Khởi tạo môi trường lập trình và tìm hiểu cơ sở lý thuyết về an ninh mạng cùng mô hình tác tử trí tuệ nhân tạo.
- Thiết lập kho lưu trữ mã nguồn GitHub cho dự án và phân chia vai trò cho các thành viên trong nhóm.
- Khảo sát các công nghệ lõi cần sử dụng và nguồn dữ liệu an ninh mạng đầu vào.

### 2. Kết quả đạt được
- Tạo thành công cấu trúc dự án chuẩn trên GitHub và thống nhất quy trình làm việc nhóm.
- Xác định mục tiêu trọng tâm: Tự động hóa quy trình phân tích mối đe dọa và sinh đối sách phòng thủ cho ứng dụng web.

---

## TUẦN 2: TỪ 19/10/2026 ĐẾN 25/10/2026

### 1. Nội dung công việc thực hiện
- Dựng khung kiến trúc nền tảng cho hệ thống phòng thủ.
- Tìm kiếm, đánh giá và chọn lọc các nguồn tin tức tình báo an ninh mạng uy tín trên thế giới.
- Bước đầu triển khai các mô-đun kết nối dữ liệu thử nghiệm.

### 2. Kết quả đạt được
- Lựa chọn 6 nguồn tin tức tình báo an ninh mạng mở chính thống gồm The Hacker News, CISA KEV Catalog, Bleeping Computer, Check Point Research, Kaspersky Securelist và The DFIR Report.
- Thiết lập cơ sở dữ liệu SQLite cục bộ để lưu trữ và quản lý tập trung các bài viết an ninh mạng.

---

## TUẦN 3: TỪ 26/10/2026 ĐẾN 01/11/2026

### 1. Nội dung công việc thực hiện
- Xây dựng hoàn chỉnh phân hệ thu thập dữ liệu tự động từ các nguồn tin tình báo mở OSINT.
- Chuẩn bị các bộ công cụ bóc tách chỉ số nhận diện xâm nhập nguy hại IOC.
- Bắt đầu xây dựng cơ chế làm giàu dữ liệu và chấm điểm mối đe dọa.

### 2. Kết quả đạt được
- Thu thập và lưu trữ thành công kho tri thức ban đầu hơn 200 bài báo tình báo an ninh mạng.
- Tích hợp biểu thức chính quy để trích xuất tự động địa chỉ IP tấn công, tên miền độc hại, mã định danh lỗ hổng CVE và mã băm mã độc SHA256.

---

## TUẦN 4: TỪ 02/11/2026 ĐẾN 08/11/2026 (TUẦN HIỆN TẠI)

### 1. Chi tiết các công việc và nâng cấp mới hoàn thành
- **Quy trình 6 bước tự hành cho Tác tử AI**:
  - Bước 1: Quét sâu cây cú pháp trừu tượng AST mã nguồn dự án mục tiêu để tìm các điểm nóng nhạy cảm như hàm thực thi lệnh hệ thống, hàm tải tệp tin.
  - Bước 2: Tự động kiểm tra phần cứng máy tính và chọn mô hình ngôn ngữ lớn cục bộ Qwen3 8B chạy trên card đồ họa AMD Radeon RX 6600.
  - Bước 3: Định danh kiến trúc và gán phân hệ phòng thủ chính xác cho dự án như phân hệ Web và API.
  - Bước 4: Thiết lập chu kỳ tự động giám sát và quét mối đe dọa định kỳ.
  - Bước 5: Kích hoạt Tác tử cào dữ liệu chuyên sâu theo phân hệ đã chọn.
  - Bước 6: Đóng gói bản vá ảo WAF, sinh kỹ năng phòng thủ và kiểm thử thực chiến.

- **Trung tâm cào báo trực quan tại Bước 5**:
  - Giao diện hiển thị trực quan trạng thái kết nối của 6 nguồn tin an ninh quốc tế với đèn tín hiệu chuyển đổi từ Chờ kết nối sang Đang kết nối rồi đến Hoàn tất.
  - Thanh tiến trình phần trăm chuyển động mượt mà từ 0% đến 100% kèm nhãn trạng thái của từng giai đoạn.
  - Bảng điều khiển dòng lệnh Terminal hiển thị nhật ký thu thập dữ liệu thời gian thực.
  - Cơ chế nạp từng bài báo vào hàng đợi: Lọc đúng 15 bài báo nguy cơ cao nhất sát với công nghệ dự án và nạp lần lượt kèm độ trễ để người dùng quan sát rõ ràng quá trình Tác tử làm việc.

- **Sửa triệt để lỗi dính dữ liệu cũ và phân tách vùng làm việc**:
  - Khi bắt đầu kiểm tra một dự án mới hoặc nhấn nút quét lại, hàng đợi bài báo được đặt lại sạch sẽ về 0 bài, không còn bị nạp tràn lan hàng trăm bài báo cũ từ trước.
  - Tách bạch hai chế độ xem: Chế độ chỉ xem bài báo thuộc dự án hiện tại và Chế độ xem toàn bộ kho tri thức lịch sử hệ thống lưu trong cơ sở dữ liệu SQLite.

- **Đóng gói Kỹ năng Tác tử phòng thủ đa tầng**:
  - Tự động sinh trọn bộ quy tắc phòng thủ phối hợp gồm tường lửa ứng dụng ModSecurity WAF cổng 8766, hệ thống ngăn chặn xâm nhập Suricata IPS, luật giám sát hành vi Sigma, luật rà quét mã độc YARA và chính sách chặn mạng OpenC2.
  - Đóng gói tệp hướng dẫn chuẩn SKILL.md cùng mã nguồn mẫu trước và sau khi sửa lỗi cho các công cụ lập trình AI tự động đọc và thực thi.

- **Dọn dẹp mã nguồn và bảo mật kho lưu trữ**:
  - Di chuyển toàn bộ các tài liệu Word vào thư mục riêng `docs/`, xóa bỏ các bản sao lưu trùng lặp.
  - Cập nhật tệp `.gitignore` chặn tuyệt đối mọi tệp chứa biến môi trường, khóa bí mật, chứng chỉ số trước khi mở công khai kho lưu trữ.

### 2. Các điểm nghẽn và khó khăn đang gặp phải (Stuck ở đâu)
- **Giới hạn bộ nhớ đồ họa 8GB VRAM**: Khi gặp bài báo tình báo có nội dung văn bản quá dài, việc nạp toàn bộ vào mô hình ngôn ngữ lớn cục bộ làm thời gian suy luận bị chậm. Hướng giải quyết là xây dựng bộ lọc đoạn văn chứa mã nhận diện nguy hại trước khi đưa vào mô hình.
- **Giới hạn số lượt gọi API từ các dịch vụ bên ngoài**: Các dịch vụ kiểm tra như VirusTotal và AbuseIPDB giới hạn số lượt truy vấn miễn phí trong một phút. Hướng giải quyết là nhóm đã xây dựng cơ chế lưu bộ nhớ đệm kết quả vào cơ sở dữ liệu SQLite để không phải gọi lại các chỉ số đã kiểm tra.
- **Quyền hạn can thiệp tường lửa hệ điều hành**: Việc tự động thêm luật chặn IP qua lệnh Netsh trên Windows cần quyền quản trị viên cao cấp, nhóm đang hoàn thiện giao diện thông báo mượt mà hơn cho người dùng.

---

## TUẦN 5: TỪ 09/11/2026 ĐẾN 15/11/2026 (KẾ HOẠCH TIẾP THEO)

### 1. Nhiệm vụ trọng tâm cần triển khai
- **Kiểm thử đối kháng tự động**: Xây dựng kịch bản cho Tác tử tự động gửi mã tấn công thử nghiệm vào dự án mẫu, kích hoạt tường lửa ModSecurity WAF và Suricata IPS để chặn đứng, sau đó áp dụng mã vá lỗi và tái kiểm thử xác nhận an toàn.
- **Đo lường hiệu năng và tối ưu hóa**: Đo thời gian phản hồi từ lúc cào tin tức đến lúc kích hoạt phòng thủ thành công, tối ưu tốc độ xử lý của mô hình AI xuống dưới 10 giây mỗi đợt quét.
- **Hoàn thiện tài liệu báo cáo và chuẩn bị slide**: Viết hoàn chỉnh tài liệu báo cáo đồ án theo đúng mẫu khoa và thiết kế slide trình chiếu để chuẩn bị báo cáo demo trực tiếp với giảng viên hướng dẫn.
