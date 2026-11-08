# BÁO CÁO TIẾN ĐỘ THỰC HIỆN ĐỒ ÁN CHUYÊN NGÀNH

- **Tên đề tài**: Tự động hóa quy trình CTI và sinh quy tắc phòng thủ ứng dụng AI Agent
- **Giảng viên hướng dẫn**: Thầy Đinh Phương Nam
- **Nhóm sinh viên thực hiện**:
  - Trần Minh Khang - MSSV: 2387700027 - Lớp: 23DATH1 - Nhóm trưởng
  - Nguyễn Phi Phúc - MSSV: 2387701131 - Lớp: 23DATH1 - Thành viên
  - Nguyễn Nhật Lâm - MSSV: 2387700036 - Lớp: 23DATH1 - Thành viên
- **Ngành**: An toàn thông tin

---

## 1. TỔNG HỢP TIẾN ĐỘ CÁC TUẦN (THEO PHIẾU THEO DÕI)

| Tuần | Thời gian | Nội dung công việc thực hiện | Trạng thái |
| :--- | :--- | :--- | :--- |
| **Tuần 1** | 12/10/2026 đến 18/10/2026 | Chuẩn bị môi trường, tìm hiểu lý thuyết, thiết lập kho lưu trữ mã nguồn GitHub, phân chia công việc trong nhóm, khảo sát công nghệ và nguồn dữ liệu an ninh mạng đầu vào. | Hoàn thành |
| **Tuần 2** | 19/10/2026 đến 25/10/2026 | Dựng khung hệ thống, khảo sát và chọn lọc các nguồn tin tức tình báo an ninh uy tín, bước đầu triển khai kiến trúc ứng dụng. | Hoàn thành |
| **Tuần 3** | 26/10/2026 đến 01/11/2026 | Xây dựng hoàn chỉnh phân hệ thu thập dữ liệu tự động từ các nguồn tình báo mở OSINT, chuẩn bị các công cụ bóc tách chỉ số nguy hại IOC. | Hoàn thành |
| **Tuần 4** | 02/11/2026 đến 08/11/2026 | Nâng cấp quy trình 6 bước tự hành cho Tác tử AI, tích hợp bộ cào báo trực quan đa nguồn tại Bước 5, khắc phục triệt để hiện tượng dính dữ liệu cũ, đóng gói Kỹ năng Tác tử phòng thủ đa tầng và dọn dẹp bảo mật mã nguồn. | Hoàn thành |

---

## 2. CHI TIẾT KẾT QUẢ THỰC HIỆN TUẦN 4 (ĐÃ LÀM TỚI GÌ)

Trong tuần 4, nhóm tập trung nâng cấp hệ thống theo hướng trực quan hóa hoạt động của Tác tử AI và hoàn thiện cơ chế xử lý dữ liệu sạch cho từng dự án:

- **Nâng cấp quy trình 6 bước tự hành khép kín (Wizard)**:
  - Bước 1: Quét sâu cây cú pháp trừu tượng AST mã nguồn dự án mục tiêu và nhận diện điểm nóng nhạy cảm như upload tệp tin, thực thi lệnh hệ thống.
  - Bước 2: Tự động đo lường cấu hình phần cứng phần cứng GPU AMD Radeon RX 6600, 8GB VRAM và đề xuất mô hình AI cục bộ phù hợp như Qwen3 8B.
  - Bước 3: Gán phân hệ phòng thủ chính xác cho dự án như Web và API.
  - Bước 4: Thiết lập chu kỳ quét giám sát tự động.
  - Bước 5: Kích hoạt Tác tử cào báo tình báo chuyên biệt theo phân hệ và nạp dữ liệu trực quan.
  - Bước 6: Đóng gói bản vá ảo WAF, sinh bộ kỹ năng phòng thủ và kiểm thử thực chiến.

- **Xây dựng Trung tâm điều khiển cào báo trực quan tại Bước 5**:
  - Tích hợp bảng giám sát kết nối thời gian thực cho 6 nguồn tin an ninh mạng quốc tế gồm The Hacker News, CISA KEV Catalog, Bleeping Computer, Check Point Research, Kaspersky Securelist và The DFIR Report.
  - Thêm đèn chỉ thị trạng thái kết nối chuyển đổi trực tiếp: Chờ kết nối, Đang kết nối TLS tải dữ liệu và Hoàn tất.
  - Hiển thị thanh phần trăm tiến trình chuyển động mượt mà từ 0% đến 100% kèm nhãn từng bước xử lý.
  - Thêm bảng dòng lệnh Terminal hiển thị nhật ký bóc tách tin tức trực tiếp.
  - Cơ chế nạp từng bài báo vào hàng đợi: Lọc đúng 15 bài báo nguy cơ cao nhất khớp với công nghệ của dự án và nạp tuần tự từng bài kèm độ trễ để người dùng quan sát rõ ràng quá trình làm việc của Tác tử.

- **Khắc phục triệt để lỗi dính dữ liệu cũ và phân tách vùng làm việc**:
  - Khi bắt đầu dự án mới hoặc bấm quét lại, hàng đợi bài báo được làm sạch về 0 bài, không còn hiện tượng hiển thị sẵn dữ liệu từ các lần chạy trước.
  - Tách bạch rõ ràng giữa hai chế độ xem: Bài báo thuộc dự án hiện tại và Toàn bộ kho tri thức lịch sử hệ thống lưu trong cơ sở dữ liệu SQLite.

- **Đóng gói Kỹ năng Tác tử phòng thủ đa tầng (Agentic Defense Skills)**:
  - Tự động sinh trọn bộ quy tắc phòng thủ phối hợp gồm ModSecurity WAF cổng 8766, luật mạng Suricata IPS, giám sát hành vi Sigma, luật quét mã độc YARA và chính sách tường lửa OpenC2.
  - Tệp hướng dẫn SKILL.md đi kèm mã nguồn mẫu trước và sau khi vá lỗi, kèm script kiểm chứng lỗ hổng cho các AI Coding Agent nạp tự động.

- **Dọn dẹp mã nguồn và thắt chặt an toàn kho lưu trữ**:
  - Quy hoạch toàn bộ tài liệu hướng dẫn và đề cương vào thư mục `docs/`.
  - Loại bỏ các tệp rác, các bản sao lưu trùng lặp và các script kiểm tra tạm thời.
  - Cập nhật tệp `.gitignore` chặn tuyệt đối mọi tệp chứa biến môi trường, khóa bí mật, chứng chỉ số trước khi mở công khai kho lưu trữ.

---

## 3. CÁC ĐIỂM NGHẼN VÀ KHÓ KHĂN ĐANG GẶP PHẢI (STUCK Ở ĐÂU)

- **Giới hạn bộ nhớ đồ họa 8GB VRAM khi chạy mô hình cục bộ**: Khi gặp các bài báo phân tích chiến dịch APT có độ dài văn bản quá lớn, việc nạp toàn bộ nội dung thô vào mô hình ngôn ngữ lớn Qwen3 8B làm tăng thời gian suy luận. Giải pháp nhóm đang áp dụng là xây dựng bộ lọc đoạn văn chứa thực thể IOC trước khi chuyển vào mô hình.
- **Giới hạn số lượt gọi API từ các dịch vụ thẩm định an ninh bên ngoài**: Các dịch vụ đối soát như VirusTotal và AbuseIPDB áp dụng hạn ngạch số lần truy vấn miễn phí theo phút, gây chậm tiến độ khi đối soát hàng loạt chỉ số mới. Nhóm đã bổ sung cơ chế lưu bộ nhớ đệm cục bộ vào SQLite để tái sử dụng kết quả các chỉ số đã kiểm tra trước đó.
- **Quyền hạn can thiệp tường lửa hệ điều hành**: Việc tự động thêm quy tắc chặn IP thông qua lệnh Netsh trên Windows đòi hỏi quyền quản trị viên cao cấp, cần hoàn thiện giao diện nhắc cấp quyền mượt mà hơn cho người dùng cuối.

---

## 4. HƯỚNG ĐI TIẾP THEO TRONG TUẦN 5 (TỪ 09/11 ĐẾN 15/11/2026)

- **Hoàn thiện kịch bản kiểm thử đối kháng tự động**: Triển khai kịch bản Tác tử tự động gửi payload tấn công thử nghiệm vào ứng dụng mẫu (thực thi mã từ xa RCE, tải tệp độc hại), kích hoạt lá chắn ModSecurity WAF và tường lửa để chặn đứng, sau đó vá mã nguồn và tái kiểm thử xác nhận an toàn 100%.
- **Đo lường định lượng và tối ưu hiệu năng**: Đo thời gian phản hồi trung bình từ lúc phát hiện tin CTI đến lúc sinh xong quy tắc phòng thủ, giảm độ trễ xử lý của mô hình AI xuống dưới 10 giây mỗi đợt quét.
- **Viết báo cáo tổng kết và chuẩn bị thuyết trình demo**: Hoàn thiện tài liệu thuyết minh chi tiết của đồ án theo mẫu khoa và biên soạn slide trình chiếu demo trực tiếp toàn bộ luồng hoạt động cho giảng viên hướng dẫn.
