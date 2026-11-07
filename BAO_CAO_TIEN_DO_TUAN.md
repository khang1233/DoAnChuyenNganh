# Báo cáo tiến độ tuần đồ án chuyên ngành

**Đề tài**: Tự động hóa quy trình thu thập tình báo an ninh mạng và đóng gói kỹ năng phòng thủ ứng dụng tác tử nhân tạo  
**Giảng viên hướng dẫn**: Thầy Đinh Phương Nam  
**Nhóm sinh viên thực hiện**:
- Trần Minh Khang - 2387700027 - Nhóm trưởng
- Nguyễn Phi Phúc - 2387701131 - Thành viên
- Nguyễn Nhật Lâm - 2387700036 - Thành viên  
**Thời gian báo cáo**: Tuần từ ngày 01 tháng 11 năm 2026 đến ngày 07 tháng 11 năm 2026  

---

## Bảng chữ viết tắt và thuật ngữ

| Viết tắt | Thuật ngữ đầy đủ | Ý nghĩa kỹ thuật |
| :--- | :--- | :--- |
| CTI | Cyber Threat Intelligence | Dữ liệu tình báo về các mối đe dọa an ninh mạng từ nguồn mở |
| IOC | Indicator of Compromise | Chỉ số nhận diện xâm nhập như địa chỉ mạng, tên miền độc, mã băm tập tin |
| CVE | Common Vulnerabilities and Exposures | Danh mục mã định danh các lỗ hổng bảo mật tiêu chuẩn quốc tế |
| WAF | Web Application Firewall | Tường lửa lọc và kiểm soát lưu lượng tầng ứng dụng web |
| IPS | Intrusion Prevention System | Hệ thống giám sát và chủ động ngăn chặn xâm nhập mạng |
| SIEM | Security Information and Event Management | Hệ thống thu thập, phân tích và tương quan sự kiện an ninh mạng |
| AST | Abstract Syntax Tree | Cấu trúc cây cú pháp trừu tượng của mã nguồn phần mềm |
| LLM | Large Language Model | Mô hình ngôn ngữ lớn dùng làm bộ não suy luận cho tác tử |
| VRAM | Video Random Access Memory | Dung lượng bộ nhớ đồ họa dùng để nạp trọng số mô hình |
| API | Application Programming Interface | Giao diện kết nối và trao đổi dữ liệu giữa các dịch vụ |
| CLI | Command Line Interface | Giao diện điều khiển tác vụ bằng dòng lệnh |

---

## 1. Các công việc đã hoàn thành trong tuần

Nhóm đã tập trung hoàn thiện bộ khung kỹ thuật, tích hợp mô hình ngôn ngữ lớn cục bộ và chuẩn hóa quy trình tự hành 6 bước cho tác tử an ninh mạng. Cụ thể:

- Xây dựng mô-đun phân tích mã nguồn dựa trên cấu trúc cây cú pháp trừu tượng AST và quét điểm nóng nhạy cảm trong dự án mục tiêu.
- Tích hợp mô hình ngôn ngữ cục bộ Qwen3 8B chạy trực tiếp trên phần cứng đồ họa AMD Radeon RX 6600 qua máy chủ Ollama để thẩm định kiến trúc và gán phân hệ phòng thủ tự động.
- Hoàn thiện quy trình tự hành 6 bước gồm:
  1. Quét sâu mã nguồn dự án mục tiêu và nhận diện điểm nóng rủi ro.
  2. Khảo sát phần cứng và chốt mô hình ngôn ngữ phù hợp.
  3. Xác lập phân hệ phòng thủ mục tiêu theo ngữ cảnh kiến trúc.
  4. Cấu hình nhịp độ quét và thời gian biểu giám sát.
  5. Thu thập tình báo chuyên biệt theo phân hệ và sinh kỹ năng tác tử.
  6. Áp dụng ảo hóa bản vá WAF và kiểm thử xác thực đối kháng.
- Đóng gói chuẩn kỹ năng phòng thủ Agentic Skill Package tương thích với 15 nền tảng tác tử lập trình phổ biến, gồm tệp hướng dẫn SKILL.md, quy tắc phân tích tĩnh, kịch bản khai thác đối chứng và kịch bản khắc phục mã nguồn an toàn.
- Thiết lập hệ thống phòng thủ đa tầng phối hợp gồm:
  - Ảo hóa bản vá ModSecurity WAF hoạt động trên cổng 8766.
  - Bộ luật nhận diện xâm nhập mạng Suricata IPS.
  - Quy tắc giám sát hành vi Sigma và bộ tương quan sự kiện SIEM.
  - Quy tắc truy vết tiến trình độc hại YARA.
  - Tự động điều khiển tường lửa hệ điều hành thông qua lệnh chuẩn hóa OpenC2.
- Xây dựng bảng điều khiển trực quan thời gian thực trên cổng 8765, hiển thị toàn bộ 282 bài báo trong kho lưu trữ SQLite, thông số đo lường hiệu năng và bảng đối soát chỉ số nguy hại đa nguồn từ AlienVault OTX, VirusTotal, AbuseIPDB và Shodan.
- Chuẩn hóa toàn bộ hệ thống thời gian lưu trữ và hiển thị sang múi giờ Việt Nam UTC+7, loại bỏ triệt để hiện tượng nghịch lý thời gian và tình trạng rò rỉ dữ liệu phân tích cũ khi khởi tạo lại dự án.
- Bổ sung bộ điều khiển dòng lệnh CLI mang tên cti-defense giúp khởi động, kiểm tra trạng thái và tắt sạch toàn bộ tiến trình hệ thống bằng một thao tác duy nhất.

---

## 2. Các khó khăn và điểm nghẽn kỹ thuật đang gặp phải

- Dung lượng bộ nhớ đồ họa 8GB VRAM giới hạn khả năng nạp các bài báo tình báo có dung lượng văn bản quá dài vào ngữ cảnh suy luận của mô hình ngôn ngữ cục bộ mà vẫn duy trì tốc độ xử lý dưới 20 giây mỗi bài.
- Giới hạn tần suất gọi API từ các máy chủ tình báo an ninh công cộng nước ngoài gây gián đoạn quá trình làm giàu dữ liệu hàng loạt khi đối soát đồng thời nhiều chỉ số kỹ thuật.
- Cơ chế đồng bộ hóa quy tắc tường lửa hệ điều hành trên Windows đòi hỏi quyền quản trị viên cao cấp, cần hoàn thiện giải pháp phân quyền an toàn để tránh xung đột với các tiến trình bảo vệ nội tại của hệ điều hành.

---

## 3. Kế hoạch và nhiệm vụ trọng tâm tuần tiếp theo

- Xây dựng cơ chế trích xuất đoạn văn rút gọn thông minh trước khi đưa vào mô hình ngôn ngữ lớn để giảm tải số lượng token và tăng tốc độ suy luận trên phần cứng cục bộ.
- Thiết lập bộ nhớ đệm cục bộ bền vững cho các chỉ số đã được đối soát qua API công cộng nhằm khắc phục triệt để vấn đề giới hạn tần suất truy vấn.
- Hoàn thiện kịch bản kiểm thử xâm nhập tự động mô phỏng các đòn tấn công web phổ biến để đo lường định lượng tỷ lệ chặn thành công của hệ thống trước và sau khi kích hoạt kỹ năng phòng thủ.
- Viết tài liệu báo cáo kỹ thuật chi tiết theo đúng cấu trúc đề cương đồ án chuyên ngành và chuẩn bị slide thuyết trình demo báo cáo trực tiếp với giảng viên hướng dẫn.
