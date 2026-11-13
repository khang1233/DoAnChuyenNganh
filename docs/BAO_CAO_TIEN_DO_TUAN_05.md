# BÁO CÁO TIẾN ĐỘ HÀNG TUẦN - TUẦN 05

- **Môn học**: Đồ án chuyên ngành
- **Tên đề tài**: Tự động hóa quy trình CTI và sinh quy tắc phòng thủ ứng dụng AI Agent
- **Giai đoạn**: Hoàn thiện tập đối chuẩn Ground Truth 50 bản tin CTI năm 2026, tối ưu hóa độ chính xác pipeline Local AI Agent và thực nghiệm định lượng 3 bảng
- **Thời gian thực hiện**: Từ 09/11/2026 đến 15/11/2026
- **Giảng viên hướng dẫn**: Thầy Đinh Phương Nam
- **Nhóm sinh viên thực hiện**:
  - Nguyễn Phi Phúc - MSSV: 2387701131 - Lớp: 23DATA1 - Nhóm trưởng
  - Trần Minh Khang - MSSV: 2387700027 - Lớp: 23DATA1 - Thành viên
  - Nguyễn Nhật Lâm - MSSV: 2387700036 - Lớp: 23DATA1 - Thành viên

---

## 1. Bảng chữ viết tắt và thuật ngữ

| Ký hiệu / Thuật ngữ | Diễn giải đầy đủ |
| :--- | :--- |
| CTI | Cyber Threat Intelligence, thông tin tình báo mối đe dọa an ninh mạng |
| IOC | Indicator of Compromise, chỉ báo xâm phạm hệ thống gồm IP, Domain, URL, Hash và CVE |
| LLM | Large Language Model, mô hình ngôn ngữ lớn chạy cục bộ qua Ollama |
| Ground Truth | Tập đáp án chuẩn được đọc kiểm và xác thực thủ công trên từng bài báo |
| TP | True Positive, số chỉ báo AI trích xuất trùng khớp với Ground Truth |
| FP | False Positive, số chỉ báo AI trích xuất dư hoặc nhận nhầm từ thực thể sạch |
| FN | False Negative, số chỉ báo có trong Ground Truth nhưng AI bỏ sót |
| Precision | Độ chính xác, tỷ lệ chỉ báo đúng trên tổng số chỉ báo AI xuất ra |
| Recall | Độ phủ, tỷ lệ chỉ báo thu được trên tổng số chỉ báo thực tế trong Ground Truth |
| F1-Score | Điểm trung bình điều hòa giữa Precision và Recall |
| xAI Grounding | Cơ chế đối chiếu ngược từng IOC với câu văn nguyên văn trong bài báo gốc |
| CDN | Content Delivery Network, mạng phân phối nội dung dùng chung nhiều trang web |
| AST | Abstract Syntax Tree, cây cú pháp trừu tượng dùng kiểm tra mã nguồn Python |

---

## 2. Mục tiêu trọng tâm của tuần
- Hoàn thành toàn diện tập dữ liệu đối chuẩn Ground Truth gồm 50 bản tin an ninh mạng thực tế đầu năm 2026 được đọc kiểm và gắn nhãn thủ công 100%.
- Tối ưu hóa pipeline tác tử AI cục bộ sử dụng mô hình `qwen3:8b` qua Ollama, giải quyết triệt để các xung đột ngữ cảnh, nâng độ chính xác trích xuất từ 66,7% lên mức trên 98%.
- Xây dựng giao diện web Workbench phục vụ gán nhãn thủ công và so sánh quy mô lớn tự động tại cổng 8780.
- Thực thi toàn diện bộ đo lường khoa học 3 bảng định lượng: độ đúng trích xuất IOC, tỷ lệ đóng gói Agentic Skill hợp lệ và tỷ lệ thực thi phát hiện mã độc.

---

## 3. Nội dung thực hiện và phân công chi tiết

- **Trần Minh Khang**:
  - Trực tiếp đọc toàn văn, rà soát và hoàn thiện 100% tập dữ liệu Ground Truth cho trọn bộ 50 bản tin CTI đầu năm 2026 trong `ground_truth_50.json`, bóc tách chính xác 768 chỉ báo kỹ thuật gồm 67 địa chỉ IP, 218 tên miền, 119 đường dẫn URL, 287 mã băm MD5, 10 mã băm SHA256 và 67 mã định danh CVE.
  - Phân tích nguyên nhân gốc rễ gây sụt giảm Precision ở bản tin số 01 và tiến hành tối ưu hóa thuật toán lọc ngữ cảnh trong `cti_local_agent_pipeline.py`.
  - Kiểm thử thực tế các bản tin phức tạp có bảng mã băm dài như bài số 14, bài số 49 và các biến thể làm mờ ký tự đặc biệt.

- **Nguyễn Phi Phúc**:
  - Tái cấu trúc pipeline xử lý tác tử cục bộ `cti_local_agent_pipeline.py`, phân tách rõ ràng lược đồ JSON đầu ra với trường `excluded_non_malicious` để mô hình tự động phân loại dịch vụ API công cộng bị lợi dụng, tên miền trang web nạn nhân và dải mạng CDN dùng chung.
  - Xây dựng cơ chế trích xuất mã băm sạch `_extract_clean_hashes` nhằm loại bỏ chuỗi hex nằm trong tham số URL, mã bucket đám mây và chuỗi salt giải mã.
  - Thiết lập cơ chế bảo vệ danh sách trắng mạng theo nguyên tắc Fail-Closed, tự động nhận diện 15 dải mạng Anycast của Cloudflare và địa chỉ liên kết cục bộ 169.254.x.x.

- **Nguyễn Nhật Lâm**:
  - Phát triển và hoàn thiện giao diện web Workbench chuyên dụng tại `labeler_server.py` cổng 8780 với hai phân hệ: phân hệ hỗ trợ đọc báo gán nhãn từng bài và phân hệ bảng đối chiếu tự động 50 bài.
  - Tích hợp tính năng chạy hàng loạt toàn bộ 50 bài với thanh tiến trình đo đạc thời gian thực từng giây, ước lượng thời gian hoàn tất, hệ thống nhật ký 8 bước gần nhất và cơ chế dừng an toàn.
  - Khắc phục triệt để lỗi tràn bảng giao diện bằng `table-layout: fixed`, ngắt dòng `overflow-wrap: anywhere` và áp dụng kỹ thuật khóa luồng kèm ghi tệp nguyên tử tránh xung đột dữ liệu.

---

## 4. Kết quả đạt được và bảng số liệu định lượng

Toàn bộ quá trình chạy tự động 50 bản tin với mô hình `qwen3:8b` hoàn tất trong khoảng 91 phút, đạt tốc độ trung bình 109,2 giây mỗi bài với các kết quả cụ thể:

### 4.1. Bảng 1: Độ đúng trích xuất IOC đối chiếu Ground Truth gán tay

| Loại IOC | Số lượng Ground Truth | AI trích xuất | TP | FP | FN | Precision | Recall | F1-Score |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| IP | 67 | 66 | 64 | 2 | 3 | 96,97% | 95,52% | 96,24% |
| DOMAIN | 218 | 163 | 163 | 0 | 55 | 100,00% | 74,77% | 85,56% |
| URL | 119 | 115 | 106 | 9 | 13 | 92,17% | 89,08% | 90,60% |
| MD5 | 287 | 286 | 286 | 0 | 1 | 100,00% | 99,65% | 99,83% |
| SHA256 | 10 | 9 | 9 | 0 | 1 | 100,00% | 90,00% | 94,74% |
| CVE | 67 | 67 | 67 | 0 | 0 | 100,00% | 100,00% | 100,00% |
| **Tổng hợp Micro** | **768** | **706** | **695** | **11** | **73** | **98,44%** | **90,49%** | **94,30%** |

- Tỷ lệ bằng chứng trích dẫn nguyên văn xAI Grounding đạt **100,0%** trên 706/706 chỉ báo.
- Có 25 trên 50 bài đạt điểm tuyệt đối 100% ở cả hai tiêu chí Precision và Recall.
- Có 41 trên 50 bài đạt 0 chỉ báo dương tính giả.

### 4.2. Bảng 2: Tỷ lệ hợp lệ cấu trúc gói Agentic Skill

| Thành phần Skill | Cơ chế kiểm định | Đạt cú pháp thô từ LLM | Hợp lệ sau kiểm chuẩn | Tỷ lệ cuối |
| :--- | :--- | :---: | :---: | :---: |
| `SKILL.md` | PyYAML Frontmatter và cấu trúc SOP | 47/50 đạt 94,0% | 50/50 | 100,00% |
| `manifest.json` | Đối chiếu JSON Schema | 43/50 đạt 86,0% | 50/50 | 100,00% |
| `scripts/verify_threat.py` | Phân tích Python AST và kiểm thử hợp đồng hàm | 37/50 đạt 74,0% | 50/50 | 100,00% |
| `references/c2_ip_indicators.txt` | Kiểm tra hợp lệ IPv4, tên miền và whitelist sạch | 50/50 đạt 100,0% | 50/50 | 100,00% |

### 4.3. Bảng 3: Tỷ lệ thực thi phát hiện mối đe dọa trên mẫu thử

| Kênh kiểm thử | Đối tượng thực thi | Tổng số bộ mẫu | Phát hiện mẫu độc | Tỷ lệ phát hiện | Báo nhầm mẫu sạch |
| :--- | :--- | :---: | :---: | :---: | :---: |
| Nhật ký hành vi | Hàm `scan_artifact` truyền `log_event` | 50 | 49/50 | 98,00% | 0/50 |
| Bộ đệm nhị phân | Hàm `scan_artifact` truyền `payload_bytes` | 50 | 48/50 | 96,00% | 0/50 |
| Chỉ báo mạng C2 | Tập `c2_ip_indicators.txt` đối chiếu DNS sạch | 43 | 36/43 | 83,72% | 0/43 |

---

## 5. Các khúc mắc kỹ thuật đã xử lý thành công

- Xung đột giữa biểu thức chính quy thô và phán đoán ngữ cảnh của AI: Ban đầu thuật toán hậu xử lý ép nạp lại toàn bộ tên miền và IP tìm thấy từ regex vào kết quả cuối, khiến các dịch vụ API hợp pháp như `tronscanapi.com` ở bài số 01 bị biến thành dương tính giả dù AI đã nhận xét đúng trong phần phân tích ngữ cảnh. Nhóm đã loại bỏ việc ép nạp lại dữ liệu thô, bổ sung trường phân loại vai trò `excluded_non_malicious` và cơ chế kiểm tra tự nhất quán với nhận xét phân tích.
- Lỗi cắt cụt chuỗi URL làm mờ: Biểu thức nhận diện URL cũ chứa ký tự loại trừ dấu đóng ngoặc vuông khiến các đường dẫn defang dạng `[.]` bị ngắt quãng trước phần tên miền. Nhóm đã tinh chỉnh lại biểu thức chính quy hỗ trợ đầy đủ các chuẩn làm mờ, đồng thời thiết lập danh sách tên miền nền tảng dùng chung để không tách nhầm tên miền gốc khỏi đường dẫn tải mã độc cụ thể.
- Lọc nhiễu chuỗi thập lục phân: Cơ chế quét chuỗi 32 hoặc 64 ký tự hex ban đầu bắt nhầm mã định danh Gist, mã phân vùng lưu trữ đám mây, chuỗi salt giải mã của phần mềm độc hại và mã băm của tệp tin sạch có chú thích không độc hại. Nhóm đã phát triển bộ lọc vị trí ký tự và ngữ cảnh xung quanh để loại trừ triệt để các chuỗi này.
- Bảo vệ hạ tầng công cộng theo nguyên tắc Fail-Closed: Bổ sung kiểm tra địa chỉ liên kết cục bộ 169.254.x.x và nhận diện 15 dải mạng Anycast của Cloudflare để tránh chặn nhầm hạ tầng mạng diện rộng.
- Tối ưu hóa tải tài nguyên tính toán và giao diện: Cố định kích thước ngữ cảnh ở mức 8192 token để duy trì toàn bộ mô hình trong bộ nhớ VRAM của GPU, rút ngắn thời gian xử lý; đồng thời khắc phục lỗi tràn bảng trên giao diện web bằng việc cố định độ rộng cột và hỗ trợ ngắt dòng linh hoạt.

---

## 6. Kế hoạch tuần tiếp theo
- Tổng hợp và hoàn thiện báo cáo đồ án chuyên ngành bản chính thức, bổ sung các bảng biểu và phân tích nguyên nhân sai số còn tồn tại.
- Chuẩn bị slide trình chiếu và kịch bản thuyết minh thực nghiệm đối chiếu trước hội đồng đánh giá.
- Đóng gói bản cài đặt thử nghiệm độc lập của công cụ Workbench phục vụ việc kiểm chứng kết quả khách quan.
