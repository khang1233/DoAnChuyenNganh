# BÁO CÁO TIẾN ĐỘ THỰC HIỆN ĐỒ ÁN CHUYÊN NGÀNH THEO TỪNG TUẦN

- **Tên đề tài**: Tự động hóa quy trình CTI và sinh quy tắc phòng thủ ứng dụng AI Agent
- **Giảng viên hướng dẫn**: Thầy Đinh Phương Nam
- **Nhóm sinh viên thực hiện**:
  - Nguyễn Phi Phúc - MSSV: 2387701131 - Lớp: 23DATA1 - Nhóm trưởng
  - Trần Minh Khang - MSSV: 2387700027 - Lớp: 23DATA1 - Thành viên
  - Nguyễn Nhật Lâm - MSSV: 2387700036 - Lớp: 23DATA1 - Thành viên
- **Ngành**: An toàn thông tin
- **Chuyên ngành**: An toàn thông tin

## Bảng chữ viết tắt

| Ký hiệu | Thuật ngữ đầy đủ | Ý nghĩa trong đề tài |
| :--- | :--- | :--- |
| CTI | Cyber Threat Intelligence | Tình báo mối đe dọa an ninh mạng |
| IOC | Indicator of Compromise | Chỉ số nhận diện xâm nhập nguy hại |
| LLM | Large Language Model | Mô hình ngôn ngữ lớn chạy cục bộ qua Ollama |
| xAI | Explainable AI | Giải trình bằng chứng trích dẫn nguyên văn cho từng chỉ số |
| AST | Abstract Syntax Tree | Cây cú pháp trừu tượng để kiểm tra hợp lệ mã nguồn Python |
| SAST | Static Application Security Testing | Kiểm thử bảo mật mã nguồn tĩnh |
| TP / FP / FN | True Positive / False Positive / False Negative | Phát hiện đúng / Báo nhầm / Bỏ sót |

---

## Tuần 1: Từ 12/10/2026 đến 18/10/2026

### 1. Nội dung công việc thực hiện
- Khởi tạo môi trường phát triển Python, thiết lập kho lưu trữ mã nguồn trên GitHub và phân chia nhiệm vụ cho 3 thành viên.
- Nghiên cứu quy trình tự động hóa tình báo an ninh mạng CTI và phương pháp dùng mô hình ngôn ngữ lớn cục bộ để trích xuất IOC kèm bằng chứng.
- Thiết kế chuẩn cấu trúc gói kỹ năng tác tử Agentic Skill gồm tệp hướng dẫn `SKILL.md`, tệp mô tả `manifest.json`, kịch bản thực thi `scripts/` và thư mục tham chiếu `references/`.

### 2. Kết quả đạt được
- Thống nhất phạm vi đề tài theo luồng xử lý từ bản tin CTI thô sang trích xuất IOC có giải trình và đóng gói thành gói kỹ năng tác tử.
- Hoàn tất khung thư mục dự án trên GitHub và thống nhất quy ước cam kết mã nguồn trong nhóm.

---

## Tuần 2: Từ 19/10/2026 đến 25/10/2026

### 1. Nội dung công việc thực hiện
- Xây dựng lược đồ cơ sở dữ liệu SQLite cục bộ để lưu trữ toàn văn bản tin, ngày xuất bản, nguồn tin và các chỉ số IOC đã trích xuất.
- Kết nối thử nghiệm nguồn cấp RSS và trang chuyên khảo của 6 đơn vị tình báo an ninh mạng uy tín.
- Triển khai hàm làm sạch dữ liệu, chuẩn hóa định dạng ngày giờ và loại bỏ bản tin trùng lặp theo đường dẫn và tiêu đề.

### 2. Kết quả đạt được
- Tích hợp hoàn chỉnh 6 nguồn CTI gồm The Hacker News, CISA KEV Catalog, Bleeping Computer, Check Point Research, Kaspersky Securelist và The DFIR Report.
- Vận hành ổn định cơ sở dữ liệu SQLite cục bộ sẵn sàng phục vụ bước phân tích tự động.

---

## Tuần 3: Từ 26/10/2026 đến 01/11/2026

### 1. Nội dung công việc thực hiện
- Hoàn thiện mô-đun thu thập toàn văn bản tin tự động và nạp kho lưu trữ lịch sử nhiều năm để phục vụ thử nghiệm.
- Xây dựng bộ phân tích biểu thức chính quy nhận diện bước đầu địa chỉ IP, tên miền, đường dẫn URL, mã băm MD5 và SHA256 cùng mã định danh CVE.
- Xây dựng tập danh sách trắng hạ tầng công cộng và mạng nội bộ để tránh chặn nhầm các dịch vụ thiết yếu như máy chủ DNS 8.8.8.8 hay 1.1.1.1.

### 2. Kết quả đạt được
- Kho tri thức lịch sử `cti_multi_source_archive_full_corpus.sqlite` đạt hơn 7.450 bài báo toàn văn, trong đó có hơn 1.170 bài thuộc nửa đầu năm 2026.
- Thiết lập thành công cơ chế lọc chỉ số an toàn fail-closed và khử làm mờ defang cho các định dạng như `[.]` hoặc `hxxps`.

---

## Tuần 4: Từ 02/11/2026 đến 08/11/2026

### 1. Nội dung công việc thực hiện
- Xây dựng giao diện giám sát trực quan tại cổng 8765 kết hợp quy trình nạp bài báo theo thời gian thực.
- Tích hợp mô hình ngôn ngữ lớn cục bộ qua Ollama trên máy trạm sử dụng card đồ họa AMD Radeon RX 6600 8GB VRAM.
- Xây dựng cơ chế truy vết xAI đính kèm câu trích dẫn nguyên văn từ bài báo cho từng chỉ số IOC mà tác tử AI trích xuất được.
- Rà soát định hướng chuyên môn cùng giảng viên hướng dẫn:
  - Loại bỏ hoàn toàn phần kiểm thử mã nguồn tĩnh SAST và phần sinh luật tĩnh rời rạc, tập trung trọn vẹn vào quy trình từ bản tin CTI sang trích xuất IOC có bằng chứng xAI và đóng gói thành Agentic Skill hoàn chỉnh.
  - Bổ sung bộ tiêu chuẩn đo lường định lượng khách quan để đánh giá độ chính xác của tác tử AI trên tập 50 bài báo gán nhãn thủ công.

### 2. Khó khăn kỹ thuật phát sinh
- Khi yêu cầu mô hình cục bộ trả về cùng lúc tài liệu Markdown và mã nguồn Python trong một chuỗi JSON, mô hình thường phát sinh lỗi thoát ký tự dẫn đến hỏng cấu trúc.
- Một số bản tin CTI chỉ làm mờ phần đuôi tên miền như `popnike-share[.]com` khiến bộ lọc tên miền 3 nhãn ban đầu bị sót khi đối chiếu câu trích dẫn xAI.
- Bài báo dài đặt danh sách IOC ở cuối bài dễ bị cắt bỏ nếu chỉ truyền phần đầu văn bản vào cửa sổ ngữ cảnh giới hạn của mô hình cục bộ.

---

## Tuần 5: Từ 09/11/2026 đến 15/11/2026

### 1. Mục tiêu trọng tâm của tuần
- Hoàn thành toàn diện tập dữ liệu đối chuẩn Ground Truth gồm 50 bản tin an ninh mạng thực tế đầu năm 2026 được đọc kiểm và gắn nhãn thủ công 100%.
- Tối ưu hóa pipeline tác tử AI cục bộ sử dụng mô hình `qwen3:8b` qua Ollama, giải quyết triệt để các xung đột ngữ cảnh, nâng độ chính xác trích xuất từ 66,7% lên mức trên 98%.
- Xây dựng giao diện web Workbench phục vụ gán nhãn thủ công và so sánh quy mô lớn tự động tại cổng 8780.
- Thực thi toàn diện bộ đo lường khoa học 3 bảng định lượng: độ đúng trích xuất IOC, tỷ lệ đóng gói Agentic Skill hợp lệ và tỷ lệ thực thi phát hiện mã độc.

### 2. Phân công nhiệm vụ và nội dung thực hiện chi tiết
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

### 3. Kết quả thực nghiệm định lượng trên 50 bản tin
Toàn bộ quá trình chạy tự động 50 bản tin với mô hình `qwen3:8b` hoàn tất trong khoảng 91 phút, đạt tốc độ trung bình 109,2 giây mỗi bài với các kết quả cụ thể:

- **Bảng 1 - Độ đúng trích xuất IOC đối chiếu Ground Truth**:
  - Trích xuất 706 chỉ báo, ghi nhận 695 chỉ báo đúng TP, 11 chỉ báo dư FP và 73 chỉ báo sót FN.
  - **Precision đạt 98,44%**, **Recall đạt 90,49%**, **F1-Score đạt 94,30%**.
  - Tỷ lệ bằng chứng trích dẫn nguyên văn xAI Grounding đạt **100,0%** trên 706/706 chỉ báo.
  - Có 25 trên 50 bài đạt điểm tuyệt đối 100% ở cả hai tiêu chí Precision và Recall.
  - Có 41 trên 50 bài đạt 0 chỉ báo dương tính giả.
- **Bảng 2 - Tỷ lệ hợp lệ cấu trúc gói Agentic Skill**:
  - Đạt tỷ lệ tuyệt đối **100,0%** hợp lệ cho toàn bộ 50 bài trên cả 4 thành phần: `SKILL.md` tuân thủ YAML frontmatter cùng quy trình SOP, `manifest.json` chuẩn lược đồ JSON, `scripts/verify_threat.py` vượt qua kiểm tra cây cú pháp Python AST và `references/c2_ip_indicators.txt` sạch danh sách trắng.
- **Bảng 3 - Tỷ lệ thực thi phát hiện mối đe dọa trên mẫu thử**:
  - Tỷ lệ phát hiện đạt **98,00%** trên nhật ký sự kiện, **96,00%** trên bộ đệm nhị phân và **83,72%** trên chỉ báo mạng C2.
  - Tỷ lệ báo nhầm trên toàn bộ các tập mẫu thử âm tính sạch đạt **0,0%**.

### 4. Các vấn đề kỹ thuật đã xử lý thành công
- Xung đột giữa biểu thức chính quy thô và phán đoán ngữ cảnh của AI: Gỡ bỏ việc ép nạp lại dữ liệu văn xuôi, đưa cơ chế tự kiểm chứng tính nhất quán giữa nhận xét phân tích và danh sách IOC giữ lại.
- Lỗi cắt cụt chuỗi URL làm mờ: Tinh chỉnh lại biểu thức nhận diện URL hỗ trợ đầy đủ các dạng làm mờ dấu chấm, hai chấm và phân định rõ ràng giữa tên miền dịch vụ chia sẻ và đường dẫn tải payload cụ thể.
- Lọc nhiễu chuỗi thập lục phân: Tách biệt mã băm tệp tin thực thụ khỏi mã định danh Gist, mã phân vùng lưu trữ đám mây và chuỗi khóa đối xứng.
- Tối ưu hóa tải tài nguyên tính toán: Cố định kích thước ngữ cảnh ở mức 8192 token để duy trì toàn bộ dữ liệu suy luận trong bộ nhớ VRAM của GPU, loại bỏ hiện tượng tràn bộ nhớ làm chậm hệ thống.

### 5. Kế hoạch tuần tiếp theo
- Tổng hợp và hoàn thiện báo cáo đồ án chuyên ngành bản chính thức, bổ sung các bảng biểu và phân tích nguyên nhân sai số còn tồn tại.
- Chuẩn bị slide trình chiếu và kịch bản thuyết minh thực nghiệm đối chiếu trước hội đồng đánh giá.
- Đóng gói bản cài đặt thử nghiệm độc lập của công cụ Workbench phục vụ việc kiểm chứng kết quả khách quan.
