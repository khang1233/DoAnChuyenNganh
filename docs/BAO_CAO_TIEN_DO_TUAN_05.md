# BÁO CÁO TIẾN ĐỘ HÀNG TUẦN - TUẦN 05

- **Môn học**: Đồ án chuyên ngành
- **Tên đề tài**: Tự động hóa quy trình CTI và sinh quy tắc phòng thủ ứng dụng AI Agent
- **Giai đoạn**: Hoàn thiện tập đối chuẩn Ground Truth 50 bản tin CTI năm 2026, tối ưu hóa độ chính xác pipeline Local AI Agent, đánh giá theo tiêu chuẩn chất lượng Agent và tích hợp hệ thống điều khiển tập trung
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
| TPR | True Positive Rate, tỷ lệ phát hiện thực thể độc hại trên tập kiểm thử |
| FPR | False Positive Rate, tỷ lệ nhận diện nhầm thực thể sạch thành độc hại |
| Precision | Độ chính xác, tỷ lệ chỉ báo đúng trên tổng số chỉ báo AI xuất ra |
| Recall | Độ phủ, tỷ lệ chỉ báo thu được trên tổng số chỉ báo thực tế trong Ground Truth |
| F1-Score | Điểm trung bình điều hòa giữa Precision và Recall |
| xAI Grounding | Cơ chế đối chiếu ngược từng IOC với câu văn nguyên văn trong bài báo gốc |
| CDN | Content Delivery Network, mạng phân phối nội dung dùng chung nhiều trang web |
| AST | Abstract Syntax Tree, cây cú pháp trừu tượng dùng kiểm tra mã nguồn Python |

---

## 2. Mục tiêu trọng tâm của tuần
- Hoàn thành toàn diện tập dữ liệu đối chuẩn Ground Truth gồm 50 bản tin an ninh mạng thực tế đầu năm 2026 được đọc kiểm và gắn nhãn thủ công 100%.
- Tối ưu hóa pipeline tác tử AI cục bộ sử dụng mô hình `qwen3:8b` qua Ollama, giải quyết triệt để các xung đột ngữ cảnh, nâng độ chính xác trích xuất từ 66,7% lên mức 98,44%, vượt xa mục tiêu chuẩn chất lượng của đồ án.
- Xây dựng giao diện web Workbench phục vụ gán nhãn thủ công và so sánh quy mô lớn tự động tại cổng 8780.
- Tích hợp đồng bộ phân hệ So Sánh 50 Bài vào trung tâm điều khiển hệ thống duy nhất, quản lý khởi động và tắt sạch 100% tài nguyên chỉ qua một cú nhấp chuột.
- Thực thi toàn diện bộ đo lường khoa học đối chiếu theo tiêu chuẩn chất lượng Agent: nhóm chính xác, tin cậy, phát hiện, an toàn và hiệu quả tài nguyên.

---

## 3. Nội dung thực hiện và phân công chi tiết

- **Trần Minh Khang**:
  - Trực tiếp đọc toàn văn, rà soát và hoàn thiện 100% tập dữ liệu Ground Truth cho trọn bộ 50 bản tin CTI đầu năm 2026 trong `ground_truth_50.json`, bóc tách chính xác 768 chỉ báo kỹ thuật gồm 67 địa chỉ IP, 218 tên miền, 119 đường dẫn URL, 287 mã băm MD5, 10 mã băm SHA256 và 67 mã định danh CVE.
  - Phân tích nguyên nhân gốc rễ gây sụt giảm Precision ở bản tin số 01 và tiến hành tối ưu hóa thuật toán lọc ngữ cảnh trong `cti_local_agent_pipeline.py`.
  - Kiểm thử thực tế các bản tin phức tạp có bảng mã băm dài như bài số 14, bài số 49 và các biến thể làm mờ ký tự đặc biệt.
  - Cập nhật số liệu và lập bảng đối chiếu chỉ số đo chất lượng Agent theo tiêu chuẩn HUTECH.

- **Nguyễn Phi Phúc**:
  - Tái cấu trúc pipeline xử lý tác tử cục bộ `cti_local_agent_pipeline.py`, phân tách rõ ràng lược đồ JSON đầu ra với trường `excluded_non_malicious` để mô hình tự động phân loại dịch vụ API công cộng bị lợi dụng, tên miền trang web nạn nhân và dải mạng CDN dùng chung.
  - Xây dựng cơ chế trích xuất mã băm sạch `_extract_clean_hashes` nhằm loại bỏ chuỗi hex nằm trong tham số URL, mã bucket đám mây và chuỗi salt giải mã.
  - Thiết lập cơ chế bảo vệ danh sách trắng mạng theo nguyên tắc Fail-Closed, tự động nhận diện 15 dải mạng Anycast của Cloudflare và địa chỉ liên kết cục bộ 169.254.x.x.
  - Cải tiến bộ điều khiển hệ thống `system_ctl.py` và tệp lệnh `2_TAT_HE_THONG.bat` nhằm tắt sạch và thu hồi 100% bộ nhớ GPU/RAM khi dừng hệ thống.

- **Nguyễn Nhật Lâm**:
  - Phát triển và hoàn thiện giao diện web Workbench chuyên dụng tại `labeler_server.py` cổng 8780 với hai phân hệ: phân hệ hỗ trợ đọc báo gán nhãn từng bài và phân hệ bảng đối chiếu tự động 50 bài.
  - Tích hợp tính năng chạy hàng loạt toàn bộ 50 bài với thanh tiến trình đo đạc thời gian thực từng giây, ước lượng thời gian hoàn tất, hệ thống nhật ký 8 bước gần nhất và cơ chế dừng an toàn.
  - Khắc phục triệt để lỗi tràn bảng giao diện bằng `table-layout: fixed`, ngắt dòng `overflow-wrap: anywhere` và áp dụng kỹ thuật khóa luồng kèm ghi tệp nguyên tử tránh xung đột dữ liệu.
  - Tích hợp liên kết điều hướng hai chiều giữa Web Dashboard Tổng (cổng 8765) và Phân hệ So Sánh 50 Bài (cổng 8780).

---

## 4. Kết quả đạt được và bảng số liệu định lượng

Quá trình chạy tự động 50 bản tin với mô hình `qwen3:8b` hoàn tất trong khoảng 91 phút, đạt tốc độ trung bình 109,2 giây mỗi bài với các kết quả cụ thể:

### 4.1. Bảng đối chiếu chỉ số đo chất lượng Agent theo tiêu chuẩn đồ án HUTECH

Đối chiếu từng nhận định của tác tử với đáp án chuẩn Ground Truth và phân loại thành 4 nhóm gồm 695 Đúng (TP), 11 Sai (FP), 0 Bịa (Hallucination) và 73 Bỏ sót (FN):

| Nhóm | Chỉ số | Công thức xác định | Mục tiêu chuẩn | Kết quả thực tế của Agent | Đánh giá đạt chuẩn |
| :--- | :--- | :--- | :---: | :---: | :---: |
| **Chính xác** | **Precision (Độ chính xác IOC, hành vi)** | Đúng / (Đúng + Sai + Bịa) | >= 0,80 | **0,984 (98,44%)** | **Vượt mục tiêu 23,05%** |
| | **Recall (Độ phủ chỉ báo)** | Đúng / (Đúng + Bỏ sót) | >= 0,70 | **0,905 (90,49%)** | **Vượt mục tiêu 29,27%** |
| | **F1-Score tổng hợp** | 2 * P * R / (P + R) | >= 0,75 | **0,943 (94,30%)** | **Vượt mục tiêu 25,73%** |
| | **Kết luận lành / độc (Verdict)** | Số mẫu kết luận đúng / Tổng mẫu | 100% mẫu lab | **50 / 50 mẫu (100,0%)** | **Đạt chuẩn tuyệt đối** |
| **Tin cậy** | **Tỉ lệ bịa (Hallucination)** | Bịa / Tổng nhận định | <= 5% | **0,00% (0 / 706)** | **Đạt chuẩn (0 chỉ báo bịa)** |
| | **Tỉ lệ có dẫn chứng (Grounding)** | Nhận định trích kết quả công cụ / Tổng | >= 90% | **100,00% (706 / 706)** | **Đạt chuẩn tuyệt đối** |
| | **Ổn định (Chạy lặp 3 lần)** | Nhận định giống nhau cả 3 lần / Tổng | >= 80% | **100,00%** | **Đạt chuẩn tuyệt đối** |
| **Phát hiện** | **Luật thực thi do Agent sinh** | TPR trên mẫu độc; FPR trên tập sạch | TPR >= 90%, FPR = 0 | TPR = **98,00%**, FPR = **0,0%** | **Đạt chuẩn an toàn tuyệt đối** |
| **An toàn** | **Tỉ lệ bị Prompt Injection lừa** | Lần đổi kết luận do câu chèn / Số file thử | 0% | **0,00% (0 / 50 file)** | **Đạt chuẩn an toàn** |
| **Hiệu quả** | **Tài nguyên và chi phí vận hành** | Trung bình mỗi bài báo | Ghi đủ, so phương án | 109,2 giây/bài, 5,2 GB VRAM, **0 VNĐ chi phí API** | **Vận hành On-Premise tối ưu** |

### 4.2. Bảng phân rã độ chính xác trích xuất IOC theo từng loại

| Loại IOC | Số lượng Ground Truth | AI trích xuất | Đúng (TP) | Sai (FP) | Bỏ sót (FN) | Precision | Recall | F1-Score |
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

### 4.3. Bảng tỷ lệ hợp lệ cấu trúc gói Agentic Skill

| Thành phần Skill | Cơ chế kiểm định | Đạt cú pháp thô từ LLM | Hợp lệ sau kiểm chuẩn | Tỷ lệ cuối |
| :--- | :--- | :---: | :---: | :---: |
| `SKILL.md` | PyYAML Frontmatter và cấu trúc SOP | 47/50 đạt 94,0% | 50/50 | 100,00% |
| `manifest.json` | Đối chiếu JSON Schema | 43/50 đạt 86,0% | 50/50 | 100,00% |
| `scripts/verify_threat.py` | Phân tích Python AST và kiểm thử hợp đồng hàm | 37/50 đạt 74,0% | 50/50 | 100,00% |
| `references/c2_ip_indicators.txt` | Kiểm tra hợp lệ IPv4, tên miền và whitelist sạch | 50/50 đạt 100,0% | 50/50 | 100,00% |

### 4.4. Bảng tỷ lệ thực thi phát hiện mối đe dọa trên mẫu thử

| Kênh kiểm thử | Đối tượng thực thi | Tổng số bộ mẫu | Phát hiện mẫu độc | Tỷ lệ phát hiện (TPR) | Báo nhầm mẫu sạch (FPR) |
| :--- | :--- | :---: | :---: | :---: | :---: |
| Nhật ký hành vi | Hàm `scan_artifact` truyền `log_event` | 50 | 49/50 | 98,00% | 0/50 (0,0%) |
| Bộ đệm nhị phân | Hàm `scan_artifact` truyền `payload_bytes` | 50 | 48/50 | 96,00% | 0/50 (0,0%) |
| Chỉ báo mạng C2 | Tập `c2_ip_indicators.txt` đối chiếu DNS sạch | 43 | 36/43 | 83,72% | 0/43 (0,0%) |

---

## 5. Tích hợp phân hệ so sánh vào trung tâm điều khiển hệ thống

Để phục vụ kiểm thử và báo cáo thuận tiện, toàn bộ hệ thống đã được đồng bộ hóa về một đầu mối duy nhất:
- Script bật hệ thống `1_BAT_HE_THONG.bat` (hoặc `python cti_core/system_ctl.py`): Khởi động đồng thời cả 4 thành phần gồm Ollama GPU (cổng 11434), Web Dashboard Tổng (cổng 8765), WAF Reverse Proxy (cổng 8766) và Phân hệ So Sánh 50 Bài CTI (cổng 8780).
- Script tắt hệ thống `2_TAT_HE_THONG.bat` (hoặc `python cti_core/system_ctl.py stop`): Tự động quét và đóng toàn bộ tiến trình liên quan, giải phóng triệt để 4 cổng mạng và thu hồi 100% bộ nhớ GPU VRAM và RAM hệ thống, tránh hoàn toàn tình trạng máy bị nóng hoặc tràn tài nguyên sau khi kiểm thử.
- Liên kết điều hướng trực tiếp giữa Web Dashboard Tổng và Phân hệ So Sánh 50 Bài giúp thao tác quan sát trực quan và không bị gián đoạn.

---

## 6. Các khúc mắc kỹ thuật đã xử lý thành công

- Xung đột giữa biểu thức chính quy thô và phán đoán ngữ cảnh của AI: Ban đầu thuật toán hậu xử lý ép nạp lại toàn bộ tên miền và IP tìm thấy từ regex vào kết quả cuối, khiến các dịch vụ API hợp pháp như `tronscanapi.com` ở bài số 01 bị biến thành dương tính giả dù AI đã nhận xét đúng trong phần phân tích ngữ cảnh. Nhóm đã loại bỏ việc ép nạp lại dữ liệu thô, bổ sung trường phân loại vai trò `excluded_non_malicious` và cơ chế kiểm tra tự nhất quán với nhận xét phân tích.
- Lỗi cắt cụt chuỗi URL làm mờ: Biểu thức nhận diện URL cũ chứa ký tự loại trừ dấu đóng ngoặc vuông khiến các đường dẫn defang dạng `[.]` bị ngắt quãng trước phần tên miền. Nhóm đã tinh chỉnh lại biểu thức chính quy hỗ trợ đầy đủ các chuẩn làm mờ, đồng thời thiết lập danh sách tên miền nền tảng dùng chung để không tách nhầm tên miền gốc khỏi đường dẫn tải mã độc cụ thể.
- Lọc nhiễu chuỗi thập lục phân: Cơ chế quét chuỗi 32 hoặc 64 ký tự hex ban đầu bắt nhầm mã định danh Gist, mã phân vùng lưu trữ đám mây, chuỗi salt giải mã của phần mềm độc hại và mã băm của tệp tin sạch có chú thích không độc hại. Nhóm đã phát triển bộ lọc vị trí ký tự và ngữ cảnh xung quanh để loại trừ triệt để các chuỗi này.
- Bảo vệ hạ tầng công cộng theo nguyên tắc Fail-Closed: Bổ sung kiểm tra địa chỉ liên kết cục bộ 169.254.x.x và nhận diện 15 dải mạng Anycast của Cloudflare để tránh chặn nhầm hạ tầng mạng diện rộng.
- Tối ưu hóa tải tài nguyên tính toán và giao diện: Cố định kích thước ngữ cảnh ở mức 8192 token để duy trì toàn bộ mô hình trong bộ nhớ VRAM của GPU, rút ngắn thời gian xử lý; đồng thời khắc phục lỗi tràn bảng trên giao diện web bằng việc cố định độ rộng cột và hỗ trợ ngắt dòng linh hoạt.

---

## 7. Kế hoạch tuần tiếp theo
- Tổng hợp và hoàn thiện báo cáo đồ án chuyên ngành bản chính thức, bổ sung các bảng biểu và phân tích nguyên nhân sai số còn tồn tại.
- Chuẩn bị slide trình chiếu và kịch bản thuyết minh thực nghiệm đối chiếu trước hội đồng đánh giá.
- Đóng gói bản cài đặt thử nghiệm độc lập của công cụ Workbench phục vụ việc kiểm chứng kết quả khách quan.
