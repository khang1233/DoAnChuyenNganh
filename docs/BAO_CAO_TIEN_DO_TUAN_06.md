# BÁO CÁO TIẾN ĐỘ HÀNG TUẦN - TUẦN 06

- **Môn học**: Đồ án chuyên ngành
- **Tên đề tài**: Tự động hóa quy trình CTI và sinh quy tắc phòng thủ ứng dụng AI Agent
- **Giai đoạn**: Chuẩn hóa bộ chỉ số đo lường chất lượng Agent theo tiêu chuẩn Đồ án HUTECH, hoàn thiện trung tâm điều khiển hệ thống 1-click và chuẩn bị hồ sơ nghiệm thu
- **Thời gian thực hiện**: Từ 16/11/2026 đến 22/11/2026
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
| AST | Abstract Syntax Tree, cây cú pháp trừu tượng dùng kiểm tra mã nguồn Python |

---

## 2. Mục tiêu trọng tâm của tuần 06

- Chuẩn hóa toàn bộ số liệu thực nghiệm trên tập 50 bản tin CTI theo bảng tiêu chí chất lượng Agent của Khoa Công nghệ thông tin HUTECH, phân định rõ ràng 4 nhóm nhận định kỹ thuật gồm Đúng, Sai, Bịa và Bỏ sót.
- Hoàn thiện và chuẩn hóa bộ tệp lệnh điều khiển khởi động và tắt hệ thống 1-click, tích hợp trọn vẹn cả 4 dịch vụ gồm Ollama GPU, Web Dashboard Tổng, WAF Reverse Proxy L7 và Phân hệ So Sánh 50 bài.
- Xây dựng cơ chế tắt an toàn, giải phóng 100% bộ nhớ GPU VRAM và RAM hệ thống, đóng sạch các cổng mạng 8765, 8766, 8780 và 11434, bảo đảm không còn tiến trình chạy ngầm làm nóng máy.
- Hoàn thiện tài liệu nghiệm thu kỹ thuật và chuẩn bị nội dung thuyết minh phục vụ buổi báo cáo tiến độ với Giảng viên hướng dẫn.

---

## 3. Phân công nhiệm vụ và tiến độ thực hiện chi tiết

- **Trần Minh Khang**:
  - Đối chiếu toàn bộ 768 chỉ báo kỹ thuật của tập Ground Truth với kết quả thực thi của mô hình `qwen3:8b`, lập bảng phân loại chi tiết theo 4 nhóm nhận định của đồ án: Đúng 695 mục, Sai 11 mục, Bịa 0 mục và Bỏ sót 73 mục.
  - Phân tích nguyên nhân sai số của 11 chỉ báo dương tính giả và 73 chỉ báo bỏ sót, ghi nhận bài học kinh nghiệm để đưa vào tài liệu nghiệm thu.
  - Xây dựng bảng đối chuẩn chất lượng Agent, cập nhật đồng bộ các số liệu Precision 98,44%, Recall 90,49%, F1 94,30% vào báo cáo kỹ thuật.

- **Nguyễn Phi Phúc**:
  - Tái cấu trúc bộ điều khiển trung tâm `cti_core/system_ctl.py`, tích hợp cổng 8780 của Phân hệ So Sánh 50 bài vào vòng đời quản lý chung cùng cổng 8765 và 8766.
  - Chuẩn hóa script `1_BAT_HE_THONG.bat` và `2_TAT_HE_THONG.bat`, bổ sung lệnh kiểm tra trạng thái cổng mạng sau khi tắt nhằm xác nhận hệ thống đã đóng sạch sẽ.
  - Kiểm thử cơ chế giải phóng tiến trình trên Windows bằng lệnh PowerShell cưỡng chế theo mã tiến trình và số hiệu cổng mạng.

- **Nguyễn Nhật Lâm**:
  - Hoàn thiện giao diện điều hướng hai chiều giữa Web Dashboard Tổng và Phân hệ So Sánh 50 bài, bổ sung nút chuyển đổi trực tiếp trên thanh TopNav của cả hai máy chủ.
  - Biên dịch toàn bộ tài liệu báo cáo tuần và báo cáo thực nghiệm 50 bài sang định dạng Word (.docx) chuẩn khổ A4, kiểm tra định dạng bảng biểu và tính nhất quán văn bản.
  - Đồng bộ mã nguồn, cấu hình và báo cáo lên kho lưu trữ GitHub phục vụ việc báo cáo tiến độ tuần 06.

---

## 4. Kết quả nghiệm thu và bộ chỉ số chất lượng Agent theo tiêu chuẩn HUTECH

### 4.1. Bảng đối chiếu chỉ số đo chất lượng Agent

Từng nhận định của tác tử AI được phân loại thành 4 nhóm theo quy chuẩn đánh giá: Đúng (TP) có 695 chỉ báo; Sai (FP) có 11 chỉ báo; Bịa (Hallucination) có 0 chỉ báo; Bỏ sót (FN) có 73 chỉ báo.

| Nhóm tiêu chí | Tên chỉ số | Công thức xác định | Mục tiêu chuẩn (HUTECH) | Kết quả thực tế của Agent | Đánh giá đạt chuẩn |
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
| **Hiệu quả** | **Tài nguyên và chi phí vận hành** | Trung bình mỗi bài báo | Ghi đủ, so phương án | 109,2s/bài, 5,2 GB VRAM, **0 VNĐ chi phí API** | **Vận hành On-Premise tối ưu** |

### 4.2. Phân tích chi tiết kết quả trích xuất theo từng loại chỉ báo

| Loại IOC | Số lượng Ground Truth | AI trích xuất | Đúng (TP) | Sai (FP) | Bỏ sót (FN) | Precision | Recall | F1-Score |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| IP | 67 | 66 | 64 | 2 | 3 | 96,97% | 95,52% | 96,24% |
| DOMAIN | 218 | 163 | 163 | 0 | 55 | 100,00% | 74,77% | 85,56% |
| URL | 119 | 115 | 106 | 9 | 13 | 92,17% | 89,08% | 90,60% |
| MD5 | 287 | 286 | 286 | 0 | 1 | 100,00% | 99,65% | 99,83% |
| SHA256 | 10 | 9 | 9 | 0 | 1 | 100,00% | 90,00% | 94,74% |
| CVE | 67 | 67 | 67 | 0 | 0 | 100,00% | 100,00% | 100,00% |
| **Tổng hợp Micro** | **768** | **706** | **695** | **11** | **73** | **98,44%** | **90,49%** | **94,30%** |

- Tỷ lệ có bằng chứng nguyên văn đạt 706 trên 706 chỉ báo, tương đương 100,0%.
- Có 25 trên 50 bài đạt điểm tuyệt đối 100% ở cả Precision và Recall.
- Có 41 trên 50 bài đạt 0 chỉ báo dương tính giả.

---

## 5. Chuẩn hóa hệ thống điều khiển khởi động và tắt an toàn

Hệ thống điều khiển được chuẩn hóa thành hai tệp lệnh thao tác trực tiếp từ thư mục gốc của dự án:

### 5.1. Tệp lệnh khởi động: `1_BAT_HE_THONG.bat`
- Cơ chế thực thi:
  - Tự động kiểm tra môi trường Python 3.10 trở lên trên hệ điều hành.
  - Dọn dẹp các tiến trình tồn đọng cũ trên các cổng mạng liên quan trước khi nạp mới.
  - Kích hoạt dịch vụ Ollama GPU Server tại cổng 11434 với biến môi trường lưu mô hình cục bộ.
  - Khởi động đồng thời máy chủ Web Dashboard Tổng tại cổng 8765, WAF Reverse Proxy L7 tại cổng 8766 và Phân hệ So Sánh 50 bài tại cổng 8780.
  - Tự động mở trình duyệt web tại địa chỉ `http://127.0.0.1:8765` và hiển thị bảng điều khiển tương tác trên cửa sổ dòng lệnh.
- Các tùy chọn điều khiển trực tiếp trên giao diện dòng lệnh:
  - Phím 1: Mở lại Web Dashboard Tổng trên trình duyệt web.
  - Phím 2: Mở Bảng So Sánh 50 bài trên trình duyệt web.
  - Phím 3: Tắt toàn bộ hệ thống và thu hồi tài nguyên.
  - Phím 4: Khởi động lại toàn bộ hệ thống.
  - Phím 0: Đóng cửa sổ lệnh nhưng vẫn duy trì hệ thống chạy ngầm.

### 5.2. Tệp lệnh tắt sạch hệ thống: `2_TAT_HE_THONG.bat`
- Cơ chế thực thi:
  - Gọi lệnh `python cti_core/system_ctl.py stop` để dừng toàn bộ tiến trình có kiểm soát.
  - Chấm dứt các tiến trình `ollama.exe` và `ollama_llama_server.exe`, giải phóng 100% bộ nhớ GPU VRAM.
  - Quét và đóng các tiến trình Python mang cờ nhận diện `live_dashboard_app` và `labeler_server`.
  - Quét cưỡng chế theo mã PID đang lắng nghe trên toàn bộ 4 cổng mạng gồm 8765, 8766, 8780 và 11434.
  - Kiểm tra lại trạng thái sau khi tắt và in thông báo `CTI Defense Status: OFFLINE` xác nhận hệ thống đã đóng hoàn toàn, không còn tác vụ chạy ngầm.

### 5.3. Liên kết chuyển đổi nhanh giữa hai giao diện web
- Web Dashboard Tổng cung cấp nút bấm `So Sánh 50 Bài (8780)` trên thanh TopNav dẫn trực tiếp sang trang đối chuẩn Ground Truth.
- Phân hệ So Sánh cung cấp nút bấm `Về Dashboard Tổng (8765)` giúp người dùng dễ dàng luân chuyển giữa phân hệ vận hành tự hành và phân hệ nghiên cứu đánh giá.

---

## 6. Kế hoạch tuần tiếp theo (Tuần 07)

- Hoàn thiện toàn bộ các chương của báo cáo Đồ án chuyên ngành bản hoàn chỉnh.
- Thiết kế bộ slide báo cáo bảo vệ đề tài trước Hội đồng đánh giá khoa học.
- Đóng gói tài liệu bàn giao sản phẩm, kịch bản thuyết minh trực tiếp và hướng dẫn kiểm thử độc lập.
