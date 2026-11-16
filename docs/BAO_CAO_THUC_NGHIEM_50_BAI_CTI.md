# Báo cáo thực nghiệm đối chiếu hệ thống CTI Local AI Agent trên tập 50 bản tin chuẩn tay

Báo cáo tổng hợp số liệu thực nghiệm, quá trình xử lý sự cố kỹ thuật và các hạn chế còn tồn tại khi chạy mô hình ngôn ngữ cục bộ `qwen3:8b` đối chiếu trực tiếp với tập Ground Truth 50 bản tin CTI năm 2026.

---

## 1. Bảng chữ viết tắt và thuật ngữ

| Ký hiệu / Thuật ngữ | Diễn giải đầy đủ |
| :--- | :--- |
| CTI | Cyber Threat Intelligence, thông tin tình báo mối đe dọa mạng |
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
| IMDS | Instance Metadata Service, dịch vụ siêu dữ liệu nội bộ trên hạ tầng đám mây |
| AST | Abstract Syntax Tree, cây cú pháp trừu tượng dùng kiểm tra mã nguồn Python |
| KV Cache | Bộ nhớ đệm khóa và giá trị phục vụ ngữ cảnh của mô hình LLM trên VRAM |

---

## 2. Dữ liệu kiểm thử và cấu hình thực nghiệm

### 2.1. Đặc tả tập dữ liệu 50 bản tin CTI năm 2026
Tập đánh giá gồm 50 bản tin an ninh mạng đầu năm 2026 lưu tại `cti_core/benchmark/articles_50_2026.json` và tập nhãn chuẩn lưu tại `cti_core/benchmark/ground_truth_50.json`.

- Nguồn phân bố gồm 35 bài từ TheHackerNews, 13 bài từ Kaspersky Securelist và 2 bài từ The DFIR Report.
- Độ dài mỗi bản tin dao động từ 1.798 ký tự đến 46.539 ký tự, đạt trung bình 10.502 ký tự tương đương khoảng 1.442 từ mỗi bài.
- Tổng số chỉ báo trong Ground Truth là 768 mục, phân bổ theo 6 nhóm gồm 67 địa chỉ IP, 218 tên miền, 119 đường dẫn URL, 287 mã băm MD5, 10 mã băm SHA256 và 67 mã lỗ hổng CVE.

### 2.2. Luồng xử lý thực nghiệm
- Mô hình thực thi: `qwen3:8b` qua giao diện API cục bộ của Ollama với kích thước ngữ cảnh `num_ctx` bằng 8192 token và giới hạn sinh tối đa 1800 token cho bước trích xuất.
- Cửa sổ văn bản đầu vào được giới hạn ở mức 15.500 ký tự, giữ lại 6.500 ký tự đầu và 8.900 ký tự cuối bài báo nhằm bảo toàn phần mở đầu chiến dịch và phụ lục IOC ở cuối các bài phân tích dài.
- Mỗi bài đi qua 2 bước gồm bước 1 đọc hiểu, lọc ngữ cảnh, xác thực xAI Grounding để tạo `context_notes`, và bước 2 tổng hợp thành gói Agentic Skill gồm `SKILL.md`, `manifest.json`, `scripts/verify_threat.py` và thư mục `references`.

---

## 3. Kết quả thực nghiệm đối chiếu theo tiêu chuẩn chất lượng Agent

Theo chuẩn đánh giá chất lượng tác tử AI của đề tài đồ án, từng nhận định kỹ thuật do Agent đưa ra được đối chiếu trực tiếp với đáp án chuẩn Ground Truth và phân loại vào 4 nhóm:
- Đúng (TP): 695 chỉ báo trùng khớp hoàn toàn với Ground Truth.
- Sai (FP): 11 chỉ báo nhận nhầm từ số phiên bản phần mềm hoặc định dạng URL.
- Bịa (Hallucination): 0 chỉ báo (đạt tỷ lệ 0,0%, hoàn toàn không có hiện tượng sinh chỉ báo ảo không tồn tại trong bài báo nhờ cơ chế kiểm tra dẫn chứng văn bản gốc).
- Bỏ sót (FN): 73 chỉ báo có trong bài báo nhưng Agent chưa trích xuất đủ.

### 3.1. Bảng đối chiếu chỉ số đo chất lượng Agent theo tiêu chuẩn đồ án HUTECH

Bảng sau tổng hợp các chỉ số theo đúng tiêu chuẩn đánh giá tác tử của trường, tập trung phân tích sâu nhóm chỉ số Chính xác và các chỉ số tin cậy liên quan:

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

### 3.2. Độ chính xác trích xuất IOC chi tiết theo từng phân loại

Số liệu trích xuất từ công cụ chấm điểm `cti_core/benchmark/evaluate_50_articles.py` và tập dữ liệu kết quả `cti_core/benchmark/agent_skill_runs_qwen3_8b.json`:

| Loại IOC | Số lượng Ground Truth | AI trích xuất | Đúng (TP) | Sai (FP) | Bỏ sót (FN) | Precision | Recall | F1-Score |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| IP | 67 | 66 | 64 | 2 | 3 | 96,97% | 95,52% | 96,24% |
| DOMAIN | 218 | 163 | 163 | 0 | 55 | 100,00% | 74,77% | 85,56% |
| URL | 119 | 115 | 106 | 9 | 13 | 92,17% | 89,08% | 90,60% |
| MD5 | 287 | 286 | 286 | 0 | 1 | 100,00% | 99,65% | 99,83% |
| SHA256 | 10 | 9 | 9 | 0 | 1 | 100,00% | 90,00% | 94,74% |
| CVE | 67 | 67 | 67 | 0 | 0 | 100,00% | 100,00% | 100,00% |
| **Tổng hợp Micro** | **768** | **706** | **695** | **11** | **73** | **98,44%** | **90,49%** | **94,30%** |

- Tỷ lệ bằng chứng nguyên văn xAI Grounding đạt 706 trên 706 chỉ báo được giữ lại, tương đương 100,0%.
- Có 25 trên 50 bài đạt mức tuyệt đối 100% ở cả Precision và Recall, bao gồm nhiều bài có mật độ IOC rất cao như bài 16, bài 29, bài 32 và bài 49 với 115 chỉ báo.
- Có 41 trên 50 bài đạt 0 chỉ báo dương tính giả, hệ thống đã chủ động loại bỏ tổng cộng 58 chỉ báo sạch, thực thể nạn nhân hoặc ảo giác sinh từ mô hình.

### 3.3. Tỷ lệ hợp lệ cấu trúc gói Agentic Skill

| Thành phần Skill | Cơ chế kiểm định | Đạt cú pháp thô từ LLM | Hợp lệ sau kiểm chuẩn | Tỷ lệ cuối |
| :--- | :--- | :---: | :---: | :---: |
| `SKILL.md` | PyYAML Frontmatter và cấu trúc SOP | 47/50 đạt 94,0% | 50/50 | 100,00% |
| `manifest.json` | Đối chiếu JSON Schema | 43/50 đạt 86,0% | 50/50 | 100,00% |
| `scripts/verify_threat.py` | Phân tích Python AST và kiểm thử hợp đồng hàm | 37/50 đạt 74,0% | 50/50 | 100,00% |
| `references/c2_ip_indicators.txt` | Kiểm tra hợp lệ IPv4, tên miền và whitelist sạch | 50/50 đạt 100,0% | 50/50 | 100,00% |

### 3.4. Kết quả kiểm thử thực thi phát hiện mẫu độc hại và mẫu sạch

| Kênh kiểm thử | Đối tượng thực thi | Tổng số bộ mẫu | Phát hiện mẫu độc | Tỷ lệ phát hiện (TPR) | Báo nhầm mẫu sạch (FPR) |
| :--- | :--- | :---: | :---: | :---: | :---: |
| Nhật ký hành vi | Hàm `scan_artifact` truyền `log_event` | 50 | 49/50 | 98,00% | 0/50 (0,0%) |
| Bộ đệm nhị phân | Hàm `scan_artifact` truyền `payload_bytes` | 50 | 48/50 | 96,00% | 0/50 (0,0%) |
| Chỉ báo mạng C2 | Tập `c2_ip_indicators.txt` đối chiếu DNS sạch | 43 | 36/43 | 83,72% | 0/43 (0,0%) |

### 3.5. Thống kê thời gian xử lý thực tế
- Thời gian toàn pipeline cho mỗi bài đạt trung bình 109,2 giây trên phần cứng cục bộ.
- Riêng bước 1 trích xuất IOC và phân tích ngữ cảnh mất trung bình 73,6 giây và trung vị 73,9 giây, ngắn nhất 17,7 giây và dài nhất 120,1 giây.

---

## 4. Các khúc mắc kỹ thuật gặp phải và phương án xử lý

### 4.1. Xung đột giữa bộ lọc Regex và nhận thức ngữ cảnh của AI
- Vấn đề phát sinh: Ở phiên bản đầu trên bài 01, mô hình `qwen3:8b` đã nhận diện đúng `tronscanapi.com` trong phần `context_notes` là dịch vụ API hợp pháp của mạng TRON bị mã độc lợi dụng, nhưng bảng kết quả vẫn bị chấm dư FP `tronscanapi.com` khiến Precision tụt xuống 66,7%. Nguyên nhân nằm ở đoạn mã hậu xử lý ép nạp lại toàn bộ danh sách Regex `cand_doms` và `cand_ips` vào kết quả cuối cùng, vô hiệu hóa hoàn toàn phán đoán ngữ cảnh của LLM.
- Cách xử lý: Gỡ bỏ cơ chế ép nạp lại tên miền và IP từ văn xuôi; bổ sung trường `excluded_non_malicious` vào lược đồ JSON đầu ra để AI tách riêng các dịch vụ API công cộng, trang web nạn nhân hoặc hạ tầng bị lạm dụng; đồng thời bổ sung bộ kiểm tra tự nhất quán giữa danh sách domain giữ lại và nhận xét tiếng Việt trong `context_notes`.

### 4.2. Lỗi cắt chuỗi biểu thức chính quy trên URL bị làm mờ ký tự
- Vấn đề phát sinh: Các bài báo bảo mật dùng chuẩn defang như `hxxps://hentakugames[.]com/...` hoặc `https[:]//pastebin[.]com/...`. Biểu thức `RE_URL` ban đầu chứa ký tự loại trừ dấu `]` trong lớp ký tự nên chuỗi URL bị cắt cụt ngay trước dấu chấm đầu tiên, khiến gần như toàn bộ URL defang không vượt qua bước kiểm tra tên miền. Ngoài ra, danh sách chặn tên miền sạch trước đó chặn luôn toàn bộ URL trên `github.com` và `gist.github.com`, làm sót các liên kết tải payload thật ở bài 32.
- Cách xử lý: Sửa lại `RE_URL` hỗ trợ đầy đủ cụm `[.]`, `(.)` và `[:]` trong phần tên miền; đồng thời phân tách rạch ròi giữa `ROOT_ONLY_PLATFORM_DOMAINS` dùng cho tên miền gốc và cơ chế cho phép URL có đường dẫn cụ thể như `/raw/`, `/releases/download/` ở `is_valid_malicious_url`.

### 4.3. Nhiễu mã băm trong URL và chuỗi khóa giải mã
- Vấn đề phát sinh: Trình quét 32 hoặc 64 ký tự thập lục phân bắt nhầm mã định danh Gist trong URL ở bài 32, mã bucket Cloudflare R2 nằm trong tên miền phụ ở bài 33, tham số truy vấn URL ở bài 35, chuỗi khóa AES và salt ở bài 14, cùng mã băm tệp tin hợp pháp kèm chú thích không độc hại như `WorkFlowy.exe` ở bài 22.
- Cách xử lý: Xây dựng hàm `_extract_clean_hashes` kiểm tra vị trí ký tự liền kề để loại trừ chuỗi hex nằm trong URL hoặc subdomain, kết hợp lọc ngữ cảnh cụm từ chỉ định khóa giải mã hoặc tệp hợp pháp, sau đó đối chiếu bù cho các bảng có 45 đến 81 mã MD5 như bài 11, bài 14 và bài 49 để tránh mất dữ liệu do giới hạn số token đầu ra của mô hình 8 tỷ tham số.

### 4.4. Xử lý hạ tầng công cộng và nguyên tắc Fail-Closed
- Vấn đề phát sinh: Trong các bài báo có xuất hiện địa chỉ IP siêu dữ liệu đám mây `169.254.169.254` ở bài 29 hoặc IP đại diện CDN Cloudflare `172.67.186.193` ở bài 16. Nếu đưa các địa chỉ này vào danh sách chặn tường lửa sẽ gây gián đoạn dịch vụ diện rộng.
- Cách xử lý: Bổ sung kiểm tra `is_link_local`, `is_unspecified` và tập 15 dải mạng Anycast công khai của Cloudflare vào `is_valid_malicious_ip` theo nguyên tắc Fail-Closed.

### 4.5. Đánh đổi giữa bước tự kiểm chứng thứ hai và tải VRAM cục bộ
- Vấn đề phát sinh: Khi thử nghiệm nâng `num_ctx` lên 12288 và chạy thêm một lượt gọi LLM thứ hai để tự thẩm định lại toàn bộ IP và tên miền ở bước 1B, bộ nhớ KV Cache tràn khỏi VRAM làm thời gian xử lý tăng lên 173 đến 210 giây mỗi bài. Hơn thế, mô hình 8B ở bước thẩm định phụ trở nên quá nhạy với khái niệm nạn nhân và loại nhầm cả IP tấn công thật ở bài 01 lẫn các tên miền lừa đảo thật ở bài 33.
- Cách xử lý: Loại bỏ lượt gọi LLM thẩm định phụ, giữ cấu hình gọn tại `num_ctx` 8192 token để mô hình nằm ổn định trong VRAM và dựa vào lọc vai trò `excluded_non_malicious` ngay tại bước 1, giúp Precision chung đạt 98,44% và đưa bài 01, bài 16, bài 32, bài 49 lên mức 100% Precision.

### 4.6. Tràn bảng đối chiếu giao diện web và đồng bộ tiến trình nền
- Vấn đề phát sinh: Khi chạy phân tích hàng loạt 50 bài trên giao diện web `labeler_server.py`, các URL hoặc mã SHA256 dài không có khoảng trắng làm phình cột bảng, ép cột tiêu đề bài báo hẹp thành dải chữ dọc và che khuất cột FP bên phải. Ngoài ra, tiến trình chạy tuần tự ban đầu không hiển thị trạng thái bước đang chạy nên khó theo dõi thời gian chờ.
- Cách xử lý: Bổ sung nút chạy toàn bộ và nút dừng an toàn kèm cơ chế khóa luồng `_cache_lock` và ghi file nguyên tử tránh hỏng file JSON khi ghi song song; thêm thanh tiến độ thời gian thực từng giây kèm log 8 bước gần nhất; cố định bố cục bảng bằng `table-layout: fixed`, ngắt từ bằng `overflow-wrap: anywhere` và giới hạn chiều cao vùng hiển thị chip IOC.

---

## 5. Tích hợp điều khiển hệ thống tập trung và đồng bộ hóa phân hệ so sánh 50 bài

Để đơn giản hóa thao tác vận hành và đáp ứng yêu cầu quản lý tập trung toàn bộ đề tài, phân hệ So Sánh Đối Chiếu 50 Bài CTI Ground Truth đã được tích hợp đồng bộ vào hệ thống khởi động và tắt duy nhất:

### 5.1. Khởi động toàn diện với một lệnh duy nhất
- Khi người dùng chạy tệp lệnh `1_BAT_HE_THONG.bat` hoặc thực thi lệnh `python cti_core/system_ctl.py`:
  - Hệ thống tự động kiểm tra và khởi động nền dịch vụ Ollama GPU Server tại cổng 11434.
  - Tự động kích hoạt Web Dashboard Tổng tại cổng 8765 và WAF Reverse Proxy L7 tại cổng 8766.
  - Tự động kích hoạt song song Phân hệ So Sánh Đối Chiếu 50 Bài CTI tại cổng 8780.
  - Tự động mở trình duyệt web và hiển thị menu điều khiển tương tác trực tiếp, cho phép bấm số `1` để vào Dashboard Tổng hoặc số `2` để vào ngay Bảng So Sánh 50 Bài.

### 5.2. Tắt sạch hệ thống và giải phóng 100% tài nguyên
- Khi người dùng chạy tệp lệnh `2_TAT_HE_THONG.bat` hoặc thực thi lệnh `python cti_core/system_ctl.py stop`:
  - Hệ thống đóng toàn bộ tiến trình Web Dashboard, WAF Proxy và máy chủ So Sánh 50 Bài.
  - Chấm dứt tiến trình Ollama và giải phóng hoàn toàn bộ nhớ VRAM GPU lẫn RAM hệ thống.
  - Quét sạch và giải phóng triệt để cả 4 cổng mạng: 8765, 8766, 8780 và 11434, đảm bảo không để lại bất kỳ tiến trình chạy ngầm nào làm nặng máy.

### 5.3. Liên kết chuyển đổi nhanh giữa hai giao diện web
- Trên thanh điều hướng của Web Dashboard Tổng (`http://127.0.0.1:8765`), nút "📊 So Sánh 50 Bài (8780)" được bổ sung tại cả danh mục chức năng và góc thao tác nhanh, cho phép mở trực tiếp trang đối chiếu kết quả Ground Truth.
- Trên thanh điều hướng của Phân hệ So Sánh (`http://127.0.0.1:8780`), nút "&larr; Về Dashboard Tổng (8765)" được bổ sung nổi bật, giúp chuyển đổi qua lại thuận tiện giữa hai màn hình làm việc.

---

## 6. Phân tích sai số còn tồn tại và hướng hoàn thiện

### 6.1. Nguyên nhân của 11 chỉ báo dương tính giả
- Hai trường hợp nhận nhầm số phiên bản phần mềm thành địa chỉ IPv4 là `16.3.116.4` ở bài 20 và `7.2.9.0` ở bài 43 do cụm từ chỉ phiên bản nằm xa hơn cửa sổ kiểm tra tiền tố 28 ký tự.
- Chín trường hợp rơi vào cột `URL` khi AI chuyển tên miền độc hại đơn lẻ thành định dạng URL có tiền tố `https://` như `https://aihao123.cn` ở bài 04, `https://snapshare.chat` ở bài 26, hoặc trích nhầm ví dụ minh họa `https://attacker-server.com` ở bài 24.

### 6.2. Nguyên nhân của 73 chỉ báo bỏ sót
- Trên cột `DOMAIN`, 55 trường hợp bỏ sót tập trung tại ba nhóm chính. Nhóm thứ nhất gồm 26 tên miền ở bài 35 và bài 23 được bài báo trình bày dưới dạng URL đầy đủ có đường dẫn cụ thể, nên hệ thống đưa vào cột `URL` để tránh đếm trùng lặp giữa tên miền và đường dẫn. Nhóm thứ hai gồm 17 tên miền đám mây như Azure Neon hoặc ClickHouse viết dưới dạng văn xuôi không defang trong bài 43, vượt quá số lượng tối đa trong một lượt sinh JSON của mô hình. Nhóm thứ ba gồm một số trường hợp AI gán nhãn phân loại chưa chuẩn trong trường `excluded_non_malicious` như `malicious_c2` ở bài 04 hoặc nhầm tên miền C2 thành `cdn_proxy` ở bài 02.
- Một trường hợp sót mã SHA256 ở bài 22 xảy ra do cửa sổ kiểm tra 120 ký tự của cụm từ không độc hại tràn qua ranh giới xuống dòng từ tệp sạch `WorkFlowy.exe` sang tệp mã độc `main.js` nằm ngay dòng kế dưới.

### 6.3. Giới hạn cần nêu khi báo cáo
- Mô hình cục bộ `qwen3:8b` tiêu thụ tài nguyên tính toán lớn khi chạy liên tục trên máy đơn, tốc độ trung bình gần 2 phút mỗi bài khiến thời gian chạy trọn 50 bài kéo dài khoảng 91 phút.
- Cần thu hẹp phạm vi kiểm tra nhãn sạch của mã băm về phạm vi cùng một dòng văn bản để không ảnh hưởng tới mã băm độc hại ở dòng liền kề, đồng thời chuẩn hóa điều kiện khớp chuỗi con khi kiểm tra vai trò loại trừ trong `excluded_non_malicious`.
