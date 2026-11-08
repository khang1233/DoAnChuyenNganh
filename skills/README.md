# Thư mục Kỹ năng Tác tử (Agent Skills)

Thư mục này là nơi lưu trữ các gói Kỹ năng Tác tử phòng thủ (Agentic Defense Skills) được sinh ra tự động từ quy trình phân tích tình báo mạng (CTI).

## Cơ chế sinh kỹ năng tự động
- Khi hệ thống thu thập bài báo CTI, trích xuất mã kỹ thuật MITRE ATT&CK, phân tích mẫu IOC và kiểm định mức độ tin cậy xAI, mô hình sẽ tự động đóng gói toàn bộ quy tắc phòng thủ vào thư mục này.
- Mỗi gói kỹ năng gồm:
  - `manifest.json`: Siêu dữ liệu và định nghĩa công cụ nạp vào tác tử AI.
  - `SKILL.md`: Sổ tay hướng dẫn tác tử thực hiện rà soát và khắc phục mã nguồn.
  - `scripts/`: Bộ script kiểm thử lỗ hổng (`verify_exploit.py`) và kích hoạt vá ảo (`apply_virtual_patch.py`).
  - `references/`: Báo cáo tình báo gốc, danh sách IOC độc hại và vết kiểm toán xAI.
  - `examples/`: Các mẫu mã nguồn trước và sau khi được vá bảo mật.

Để sinh gói kỹ năng cho một dự án mục tiêu hoặc bài báo CTI:
```bash
python apply_to_project.py --target <duong_dan_du_an>
```
