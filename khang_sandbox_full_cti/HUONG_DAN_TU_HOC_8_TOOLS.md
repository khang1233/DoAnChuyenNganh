# 📘 CẨM NANG TỰ HỌC & NẮM TRỌN 8 TOOLS DỰ ÁN AUTONOMOUS CTI (DÀNH RIÊNG CHO KHANG)

> **Lưu ý quan trọng:** Thư mục `D:\mkhang\DoAnChuyenNganh\khang_sandbox_full_cti\` này nằm **BÊN NGOÀI** kho Git `ai-devsecops-agent` của nhóm. Mày có thể thoải mái sửa, chạy thử toàn bộ 8 Tools (cả phần của Lâm, Phúc và Khang) tại đây mà **không bao giờ lo làm hỏng hay đẩy nhầm vào code của 2 thằng bạn**!

---

## 1. PHÂN BIỆT RÕ: CÁI NÀO ĐÃ ĐẨY LÊN GITHUB vs. CÁI NÀO ĐỂ Ở MÁY

### ✅ A. Phần chính thức của KHANG (Đã đẩy lên nhánh `feat/khang-dev` trên GitHub)
Nằm trong `D:\mkhang\DoAnChuyenNganh\ai-devsecops-agent\src\security\`:
1. **`enrichment_service.py` (Tool 3 & Tool 4 + SQLite Cache):**
   * `check_virustotal(ioc_value, ioc_type)`: Gọi VirusTotal API v3 kiểm tra IP / Domain / Hash.
   * `check_abuseipdb(ip_address)`: Gọi AbuseIPDB API v2 kiểm tra điểm nguy hiểm của IP (0 - 100%).
   * `SQLiteThreatCache`: Tự động lưu kết quả vào database SQLite cục bộ để không bị cạn lượt gọi API miễn phí.
   * `enrich_ioc()` & `enrich_ioc_list()`: Nhận `ExtractedIOC` từ Phúc $\rightarrow$ Trả về `EnrichedIOC` chuẩn `shared/schemas.py`.
2. **`stix_converter.py` (Tool 5):**
   * `export_stix_package()`: Đóng gói toàn bộ kết quả điều tra thành chuẩn quốc tế **OASIS STIX 2.1 Bundle JSON**.
3. **`benchmark/` (Nhiệm vụ Tuần 6 của Khang):**
   * `apt_dataset_builder.py` & `apt_ground_truth.json`: Bộ **30 bài báo chiến dịch APT thực tế** (gồm 120 IOC độc hại thật + 60 IOC sạch gây nhiễu như `8.8.8.8`, `192.168.1.1`, `microsoft.com`).
   * `cti_benchmark.py` & `cti_benchmark_report.md`: Script chấm điểm tự động chứng minh Tool 3 & Tool 4 của Khang giúp lọc sạch 100% cảnh báo nhầm, nâng Precision từ **66.67% lên 100.0%**.
4. **`test_security.py`:** Bộ Unit Test kiểm tra toàn bộ 5 tính năng của Khang (`5 passed`).

---

### 💻 B. Phần Sandbox Full 8 Tools để Khang tự học trên máy (Không đẩy lên GitHub)
Nằm tại `D:\mkhang\DoAnChuyenNganh\khang_sandbox_full_cti\full_cti_pipeline.py`:
* Ghép nối trọn vẹn cả **5 bước / 8 Tools** của cả nhóm:
  * **Bước 1 (Phần của Lâm):** `tool1_fetch_rss_feeds()` & `tool2_fetch_cisa_kev()` lấy bài báo tấn công mạng.
  * **Bước 2 (Phần của Phúc):** `tool6_extract_iocs()` nhặt tất cả IP, Domain, SHA256, CVE trong bài báo.
  * **Bước 3 (Phần của Khang):** Gọi `check_virustotal` & `check_abuseipdb` để lọc bỏ IP/Domain sạch (`8.8.8.8`, `192.168.1.15`, `update.microsoft.com`) và giữ lại đúng IP/Domain/Hash độc hại của hacker (`91.219.236.174`, `lockbit-decryptor-portal.top`).
  * **Bước 4 (Phần của Phúc):** `tool7_map_mitre_attack()` ánh xạ mã MITRE (`T1059.001`, `T1486`) và `tool8_generate_defensive_rules()` sinh ra **Firewall Blocklist**, **Sigma Rule (`.yml`)** và **YARA Rule (`.yar`)**.
  * **Bước 5 (Phần của Khang):** `export_stix_package()` đóng gói thành cục **STIX 2.1 JSON**.

---

## 2. CÁC LỆNH CHẠY THỬ DÀNH CHO KHANG

Mở Terminal (PowerShell) và gõ:

```powershell
# 1. Chạy thử toàn bộ dây chuyền 8 Tools từ đầu đến cuối (Bản tự học của Khang):
D:\mkhang\DoAnChuyenNganh\ai-devsecops-agent\.venv\Scripts\python.exe D:\mkhang\DoAnChuyenNganh\khang_sandbox_full_cti\full_cti_pipeline.py

# 2. Chạy kiểm tra Unit Test phần chính thức của Khang (5/5 bài test Pass):
cd D:\mkhang\DoAnChuyenNganh\ai-devsecops-agent
.\.venv\Scripts\pytest.exe src/security/test_security.py -v

# 3. Chạy đo đạc Benchmark 30 bài báo APT của Khang:
.\.venv\Scripts\python.exe src/security/benchmark/cti_benchmark.py
```

---

## 3. CÁCH GẮN API KEY THẬT (KHI MUỐN GỌI VIRUSTOTAL & ABUSEIPDB TRỰC TIẾP)

Code trong `enrichment_service.py` đã có sẵn chế độ **Offline Intelligence Fallback** nên không cần API Key vẫn chạy mượt 100%. Khi nào mày đăng ký tài khoản miễn phí trên:
* VirusTotal: `https://www.virustotal.com/` (Mục API Key)
* AbuseIPDB: `https://www.abuseipdb.com/` (Mục APIv2 Key)

Mày chỉ cần tạo file `.env` trong `D:\mkhang\DoAnChuyenNganh\ai-devsecops-agent\.env` (file này đã được `.gitignore` giấu đi, không lộ lên GitHub):
```env
VIRUSTOTAL_API_KEY=dien_key_virustotal_cua_may_vao_day
ABUSEIPDB_API_KEY=dien_key_abuseipdb_cua_may_vao_day
```
Hệ thống sẽ tự động chuyển sang gọi API trực tiếp và lưu vào SQLite Cache!
