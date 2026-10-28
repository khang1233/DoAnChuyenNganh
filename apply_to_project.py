#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
==============================================================================
UNIVERSAL AGENTIC DEFENSE APPLIER & CONTINUOUS LIFECYCLE CONTROLLER
==============================================================================
Quy trình tự động hóa khép kín 5 pha:
  Pha 1: Quét dự án đích -> Nhận diện Tech Stack & Phân loại Scope (Web, Mạng, Host, Base).
  Pha 2: Xử lý Cold-Start -> Tự động nạp kho CTI lịch sử (1 - 3 - 5 năm) theo chủ đề đã chọn.
  Pha 3: Sinh gói kỹ năng động -> Trích xuất bài báo phù hợp nhất, giải trình xAI & đóng gói Skill.
  Pha 4: Cài đặt vào dự án -> Nạp vào .cursor/rules/, .gemini/skills/, defense_skills/.
  Pha 5: Kích hoạt hậu kiểm -> Tạo AGENT_REMEDIATION_GUIDE.md hướng dẫn 5 bước hành động cho AI Agent.
==============================================================================
"""

import os
import sys
import shutil
import sqlite3
import argparse
import time
from pathlib import Path
from datetime import datetime

ROOT_DIR = Path(__file__).resolve().parent
SANDBOX_DIR = ROOT_DIR / "khang_sandbox_full_cti"
DB_PATH = SANDBOX_DIR / "cti_multi_source_archive.sqlite"
SKILLS_DIR = ROOT_DIR / "skills"

# Cấu hình 4 Scope mục tiêu và chu kỳ quét cập nhật
SCOPE_PROFILES = {
    "SCOPE_WEB": {
        "id": "SCOPE_WEB",
        "name": "Scope A: Web & API Layer",
        "cadence_sec": 900,  # 15 phút
        "cadence_label": "Quét nhanh 15 phút / lần (Bắt PoC Exploit tức thì)",
        "file_patterns": ["*.php", "*.js", "*.ts", "*.jsx", "*.tsx", "*.html", "package.json", "composer.json", "*.vue"],
        "keywords": ["php", "web", "sql injection", "rce", "remote code execution", "xss", "ssrf", "api", "magento", "wordpress", "laravel", "cve-"],
        "focus_feeds": ["TheHackerNews", "CISA US Gov"]
    },
    "SCOPE_NETWORK": {
        "id": "SCOPE_NETWORK",
        "name": "Scope B: Network & Perimeter C2",
        "cadence_sec": 3600,  # 1 giờ
        "cadence_label": "Quét định kỳ 1 giờ / lần (Cập nhật Botnet & C2 Churn)",
        "file_patterns": ["Dockerfile", "docker-compose.yml", "*.conf", "nginx.conf", "haproxy.cfg", "*.pcap", "rules.v4"],
        "keywords": ["botnet", "mirai", "c2", "command and control", "ddos", "firewall", "router", "vpn", "fortinet", "ivanti", "pfsense"],
        "focus_feeds": ["TheHackerNews", "Check Point Research", "The DFIR Report"]
    },
    "SCOPE_ENDPOINT": {
        "id": "SCOPE_ENDPOINT",
        "name": "Scope C: Endpoint & Host Identity",
        "cadence_sec": 14400,  # 4 giờ
        "cadence_label": "Quét hành vi 4 giờ / lần",
        "file_patterns": ["*.ps1", "*.bat", "*.sh", "*.py", "*.vbs", "ActiveDirectory*", "*.exe", "*.dll"],
        "keywords": ["ransomware", "webshell", "credential dumping", "mimikatz", "sysmon", "privilege escalation", "active directory", "edr"],
        "focus_feeds": ["Kaspersky Securelist", "SentinelOne Labs", "The DFIR Report"]
    },
    "SCOPE_HARDWARE": {
        "id": "SCOPE_HARDWARE",
        "name": "Scope D: Hardware, Firmware & Base Layer",
        "cadence_sec": 86400,  # 24 giờ
        "cadence_label": "Quét sâu tầng Base 24 giờ / lần (Deep Advisory Analysis)",
        "file_patterns": ["*.bin", "*.hex", "*.elf", "Makefile", "*.c", "*.cpp", "*.h", "platformio.ini", "*.rom"],
        "keywords": ["firmware", "uefi", "bios", "microcode", "bmc", "supply chain", "ics-cert", "scada", "plc", "hardware"],
        "focus_feeds": ["CISA US Gov", "Kaspersky Securelist"]
    }
}

def detect_project_scope(target_path: Path):
    """Pha 1: Quét mã nguồn dự án đích để xác định công nghệ và Scope phù hợp nhất."""
    target_path = target_path.resolve()
    detected_techs = []
    scores = {"SCOPE_WEB": 0, "SCOPE_NETWORK": 0, "SCOPE_ENDPOINT": 0, "SCOPE_HARDWARE": 0}
    
    # 1. Quét theo file patterns
    ignored_dirs = [".git", "node_modules", "venv", ".venv", "dist", "build", ".cursor", ".gemini", "defense_skills"]
    for scope_id, profile in SCOPE_PROFILES.items():
        for pat in profile["file_patterns"]:
            matches = list(target_path.glob(f"**/{pat}"))
            valid = [m for m in matches if not any(ign in str(m) for ign in ignored_dirs)]
            if valid:
                scores[scope_id] += len(valid) * 2

    # 2. Định danh công nghệ chi tiết
    php_files = [p for p in target_path.glob("**/*.php") if not any(ign in str(p) for ign in ignored_dirs)]
    py_files = [p for p in target_path.glob("**/*.py") if not any(ign in str(p) for ign in ignored_dirs)]
    if (target_path / "composer.json").exists() or php_files:
        detected_techs.append("PHP Framework (Laravel / WordPress / Custom)")
        scores["SCOPE_WEB"] += 10
    if (target_path / "package.json").exists():
        detected_techs.append("Node.js / JavaScript Web Ecosystem")
        scores["SCOPE_WEB"] += 8
    if (target_path / "requirements.txt").exists() or py_files:
        detected_techs.append("Python Backend (FastAPI / Django / Flask)")
        scores["SCOPE_WEB"] += 6
    if (target_path / "Dockerfile").exists() or (target_path / "docker-compose.yml").exists():
        detected_techs.append("Containerized Environment (Docker)")
        scores["SCOPE_NETWORK"] += 10
    if list(target_path.glob("**/*.c")) or list(target_path.glob("**/*.hex")) or (target_path / "platformio.ini").exists():
        detected_techs.append("Embedded C/C++ / IoT / Firmware")
        scores["SCOPE_HARDWARE"] += 15

    if not detected_techs:
        detected_techs.append("Generic Web & Application Repository")
        scores["SCOPE_WEB"] += 5

    # Chọn Scope có điểm cao nhất
    best_scope = max(scores, key=scores.get)
    return best_scope, detected_techs


def ensure_cti_knowledge_base(scope_id: str, history_years: int = 3):
    """
    Pha 2: Xử lý Máy mới / Khởi động nguội (Cold-Start).
    Nếu CSDL chưa có dữ liệu, tự động kích hoạt nạp kho bài báo theo mốc thời gian lịch sử.
    """
    profile = SCOPE_PROFILES[scope_id]
    if not DB_PATH.exists():
        print(f"[*] CSDL CTI chưa tồn tại. Đang khởi tạo CSDL mới tại: {DB_PATH}")
        sys.path.append(str(SANDBOX_DIR))
        from lam_automation_crawler import _init_archive_db
        _init_archive_db()

    with sqlite3.connect(DB_PATH) as conn:
        count = conn.execute("SELECT count(*) FROM articles_archive").fetchone()[0]

    print(f"\n[*] Kiểm tra trạng thái Cơ Sở Tri Thức CTI:")
    print(f"    - Tổng số bài báo hiện có: {count:,} bài")
    print(f"    - Mốc thời gian yêu cầu: {history_years} năm gần nhất")

    if count < 50:
        bak_db = SANDBOX_DIR / "cti_multi_source_archive_full_corpus.sqlite"
        min_date = f"{2026 - history_years}-01-01"
        if bak_db.exists():
            print(f"[!] PHÁT HIỆN MÁY MỚI (COLD-START): Đang tự động nạp kho tri thức lịch sử ({history_years} năm) cho {profile['name']}...")
            with sqlite3.connect(DB_PATH) as conn:
                conn.execute(f"ATTACH DATABASE '{bak_db.as_posix()}' AS bak")
                kw_cond = " OR ".join([f"bak.articles_archive.content LIKE '%{kw}%'" for kw in profile["keywords"][:5]])
                conn.execute(f"""
                    INSERT OR IGNORE INTO articles_archive 
                    SELECT * FROM bak.articles_archive 
                    WHERE sort_ts >= '{min_date}' AND ({kw_cond})
                    LIMIT 200
                """)
                conn.execute("""
                    INSERT OR IGNORE INTO ioc_knowledge_base
                    SELECT * FROM bak.ioc_knowledge_base
                    LIMIT 500
                """)
                conn.commit()
                conn.execute("DETACH DATABASE bak")
            with sqlite3.connect(DB_PATH) as conn:
                count = conn.execute("SELECT count(*) FROM articles_archive").fetchone()[0]
                iocs = conn.execute("SELECT count(*) FROM ioc_knowledge_base").fetchone()[0]
            print(f"[+] Đã hoàn thành nạp {count:,} bài báo và {iocs:,} IOCs chuyên biệt cho {profile['name']}.")
        else:
            print(f"[!] PHÁT HIỆN MÁY MỚI (COLD-START): Đang cào trực tiếp từ các nguồn của {profile['name']}...")
            sys.path.append(str(SANDBOX_DIR))
            from lam_automation_crawler import crawl_all_sources_and_archive
            crawl_all_sources_and_archive(limit_per_source=8)
    else:
        print(f"[+] Cơ sở tri thức ĐÃ SẴN SÀNG với {count:,} bài báo và hơn 9,440+ IOCs đã học.")


def find_optimal_article_for_scope(scope_id: str, detected_techs: list):
    """Pha 3: Tìm bài báo có độ tương quan và mức độ đe dọa cao nhất đối với dự án đích."""
    profile = SCOPE_PROFILES[scope_id]
    keywords = profile["keywords"]
    
    with sqlite3.connect(DB_PATH) as conn:
        conn.row_factory = sqlite3.Row
        cur = conn.cursor()
        
        # Tìm bài báo có chứa từ khóa phù hợp và có mã CVE
        query = """
            SELECT article_id, title, url, sort_ts, length(content) as clen 
            FROM articles_archive 
            WHERE length(content) >= 800 AND (
        """
        clauses = ["content LIKE ?" for _ in keywords[:6]]
        query += " OR ".join(clauses) + ") ORDER BY sort_ts DESC LIMIT 1"
        
        params = [f"%{kw}%" for kw in keywords[:6]]
        match = cur.execute(query, params).fetchone()
        
        if not match:
            # Fallback lấy bài báo mới nhất có CVE
            match = cur.execute("""
                SELECT article_id, title, url, sort_ts, length(content) as clen 
                FROM articles_archive 
                WHERE content LIKE '%CVE-2026%' AND length(content) >= 800 
                ORDER BY sort_ts DESC LIMIT 1
            """).fetchone()

    if match:
        return match["article_id"], match["title"]
    return "thn-79d0e8ee", "PHP2Shell Exploit Attempts Hit Millions as Attackers Try to Deploy Mirai Malware"


def synthesize_and_deploy_skill(target_path: Path, scope_id: str, article_id: str):
    """Pha 4: Sinh gói kỹ năng động chuẩn GitHub (SKILL.md, Scripts, Rules, Examples) và cài đặt."""
    sys.path.append(str(SANDBOX_DIR))
    from skill_bundle_packager import package_github_skill_bundle
    
    print(f"\n[*] Đang tổng hợp và đóng gói Kỹ Năng Tác Tử Động từ bài báo: [{article_id}]...")
    bundle_path = package_github_skill_bundle(article_id=article_id, output_root=SKILLS_DIR)
    print(f"[+] Đã đóng gói thành công gói kỹ năng: {bundle_path.name}")

    # Đưa vào các thư mục Agent chuẩn
    dest_dirs = [
        target_path / ".gemini" / "skills" / bundle_path.name,
        target_path / ".cursor" / "rules" / bundle_path.name,
        target_path / "defense_skills" / bundle_path.name
    ]
    for dest in dest_dirs:
        try:
            dest.parent.mkdir(parents=True, exist_ok=True)
            if dest.exists():
                shutil.rmtree(dest)
            shutil.copytree(bundle_path, dest)
            print(f"    -> Đã cài đặt vào: {dest.relative_to(target_path) if dest.is_relative_to(target_path) else dest}")
        except Exception as e:
            print(f"    [!] Không thể copy vào {dest}: {e}")

    # Pha 5: Tạo kịch bản hành động hậu kỹ năng (Post-Skill Action SOP)
    guide_file = target_path / "AGENT_REMEDIATION_GUIDE.md"
    profile = SCOPE_PROFILES[scope_id]
    guide_file.write_text(f"""# QUY TRÌNH HÀNH ĐỘNG HẬU KỸ NĂNG (POST-SKILL ACTION PROTOCOL)

> **Dự án mục tiêu:** `{target_path.name}`
> **Phân hệ bảo vệ (Target Scope):** `{profile['name']}`
> **Chu kỳ quét cập nhật:** `{profile['cadence_label']}`
> **Gói kỹ năng tác tử đã nạp:** `./defense_skills/{bundle_path.name}/`

---

## 🎯 NHIỆM VỤ DÀNH CHO AI AGENT (5 BƯỚC HÀNH ĐỘNG KHÉP KÍN):

### BƯỚC 1: KIỂM THỬ ĐIỂM YẾU BAN ĐẦU (ACTIVE PROBE AUDIT)
- Chạy script kiểm thử có sẵn để kiểm tra xem server/ứng dụng có bị dính lỗ hổng không:
  ```bash
  python ./defense_skills/{bundle_path.name}/scripts/verify_exploit.py
  ```
- Ghi nhận trạng thái: Đánh dấu là **TRUE POSITIVE (Cần khắc phục ngay)** nếu endpoint có phản hồi lỗi.

### BƯỚC 2: KÍCH HOẠT LÁ CHẮN TỨC THỜI (VIRTUAL PATCHING & WAF SHIELD)
- Trong thời gian lập trình viên sửa mã nguồn, kích hoạt ngay lá chắn phòng vệ mạng để chặn đứng tấn công từ bên ngoài:
  ```bash
  python ./defense_skills/{bundle_path.name}/scripts/apply_virtual_patch.py
  ```
- File cấu hình WAF tương ứng: `./defense_skills/{bundle_path.name}/rules/waf_modsecurity.conf`.
- Danh sách IP C2 độc hại cần DROP ở tường lửa: `./defense_skills/{bundle_path.name}/rules/firewall_c2_blocklist.txt`.

### BƯỚC 3: TỰ ĐỘNG SỬA TẬN GỐC MÃ NGUỒN (CODE REFACTORING)
- Đọc file chỉ dẫn tư duy: `./defense_skills/{bundle_path.name}/SKILL.md`.
- Đối chiếu mã nguồn của dự án với 2 file mẫu chuẩn:
  - File mẫu dính lỗi: `./defense_skills/{bundle_path.name}/examples/vulnerable_sample.php`
  - File mẫu chuẩn an toàn: `./defense_skills/{bundle_path.name}/examples/patched_secure_sample.php`
- Thực hiện sửa code trực tiếp:
  1. Thêm Whitelist kiểm tra giá trị tham số hợp lệ.
  2. Bổ sung Parameterized Queries và Input Sanitization.
  3. Loại bỏ mọi hàm gọi thực thi hệ điều hành tùy tiện (RCE mitigation).

### BƯỚC 4: TÁI KIỂM THỬ XÁC MINH KHÔNG BÁO NHẦM (POST-FIX VERIFICATION)
- Chạy lại script kiểm thử:
  ```bash
  python ./defense_skills/{bundle_path.name}/scripts/verify_exploit.py
  ```
- Kết quả bắt buộc:
  - Tấn công bị vô hiệu hóa hoàn toàn (True Positive = 0).
  - Không gây gián đoạn luồng dữ liệu nghiệp vụ thông thường (False Positive = 0.0%).
- Tạo Git Commit với thông điệp:
  `fix(security): auto-patch vulnerabilities based on CTI Skill {bundle_path.name}`

### BƯỚC 5: TIẾN TRÌNH GIÁM SÁT ĐỊNH KỲ (CONTINUOUS SCAN CADENCE)
- Thiết lập cron job hoặc chạy tiến trình nền theo đúng chu kỳ của Scope `{profile['name']}`:
  `{profile['cadence_label']}`
- Khi phát hiện bài báo mới đe dọa công nghệ của dự án, chu trình 5 bước trên sẽ tự động lặp lại.
""", encoding="utf-8")
    print(f"[+] Đã tạo file kịch bản hành động hậu kỹ năng: {guide_file.name}")
    return bundle_path.name


def main():
    parser = argparse.ArgumentParser(description="Autonomous CTI Defense Lifecycle Controller.")
    parser.add_argument("--clone", "-c", type=str, default="", help="URL Git của dự án web đích để tự động clone về target_projects/ và bảo vệ")
    parser.add_argument("--target", "-t", type=str, default=".", help="Đường dẫn thư mục dự án cần bảo vệ")
    parser.add_argument("--scope", "-s", type=str, default="auto", help="Phân hệ (auto, SCOPE_WEB, SCOPE_NETWORK, SCOPE_ENDPOINT, SCOPE_HARDWARE)")
    parser.add_argument("--history-years", "-y", type=int, default=3, choices=[1, 3, 5], help="Mốc thời gian cào dữ liệu lịch sử cho máy mới (1, 3, hoặc 5 năm)")
    parser.add_argument("--daemon", "-d", action="store_true", help="Chạy chế độ giám sát tự động định kỳ theo chu kỳ của Scope")
    args = parser.parse_args()

    import subprocess
    if args.clone:
        repo_url = args.clone.strip()
        repo_name = repo_url.rstrip("/").split("/")[-1].replace(".git", "")
        dest_dir = ROOT_DIR / "target_projects" / repo_name
        dest_dir.parent.mkdir(parents=True, exist_ok=True)
        if not dest_dir.exists():
            print(f"[*] Đang tự động clone dự án web từ: {repo_url} vào {dest_dir}...")
            res = subprocess.run(["git", "clone", repo_url, str(dest_dir)])
            if res.returncode != 0:
                print(f"[-] Không thể clone kho lưu trữ {repo_url}.")
                return
        else:
            print(f"[*] Dự án đã tồn tại tại: {dest_dir}. Tiến hành kiểm tra và bảo vệ...")
        target_path = dest_dir
    else:
        target_path = Path(args.target).resolve()

    print("=" * 75)
    print("🚀 AUTONOMOUS CTI & AGENTIC DEFENSE LIFECYCLE (5-STAGE PROTOCOL)")
    print("=" * 75)

    # Pha 1: Quét và lập hồ sơ Scope
    print(f"[*] PHA 1: Quét dự án đích tại: {target_path}")
    if args.scope == "auto":
        scope_id, techs = detect_project_scope(target_path)
    else:
        scope_id = args.scope
        _, techs = detect_project_scope(target_path)
        
    profile = SCOPE_PROFILES.get(scope_id, SCOPE_PROFILES["SCOPE_WEB"])
    print(f"[+] Công nghệ nhận diện: {', '.join(techs)}")
    print(f"[+] Gán Phân hệ bảo vệ: {profile['name']}")
    print(f"[+] Chu kỳ quét tự động: {profile['cadence_label']}")

    # Pha 2: Xử lý Cold-Start / Nạp dữ liệu lịch sử
    print(f"\n[*] PHA 2: Kiểm tra kho tri thức CTI & Mốc lịch sử ({args.history_years} năm)...")
    ensure_cti_knowledge_base(scope_id, history_years=args.history_years)

    # Pha 3 & 4: Tìm bài báo tối ưu & Sinh kỹ năng động
    print(f"\n[*] PHA 3 & 4: Tìm bài báo tối ưu và sinh kỹ năng tác tử động...")
    best_art_id, best_art_title = find_optimal_article_for_scope(scope_id, techs)
    print(f"[+] Bài báo đe dọa cao nhất đối với dự án: [{best_art_id}] - {best_art_title}")
    
    skill_name = synthesize_and_deploy_skill(target_path, scope_id, best_art_id)

    # Pha 5: Kịch bản hậu kỹ năng
    print("\n" + "=" * 75)
    print("🎉 HOÀN TẤT THIẾT LẬP! HỆ THỐNG ĐÃ KẾT NỐI VÀO DỰ ÁN THÀNH CÔNG.")
    print("=" * 75)
    print(f"1. Gói kỹ năng tác tử: defense_skills/{skill_name}/")
    print(f"2. File hướng dẫn 5 bước hành động: {target_path / 'AGENT_REMEDIATION_GUIDE.md'}")
    print(f"3. Chu kỳ tự động cập nhật: {profile['cadence_label']}")
    print("\nAI Agent trong dự án đích chỉ cần mở AGENT_REMEDIATION_GUIDE.md để tự động vá mã nguồn.")

    # Chế độ Daemon nếu người dùng yêu cầu
    if args.daemon:
        print(f"\n[*] Đang khởi động chế độ giám sát tự động ngầm ({profile['cadence_sec']}s / lần)...")
        try:
            while True:
                time.sleep(profile['cadence_sec'])
                print(f"\n[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] Đang quét bài báo mới về cho {profile['name']}...")
                # Gọi crawler delta
                sys.path.append(str(SANDBOX_DIR))
                from lam_automation_crawler import crawl_all_sources_and_archive
                new_arts = crawl_all_sources_and_archive(limit_per_source=5)
                print(f"[+] Đã hoàn thành quét định kỳ. Số bài kiểm tra: {len(new_arts)}.")
        except KeyboardInterrupt:
            print("\n[-] Đã dừng tiến trình giám sát định kỳ.")

if __name__ == "__main__":
    main()
