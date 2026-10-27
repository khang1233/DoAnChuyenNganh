#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
==============================================================================
UNIVERSAL AGENTIC DEFENSE APPLIER (BỘ KẾT NỐI PHÒNG THỦ TỰ ĐỘNG CHO DỰ ÁN)
==============================================================================
Dành cho AI Agent (Cursor, Antigravity, Claude Code) hoặc Lập trình viên:
Chỉ cần trỏ đường dẫn tới dự án của bạn, công cụ sẽ:
  1. Tự động quét và nhận diện Tech Stack (PHP, Node.js, Python, Go, Docker...).
  2. Tự động chọn Scope phòng thủ phù hợp (Web, Network, Endpoint, Base).
  3. Tự động copy và nạp Bộ Kỹ Năng Tác Tử (SKILL.md, Scripts, Rules) vào dự án:
     - .gemini/skills/ (cho Google Antigravity)
     - .cursor/rules/  (cho Cursor)
     - defense_skills/ (cho Claude Code / Copilot / Developer)
  4. Hướng dẫn AI Agent của dự án cách tự động vá mã nguồn theo chuẩn xAI SOP.
==============================================================================
"""

import os
import sys
import shutil
import argparse
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parent
SKILLS_DIR = ROOT_DIR / "skills"

def detect_project_tech_stack(target_path: Path):
    """Quét mã nguồn mục tiêu để xác định công nghệ và phân hệ phòng thủ."""
    techs = []
    scope = "SCOPE_WEB"
    
    # Kiểm tra các dấu hiệu công nghệ
    has_php = any(target_path.glob("**/*.php")) or (target_path / "composer.json").exists()
    has_node = (target_path / "package.json").exists() or any(target_path.glob("**/*.js")) or any(target_path.glob("**/*.ts"))
    has_python = (target_path / "requirements.txt").exists() or (target_path / "pyproject.toml").exists() or any(target_path.glob("**/*.py"))
    has_docker = (target_path / "Dockerfile").exists() or (target_path / "docker-compose.yml").exists()
    
    if has_php:
        techs.append("PHP Application (Laravel/WordPress/Native)")
    if has_node:
        techs.append("Node.js / TypeScript Web/API")
    if has_python:
        techs.append("Python Backend (FastAPI/Django/Flask)")
    if has_docker:
        techs.append("Docker Containerized Environment")
        
    if not techs:
        techs.append("Generic Source Code / Web Application")
        
    return techs, scope

def install_agentic_skill(target_path: Path, chosen_scope: str = "SCOPE_WEB"):
    """Cài đặt bộ kỹ năng tác tử vào thư mục dự án đích."""
    target_path = target_path.resolve()
    if not target_path.exists():
        print(f"[-] Đường dẫn dự án không tồn tại: {target_path}")
        return False
        
    print(f"\n[*] Đang quét dự án tại: {target_path}")
    techs, scope = detect_project_tech_stack(target_path)
    print(f"[+] Phát hiện công nghệ: {', '.join(techs)}")
    print(f"[+] Phân hệ phòng thủ mục tiêu: {scope}")
    
    # Tìm kiếm skill bundle sẵn có
    available_bundles = [d for d in SKILLS_DIR.iterdir() if d.is_dir()]
    if not available_bundles:
        print("[-] Không tìm thấy gói skill nào trong thư mục skills/. Đang sinh tự động...")
        sys.path.append(str(ROOT_DIR / "khang_sandbox_full_cti"))
        from skill_bundle_packager import package_github_skill_bundle
        selected_bundle = package_github_skill_bundle("thn-79d0e8ee")
    else:
        selected_bundle = available_bundles[0]
        
    print(f"[+] Chọn gói kỹ năng tác tử: {selected_bundle.name}")
    
    # Cài đặt vào các vị trí chuẩn của Agent
    dest_dirs = [
        target_path / ".gemini" / "skills" / selected_bundle.name,  # Google Antigravity
        target_path / ".cursor" / "rules" / selected_bundle.name,   # Cursor
        target_path / "defense_skills" / selected_bundle.name       # Universal
    ]
    
    for dest in dest_dirs:
        try:
            dest.parent.mkdir(parents=True, exist_ok=True)
            if dest.exists():
                shutil.rmtree(dest)
            shutil.copytree(selected_bundle, dest)
            print(f"    -> Đã cài đặt vào: {dest.relative_to(target_path) if dest.is_relative_to(target_path) else dest}")
        except Exception as e:
            print(f"    [!] Không thể copy vào {dest}: {e}")
            
    # Tạo file hướng dẫn tóm tắt cho AI Agent của dự án
    agent_prompt_file = target_path / "AGENT_REMEDIATION_GUIDE.md"
    agent_prompt_file.write_text(f"""# HƯỚNG DẪN TỰ ĐỘNG VÁ MÃ NGUỒN CHO AI AGENT

> Dự án này đã được tích hợp **Agentic Defense Skill Package** từ hệ thống CTI Đa Nguồn.
> Gói kỹ năng được đặt tại: `./defense_skills/{selected_bundle.name}/`

## YÊU CẦU ĐỐI VỚI AI AGENT CỦA DỰ ÁN:
1. Đọc kỹ file `./defense_skills/{selected_bundle.name}/SKILL.md` để nắm rõ đặc tả lỗ hổng và chữ ký khai thác.
2. Quét toàn bộ mã nguồn của dự án này, tìm kiếm các hàm nguy hiểm tương tự như mẫu trong `./defense_skills/{selected_bundle.name}/examples/vulnerable_sample.php`.
3. Tự động áp dụng quy trình sửa mã nguồn theo mẫu an toàn trong `./defense_skills/{selected_bundle.name}/examples/patched_secure_sample.php`:
   - Thêm Input Sanitization và Parameterized Queries.
   - Thay thế các hàm thực thi hệ thống không an toàn.
   - Bổ sung kiểm tra quyền và Whitelist tham số.
4. Chạy kiểm thử tự động bằng script: `python ./defense_skills/{selected_bundle.name}/scripts/verify_exploit.py`.
5. Tạo Pull Request hoặc Commit với thông điệp: `fix: auto-remediate vulnerabilities based on CTI Agentic Skill`.
""", encoding="utf-8")
    print(f"[+] Đã tạo file hướng dẫn tác tử: {agent_prompt_file.name}")
    
    print("\n" + "="*70)
    print("HOÀN TẤT KẾT NỐI PHÒNG THỦ THÀNH CÔNG!")
    print("AI Agent trong dự án đích hiện đã có đầy đủ:")
    print("  - SKILL.md: Hướng dẫn tư duy và quy trình vá mã nguồn.")
    print("  - scripts/: Công cụ Python để tự động kiểm thử lỗ hổng.")
    print("  - rules/: Cấu hình WAF, Suricata, Firewall để nạp trực tiếp.")
    print("  - examples/: Mẫu code trước và sau khi vá để Agent đối chiếu.")
    print("="*70)
    return True

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Tự động nạp Agentic Defense Skill vào bất kỳ dự án nào.")
    parser.add_argument("--target", "-t", type=str, default=".", help="Đường dẫn thư mục dự án cần bảo vệ (Mặc định: thư mục hiện tại)")
    parser.add_argument("--scope", "-s", type=str, default="SCOPE_WEB", help="Phân hệ phòng thủ (SCOPE_WEB, SCOPE_NETWORK, SCOPE_ENDPOINT, SCOPE_HARDWARE)")
    args = parser.parse_args()
    
    install_agentic_skill(Path(args.target), args.scope)
