# -*- coding: utf-8 -*-
"""
MULTI-AGENT COMPATIBILITY & CONTEXT-AWARE ORCHESTRATOR
Giải quyết triệt để 2 vấn đề lớn:
1. Xuất Kỹ Năng Tác Tử chuẩn định dạng riêng cho từng nền tảng AI Agent lớn:
   - Claude Code (Anthropic): CLAUDE.md và .claude/skills/
   - Cursor Agent: .cursor/rules/*.mdc và .cursorrules
   - Google Antigravity / Gemini CLI: .gemini/skills/
   - Windsurf (Codeium Cascade): .windsurfrules
   - GitHub Copilot: .github/copilot-instructions.md
   - OpenAI / ReAct: manifest.json (Tools Schema)
2. Quét và trích xuất Ngữ Cảnh Dự Án Thực Tế (Project Context-Aware Grounding):
   - Thay vì lý thuyết chung chung, tự động đọc cấu trúc thư mục, entrypoint,
     và các điểm nhạy cảm (Sensitive Sinks: execAsync, db.query, subprocess...)
     để chỉ dẫn chính xác cho AI Agent từng file cần sửa trong dự án đích.
"""

import os
import re
import json
import shutil
from pathlib import Path
from typing import Dict, Any, List

def extract_project_context(target_dir: Path) -> Dict[str, Any]:
    """
    Quét mã nguồn dự án mục tiêu để trích xuất ngữ cảnh kiến trúc và các điểm nhạy cảm.
    """
    target_dir = Path(target_dir).resolve()
    context = {
        "project_name": target_dir.name,
        "target_path": str(target_dir),
        "frameworks": [],
        "entrypoints": [],
        "sensitive_sinks": [],
        "total_source_files": 0
    }

    # 1. Quét Frameworks & Dependencies
    for pkg_file in target_dir.glob("**/package.json"):
        if any(ign in str(pkg_file) for ign in [".git", "node_modules", "defense_skills"]):
            continue
        try:
            d = json.loads(pkg_file.read_text(encoding="utf-8", errors="ignore"))
            deps = {**d.get("dependencies", {}), **d.get("devDependencies", {})}
            for fw in ["express", "fastify", "react", "vite", "mysql", "mysql2", "sqlite3", "sequelize", "mongoose", "axios"]:
                if fw in deps and fw not in context["frameworks"]:
                    context["frameworks"].append(fw)
        except Exception:
            pass

    for req_file in target_dir.glob("**/requirements*.txt"):
        if any(ign in str(req_file) for ign in [".git", "node_modules", "defense_skills"]):
            continue
        try:
            text = req_file.read_text(encoding="utf-8", errors="ignore").lower()
            for fw in ["flask", "fastapi", "django", "discord.py", "requests", "sqlalchemy", "pymysql"]:
                if fw in text and fw not in context["frameworks"]:
                    context["frameworks"].append(fw)
        except Exception:
            pass

    # 2. Quét các file mã nguồn và điểm nhạy cảm thực tế
    ignored_patterns = [".git", "node_modules", "venv", ".venv", "dist", "build", ".cursor", ".gemini", ".claude", "defense_skills"]
    exts = [".js", ".ts", ".jsx", ".tsx", ".py", ".php", ".go", ".java", ".cs"]

    for file_path in target_dir.glob("**/*"):
        if not file_path.is_file() or file_path.suffix not in exts:
            continue
        if any(ign in str(file_path) for ign in ignored_patterns):
            continue

        context["total_source_files"] += 1
        rel_path = str(file_path.relative_to(target_dir)).replace("\\", "/")

        # Ghi nhận file khởi chạy (Entrypoints)
        if any(kw in file_path.name.lower() for kw in ["server", "app", "main", "index", "bot"]):
            if rel_path not in context["entrypoints"]:
                context["entrypoints"].append(rel_path)

        # Phân tích các hàm nhạy cảm (Sensitive Sinks)
        try:
            content = file_path.read_text(encoding="utf-8", errors="ignore")
            lines = content.splitlines()
            sinks_found = []

            for idx, line in enumerate(lines, 1):
                # RCE / Command execution sinks
                if re.search(r"\b(execAsync|exec\(|execSync|spawn\(|child_process|eval\(|os\.system|subprocess\.)", line):
                    sinks_found.append({
                        "line": idx,
                        "type": "Command Execution / RCE Risk",
                        "snippet": line.strip()[:100]
                    })
                # Raw SQL query sinks
                elif re.search(r"\b(query\(|execute\(|raw\()", line) and re.search(r"(SELECT|INSERT|UPDATE|DELETE|FROM|WHERE)", line, re.I):
                    if "?" not in line and "$" not in line and "%s" not in line:
                        sinks_found.append({
                            "line": idx,
                            "type": "Possible Raw SQL Concatenation",
                            "snippet": line.strip()[:100]
                        })

            if sinks_found:
                context["sensitive_sinks"].append({
                    "file": rel_path,
                    "findings": sinks_found[:4]
                })
        except Exception:
            pass

    return context


def generate_context_blueprint_markdown(context: Dict[str, Any]) -> str:
    """
    Sinh tài liệu Bản Đồ Ngữ Cảnh Dự Án Thực Tế để nhúng vào SKILL.md.
    """
    pname = context.get("project_name", "Target Project")
    fws = ", ".join(context.get("frameworks", [])) or "Custom Stack"
    entrypoints = context.get("entrypoints", [])
    sinks = context.get("sensitive_sinks", [])

    lines = [
        "## 🧭 BẢN ĐỒ NGỮ CẢNH DỰ ÁN MỤC TIÊU (TARGET PROJECT ARCHITECTURAL CONTEXT)",
        "",
        "> [!IMPORTANT]",
        f"> **Tác tử AI (Claude, Cursor, Antigravity, Devin)**: Dự án `{pname}` đã được hệ thống CTI thẩm định ngữ cảnh.",
        "> Tuyệt đối không suy luận chung chung! Bạn phải đọc ngữ cảnh thực tế của dự án dưới đây để thực hiện refactor:",
        "",
        f"- **Tên dự án:** `{pname}`",
        f"- **Frameworks nhận diện:** `{fws}`",
        f"- **Tổng số tệp mã nguồn:** `{context.get('total_source_files', 0)} files`",
        "",
        "### 1. Các File Khởi Chạy Trọng Tâm (Key Entrypoints):"
    ]
    for ep in entrypoints[:8]:
        lines.append(f"- `{ep}`")

    lines.extend([
        "",
        "### 2. Các Điểm Nóng Bảo Mật Thực Tế Cần Rà Soát (Detected Sensitive Sinks):",
        "Hệ thống phát hiện các hàm thực thi hệ thống hoặc truy vấn cần được bảo vệ theo chuẩn CTI:"
    ])

    if sinks:
        for item in sinks[:6]:
            lines.append(f"- **Tệp:** `{item['file']}`")
            for f in item["findings"]:
                lines.append(f"  - Dòng {f['line']} [{f['type']}]: `{f['snippet']}`")
    else:
        lines.append("- Chưa phát hiện sink nguy hiểm trực tiếp. Cần rà soát các điểm nhận input từ request người dùng.")

    lines.extend([
        "",
        "### 3. Chỉ Dẫn Hành Động Cụ Thể Cho AI Coding Agent:",
        "1. Mở trực tiếp các tệp tin trong danh sách Điểm Nóng phía trên.",
        "2. Thay thế việc ghép chuỗi câu lệnh trong các hàm `execAsync` / `exec` bằng mảng tham số cố định `execFile` hoặc Whitelist.",
        "3. Đảm bảo toàn bộ câu lệnh truy vấn dữ liệu được chuẩn hóa bằng Prepared Statements.",
        ""
    ])
    return "\n".join(lines)


def deploy_to_all_major_agent_platforms(target_path: Path, skill_bundle_path: Path, context: Dict[str, Any]):
    """
    Đóng gói và phân phối Kỹ Năng Tác Tử đến TOÀN BỘ CÁC NỀN TẢNG AGENT LỚN HIỆN NAY:
    1. Claude Code (Anthropic): CLAUDE.md & .claude/skills/
    2. Cursor Agent: .cursor/rules/*.mdc & .cursorrules
    3. Google Antigravity / Gemini CLI: .gemini/skills/
    4. Windsurf (Codeium Cascade): .windsurfrules
    5. GitHub Copilot: .github/copilot-instructions.md
    6. ReAct / Standard: defense_skills/ & manifest.json
    """
    target_path = Path(target_path).resolve()
    skill_name = skill_bundle_path.name
    skill_md_content = (skill_bundle_path / "SKILL.md").read_text(encoding="utf-8")
    context_md = generate_context_blueprint_markdown(context)

    # Nhúng Bản Đồ Ngữ Cảnh vào SKILL.md
    if "BẢN ĐỒ NGỮ CẢNH DỰ ÁN MỤC TIÊU" not in skill_md_content:
        skill_md_content = skill_md_content + "\n\n" + context_md
        (skill_bundle_path / "SKILL.md").write_text(skill_md_content, encoding="utf-8")

    # Lưu context blueprint ra file json để các Agent dễ phân tích dạng có cấu trúc
    refs_dir = skill_bundle_path / "references"
    refs_dir.mkdir(parents=True, exist_ok=True)
    (refs_dir / "project_context_blueprint.json").write_text(json.dumps(context, indent=2, ensure_ascii=False), encoding="utf-8")

    print("\n[*] ĐANG ĐỒNG BỘ KỸ NĂNG TỚI TOÀN BỘ CÁC NỀN TẢNG AI AGENT LỚN:")

    # 1. CLAUDE CODE (ANTHROPIC)
    # Tạo .claude/skills/ và CLAUDE.md ở root dự án đích
    claude_skill_dir = target_path / ".claude" / "skills" / skill_name
    claude_skill_dir.mkdir(parents=True, exist_ok=True)
    shutil.copytree(skill_bundle_path, claude_skill_dir, dirs_exist_ok=True)
    
    claude_md_path = target_path / "CLAUDE.md"
    claude_instructions = f"""# CLAUDE CODE INSTRUCTIONS — AUTONOMOUS CTI DEFENSE SYSTEM

> **Dự án:** `{context['project_name']}`
> **Kỹ năng phòng thủ tích hợp:** `{skill_name}`
> **Nguồn tri thức:** CTI Autonomous Defense Orchestrator

## 🚀 NHIỆM VỤ CỦA CLAUDE CODE AGENT
Khi làm việc trong dự án này, bạn phải tuân thủ nghiêm ngặt Gói Kỹ Năng Phòng Thủ:
1. Đọc hướng dẫn chi tiết tại: `.claude/skills/{skill_name}/SKILL.md`
2. Kiểm tra các điểm nóng nhạy cảm đã phát hiện trong dự án:
   - Các file entrypoints: {', '.join(context.get('entrypoints', [])[:4])}
   - Các hàm nhạy cảm: xem `references/project_context_blueprint.json`
3. Chạy script kiểm thử an toàn:
   `python .claude/skills/{skill_name}/scripts/verify_exploit.py http://localhost:8766`
4. Refactor mã nguồn đạt tiêu chí Zero-Vulnerability trước khi kết thúc tác vụ.
"""
    claude_md_path.write_text(claude_instructions, encoding="utf-8")
    print(f"  [+] Claude Code (Anthropic): Đã sinh CLAUDE.md và .claude/skills/{skill_name}/")

    # 2. CURSOR AGENT
    # Tạo .cursor/rules/<skill_name>.mdc và .cursorrules ở root
    cursor_rules_dir = target_path / ".cursor" / "rules"
    cursor_rules_dir.mkdir(parents=True, exist_ok=True)
    mdc_file = cursor_rules_dir / f"{skill_name}.mdc"
    mdc_content = f"""---
description: CTI Autonomous Defense Protocol for {context['project_name']}
globs: "**/*.{{js,ts,py,php,go,java,cs}}"
alwaysApply: true
---

# CURSOR AGENT SECURITY RULE — {skill_name}

{context_md}

## NGUYÊN TẮC BẮT BUỘC KHI SINH HOẶC SỬA MÃ NGUỒN:
1. Tuyệt đối không dùng `exec()` hoặc `os.system()`. Sử dụng `execFile` hoặc `subprocess.run(shell=False)`.
2. Không nối chuỗi SQL thô. Bắt buộc dùng Parameterized Queries.
3. Tham chiếu mã mẫu chuẩn trong: `defense_skills/{skill_name}/examples/`
"""
    mdc_file.write_text(mdc_content, encoding="utf-8")

    cursorrules_file = target_path / ".cursorrules"
    cursorrules_file.write_text(mdc_content, encoding="utf-8")
    
    # Copy full bundle vào .cursor/rules để Cursor Agent truy cập examples/ và scripts/
    cursor_bundle_dir = cursor_rules_dir / skill_name
    shutil.copytree(skill_bundle_path, cursor_bundle_dir, dirs_exist_ok=True)
    print(f"  [+] Cursor Agent: Đã sinh .cursor/rules/{skill_name}.mdc và .cursorrules")

    # 3. GOOGLE ANTIGRAVITY & GEMINI CLI
    gemini_skill_dir = target_path / ".gemini" / "skills" / skill_name
    gemini_skill_dir.mkdir(parents=True, exist_ok=True)
    shutil.copytree(skill_bundle_path, gemini_skill_dir, dirs_exist_ok=True)
    print(f"  [+] Google Antigravity & Gemini CLI: Đã sinh .gemini/skills/{skill_name}/")

    # 4. WINDSURF (CODEIUM CASCADE AGENT)
    windsurf_file = target_path / ".windsurfrules"
    windsurf_content = f"""# WINDSURF CASCADE SECURITY RULES — {skill_name}

{context_md}

## CHỈ DẪN REFACTOR CHO CASCADE:
- Luôn kiểm tra các điểm nóng bảo mật trước khi commit.
- Mẫu code an toàn: `defense_skills/{skill_name}/examples/`
- Script kiểm thử: `python defense_skills/{skill_name}/scripts/verify_exploit.py http://localhost:8766`
"""
    windsurf_file.write_text(windsurf_content, encoding="utf-8")
    print(f"  [+] Windsurf (Codeium Cascade): Đã sinh .windsurfrules")

    # 5. GITHUB COPILOT WORKSPACE
    copilot_dir = target_path / ".github"
    copilot_dir.mkdir(parents=True, exist_ok=True)
    copilot_file = copilot_dir / "copilot-instructions.md"
    copilot_file.write_text(f"""# GITHUB COPILOT CODING INSTRUCTIONS

Dự án này áp dụng tiêu chuẩn phòng thủ an ninh mạng tự hành CTI ({skill_name}).
Mọi gợi ý mã nguồn cần:
1. Áp dụng Input Validation Whitelist nghiêm ngặt.
2. Không sinh mã thực thi lệnh shell trực tiếp.
3. Dùng Parameterized Queries cho cơ sở dữ liệu.
""", encoding="utf-8")
    print(f"  [+] GitHub Copilot: Đã sinh .github/copilot-instructions.md")

    # 6. OPENAI / GENERIC AGENTS CATALOG
    defense_skills_dir = target_path / "defense_skills" / skill_name
    defense_skills_dir.mkdir(parents=True, exist_ok=True)
    shutil.copytree(skill_bundle_path, defense_skills_dir, dirs_exist_ok=True)
    print(f"  [+] Standard Agent Package: Đã nạp defense_skills/{skill_name}/")
