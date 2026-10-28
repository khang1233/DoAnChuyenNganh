# -*- coding: utf-8 -*-
"""
MULTI-AGENT COMPATIBILITY & CONTEXT-AWARE ORCHESTRATOR
Giải quyết triệt để 2 vấn đề lớn:
1. Xuất Kỹ Năng Tác Tử chuẩn định dạng riêng cho TOÀN BỘ CÁC NỀN TẢNG AI AGENT LỚN HIỆN NAY:
   - Claude Code (Anthropic): CLAUDE.md và .claude/skills/
   - Cursor Agent: .cursor/rules/*.mdc và .cursorrules
   - Google Antigravity / Gemini CLI: .gemini/skills/ và .gemini/rules/
   - OpenAI Codex & ChatGPT: CODEX.md, OPENAI.md, .codex/instructions.md
   - Aider (AI Pair Programmer): .aider.conf.yml, .aider.prompt.md, CONVENTIONS.md
   - Continue.dev: .continue/config.json, .continue/prompts/, .continue/rules/
   - Cline & Roo Code: .clinerules, .roomodes
   - Devin AI (Cognition): DEVIN.md, .devin/instructions.md
   - Windsurf (Codeium Cascade): .windsurfrules
   - GitHub Copilot: .github/copilot-instructions.md
   - Zed Editor: .zed/settings.json, .zed/prompts/
   - JetBrains AI Assistant / Junie: .jetbrains/ai-instructions.md
   - Amazon Q Developer: .amazonq/rules.md
   - Sourcegraph Cody: .cody/prompts/cody-instructions.md
   - Universal ReAct / Standard: defense_skills/ & manifest.json

2. Quét và trích xuất Ngữ Cảnh Dự Án Thực Tế (Project Context-Aware Grounding):
   - Tự động đọc cấu trúc thư mục, entrypoint, frameworks, và các điểm nhạy cảm
     (Sensitive Sinks: execAsync, db.query, subprocess...) để chỉ dẫn chính xác
     cho bất kỳ AI Agent nào mở dự án ra đều biết cụ thể file nào cần sửa.
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
            for fw in ["express", "fastify", "react", "vite", "mysql", "mysql2", "sqlite3", "sequelize", "mongoose", "axios", "discord.js"]:
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
    ignored_patterns = [".git", "node_modules", "venv", ".venv", "dist", "build", ".cursor", ".gemini", ".claude", ".continue", ".zed", ".idea", "defense_skills"]
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
    Sinh tài liệu Bản Đồ Ngữ Cảnh Dự Án Thực Tế để nhúng vào SKILL.md và các file quy tắc agent.
    """
    pname = context.get("project_name", "Target Project")
    fws = ", ".join(context.get("frameworks", [])) or "Custom Web Stack"
    entrypoints = context.get("entrypoints", [])
    sinks = context.get("sensitive_sinks", [])

    lines = [
        "## 🧭 BẢN ĐỒ NGỮ CẢNH DỰ ÁN MỤC TIÊU (TARGET PROJECT ARCHITECTURAL CONTEXT)",
        "",
        "> [!IMPORTANT]",
        f"> **Tác tử AI (Claude, Cursor, Codex, Antigravity, Devin, Aider, Continue)**: Dự án `{pname}` đã được hệ thống CTI thẩm định ngữ cảnh.",
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
    Đóng gói và phân phối Kỹ Năng Tác Tử đến TOÀN BỘ CÁC NỀN TẢNG AGENT LỚN TRÊN THẾ GIỚI:
    1. Claude Code (Anthropic): CLAUDE.md & .claude/skills/
    2. Cursor Agent: .cursor/rules/*.mdc & .cursorrules
    3. Google Antigravity & Gemini CLI: .gemini/skills/ & .gemini/rules/
    4. OpenAI Codex & ChatGPT: CODEX.md, OPENAI.md, .codex/instructions.md
    5. Aider (AI Pair Programmer): .aider.conf.yml, .aider.prompt.md, CONVENTIONS.md
    6. Continue.dev: .continue/config.json, .continue/prompts/, .continue/rules/
    7. Cline & Roo Code: .clinerules, .roomodes
    8. Devin AI (Cognition): DEVIN.md, .devin/instructions.md
    9. Windsurf (Codeium Cascade): .windsurfrules
    10. GitHub Copilot: .github/copilot-instructions.md
    11. Zed Editor: .zed/settings.json, .zed/prompts/
    12. JetBrains AI Assistant / Junie: .jetbrains/ai-instructions.md
    13. Amazon Q Developer: .amazonq/rules.md
    14. Sourcegraph Cody: .cody/prompts/cody-instructions.md
    15. Universal ReAct / Standard: defense_skills/ & manifest.json
    """
    target_path = Path(target_path).resolve()
    skill_name = skill_bundle_path.name
    pname = context.get("project_name", target_path.name)
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
    claude_skill_dir = target_path / ".claude" / "skills" / skill_name
    claude_skill_dir.mkdir(parents=True, exist_ok=True)
    shutil.copytree(skill_bundle_path, claude_skill_dir, dirs_exist_ok=True)
    
    claude_md_path = target_path / "CLAUDE.md"
    claude_instructions = f"""# CLAUDE CODE INSTRUCTIONS — AUTONOMOUS CTI DEFENSE SYSTEM

> **Dự án:** `{pname}`
> **Kỹ năng phòng thủ tích hợp:** `{skill_name}`
> **Nguồn tri thức:** CTI Autonomous Defense Orchestrator

{context_md}

## 🚀 NHIỆM VỤ CỦA CLAUDE CODE AGENT
Khi làm việc trong dự án này, bạn phải tuân thủ nghiêm ngặt Gói Kỹ Năng Phòng Thủ:
1. Đọc hướng dẫn chi tiết tại: `.claude/skills/{skill_name}/SKILL.md`
2. Kiểm tra các điểm nóng nhạy cảm đã phát hiện trong dự án (xem bảng trên).
3. Chạy script kiểm thử an toàn:
   `python .claude/skills/{skill_name}/scripts/verify_exploit.py http://localhost:8766`
4. Đối chiếu mã mẫu an toàn trong `.claude/skills/{skill_name}/examples/` để refactor mã nguồn đạt tiêu chí Zero-Vulnerability.
"""
    claude_md_path.write_text(claude_instructions, encoding="utf-8")
    print(f"  [+] 1. Claude Code (Anthropic): Đã sinh CLAUDE.md và .claude/skills/{skill_name}/")

    # 2. CURSOR AGENT
    cursor_rules_dir = target_path / ".cursor" / "rules"
    cursor_rules_dir.mkdir(parents=True, exist_ok=True)
    mdc_file = cursor_rules_dir / f"{skill_name}.mdc"
    mdc_content = f"""---
description: CTI Autonomous Defense Protocol for {pname}
globs: "**/*.{{js,ts,py,php,go,java,cs}}"
alwaysApply: true
---

# CURSOR AGENT SECURITY RULE — {skill_name}

{context_md}

## NGUYÊN TẮC BẮT BUỘC KHI SINH HOẶC SỬA MÃ NGUỒN:
1. Tuyệt đối không dùng `exec()` hoặc `os.system()`. Sử dụng `execFile` hoặc `subprocess.run(shell=False)`.
2. Không nối chuỗi SQL thô. Bắt buộc dùng Parameterized Queries.
3. Tham chiếu mã mẫu chuẩn trong: `defense_skills/{skill_name}/examples/`
4. Chạy kiểm thử xác nhận: `python defense_skills/{skill_name}/scripts/verify_exploit.py http://localhost:8766`
"""
    mdc_file.write_text(mdc_content, encoding="utf-8")

    cursorrules_file = target_path / ".cursorrules"
    cursorrules_file.write_text(mdc_content, encoding="utf-8")
    
    cursor_bundle_dir = cursor_rules_dir / skill_name
    shutil.copytree(skill_bundle_path, cursor_bundle_dir, dirs_exist_ok=True)
    print(f"  [+] 2. Cursor Agent: Đã sinh .cursor/rules/{skill_name}.mdc và .cursorrules")

    # 3. GOOGLE ANTIGRAVITY & GEMINI CLI
    gemini_skill_dir = target_path / ".gemini" / "skills" / skill_name
    gemini_skill_dir.mkdir(parents=True, exist_ok=True)
    shutil.copytree(skill_bundle_path, gemini_skill_dir, dirs_exist_ok=True)
    
    gemini_rules_dir = target_path / ".gemini" / "rules"
    gemini_rules_dir.mkdir(parents=True, exist_ok=True)
    (gemini_rules_dir / f"{skill_name}.md").write_text(mdc_content, encoding="utf-8")
    print(f"  [+] 3. Google Antigravity & Gemini CLI: Đã sinh .gemini/skills/{skill_name}/ và .gemini/rules/")

    # 4. OPENAI CODEX & CHATGPT AGENT
    codex_file = target_path / "CODEX.md"
    codex_content = f"""# OPENAI CODEX INSTRUCTIONS — CTI AGENTIC DEFENSE PROTOCOL

> **Target Project:** `{pname}`
> **Active Defense Skill:** `{skill_name}`
> **Framework:** {', '.join(context.get('frameworks', [])) or 'Web Full-Stack'}

{context_md}

## 🛡️ CODEX CODING DIRECTIVES:
1. **Never Generate Arbitrary Execution Sinks:** Avoid `exec()`, `eval()`, or unescaped shell invocations.
2. **Mandatory Parameterized Queries:** Prevent SQL injection by using ORM bindings or prepared statements.
3. **Reference Hardened Samples:** Review `defense_skills/{skill_name}/examples/` before refactoring.
4. **Verification Requirement:** Confirm changes using `python defense_skills/{skill_name}/scripts/verify_exploit.py http://localhost:8766`.
"""
    codex_file.write_text(codex_content, encoding="utf-8")

    openai_file = target_path / "OPENAI.md"
    openai_file.write_text(codex_content, encoding="utf-8")

    codex_dir = target_path / ".codex"
    codex_dir.mkdir(parents=True, exist_ok=True)
    (codex_dir / "instructions.md").write_text(codex_content, encoding="utf-8")

    openai_dir = target_path / ".openai"
    openai_dir.mkdir(parents=True, exist_ok=True)
    (openai_dir / "instructions.md").write_text(codex_content, encoding="utf-8")
    print(f"  [+] 4. OpenAI Codex & ChatGPT: Đã sinh CODEX.md, OPENAI.md, .codex/ và .openai/")

    # 5. AIDER AI PAIR PROGRAMMER
    aider_conf = target_path / ".aider.conf.yml"
    aider_conf.write_text(f"""# AIDER AI PAIR PROGRAMMER CONFIGURATION
model: claude-3-5-sonnet-20241022
read:
  - AGENT_REMEDIATION_GUIDE.md
  - .aider.prompt.md
  - CONVENTIONS.md
auto-commits: false
""", encoding="utf-8")

    aider_prompt = target_path / ".aider.prompt.md"
    aider_prompt.write_text(f"""# AIDER DEFENSE DIRECTIVE — {skill_name}

You are acting as an automated security defense agent for `{pname}`.
Enforce CTI-driven security standards across all code modifications:
- Check sensitive entrypoints before editing.
- Reference safe patterns in `defense_skills/{skill_name}/examples/`.
- Validate exploit resistance with: `python defense_skills/{skill_name}/scripts/verify_exploit.py http://localhost:8766`.
""", encoding="utf-8")

    conventions_file = target_path / "CONVENTIONS.md"
    conventions_file.write_text(f"""# PROJECT CONVENTIONS & SECURITY STANDARDS — {pname}

1. All external inputs must be validated against a strict whitelist.
2. System commands must use argument arrays (no string concatenation via shell).
3. Database access must use parameter bindings exclusively.
4. Active CTI Skill: `defense_skills/{skill_name}/SKILL.md`.
""", encoding="utf-8")
    print(f"  [+] 5. Aider AI: Đã sinh .aider.conf.yml, .aider.prompt.md và CONVENTIONS.md")

    # 6. CONTINUE.DEV (VS CODE & JETBRAINS EXTENSION)
    continue_dir = target_path / ".continue"
    continue_prompts_dir = continue_dir / "prompts"
    continue_rules_dir = continue_dir / "rules"
    continue_prompts_dir.mkdir(parents=True, exist_ok=True)
    continue_rules_dir.mkdir(parents=True, exist_ok=True)

    continue_config = continue_dir / "config.json"
    continue_config.write_text(json.dumps({
        "name": f"CTI Defense Agent ({pname})",
        "systemMessage": f"You are a CTI-grounded security agent. Follow defense_skills/{skill_name}/SKILL.md strictly."
    }, indent=2), encoding="utf-8")

    (continue_prompts_dir / "cti-defense.md").write_text(f"""---
name: cti-defense
description: Run CTI security audit and auto-remediation on current file
---

Review this code against the CTI Defense Skill `{skill_name}`.
Identify any command injection, SQL injection, or unvalidated input sinks.
Propose a hardened drop-in replacement based on `defense_skills/{skill_name}/examples/`.
""", encoding="utf-8")

    (continue_rules_dir / "security.md").write_text(mdc_content, encoding="utf-8")
    print(f"  [+] 6. Continue.dev: Đã sinh .continue/config.json, prompts/ và rules/")

    # 7. CLINE & ROO CODE (VS CODE AUTONOMOUS AGENTS)
    clinerules_file = target_path / ".clinerules"
    clinerules_file.write_text(f"""# CLINE / ROO CODE AGENTIC PROTOCOL — {skill_name}

> Project: {pname}
> Context: {', '.join(context.get('frameworks', []))}

{context_md}

## EXECUTION WORKFLOW FOR CLINE / ROO CODE:
1. Read `defense_skills/{skill_name}/SKILL.md` to understand threat landscape.
2. Examine `defense_skills/{skill_name}/examples/` for positive vs negative fixtures.
3. Execute probe: `python defense_skills/{skill_name}/scripts/verify_exploit.py http://localhost:8766`.
4. Refactor code at identified sinks until probe confirms 0 vulnerabilities.
""", encoding="utf-8")

    roomodes_file = target_path / ".roomodes"
    roomodes_file.write_text(json.dumps({
        "customModes": [{
            "slug": "cti-security",
            "name": "CTI Security Refactor",
            "roleDefinition": f"Autonomous Security Auditor for {pname} enforcing {skill_name}.",
            "groups": ["read", "edit", "command"]
        }]
    }, indent=2), encoding="utf-8")
    print(f"  [+] 7. Cline & Roo Code: Đã sinh .clinerules và .roomodes")

    # 8. DEVIN AI (COGNITION SOFTWARE ENGINEER)
    devin_file = target_path / "DEVIN.md"
    devin_content = f"""# DEVIN AI INSTRUCTIONS — CTI DEFENSE IMPLEMENTATION

> Target Project: `{pname}`
> Skill Bundle: `{skill_name}`

{context_md}

## DEVIN OBJECTIVES:
1. Locate sensitive sinks detailed in `references/project_context_blueprint.json`.
2. Apply secure coding fixtures from `defense_skills/{skill_name}/examples/`.
3. Verify that `python defense_skills/{skill_name}/scripts/verify_exploit.py http://localhost:8766` passes cleanly.
4. Commit changes with title: `fix(security): eliminate vulnerabilities per CTI skill {skill_name}`.
"""
    devin_file.write_text(devin_content, encoding="utf-8")

    devin_dir = target_path / ".devin"
    devin_dir.mkdir(parents=True, exist_ok=True)
    (devin_dir / "instructions.md").write_text(devin_content, encoding="utf-8")
    print(f"  [+] 8. Devin AI (Cognition): Đã sinh DEVIN.md và .devin/instructions.md")

    # 9. WINDSURF (CODEIUM CASCADE AGENT)
    windsurf_file = target_path / ".windsurfrules"
    windsurf_content = f"""# WINDSURF CASCADE SECURITY RULES — {skill_name}

{context_md}

## CHỈ DẪN REFACTOR CHO CASCADE:
- Luôn kiểm tra các điểm nóng bảo mật trước khi commit.
- Mẫu code an toàn: `defense_skills/{skill_name}/examples/`
- Script kiểm thử: `python defense_skills/{skill_name}/scripts/verify_exploit.py http://localhost:8766`
"""
    windsurf_file.write_text(windsurf_content, encoding="utf-8")
    print(f"  [+] 9. Windsurf (Codeium Cascade): Đã sinh .windsurfrules")

    # 10. GITHUB COPILOT WORKSPACE
    copilot_dir = target_path / ".github"
    copilot_dir.mkdir(parents=True, exist_ok=True)
    copilot_file = copilot_dir / "copilot-instructions.md"
    copilot_file.write_text(f"""# GITHUB COPILOT CODING INSTRUCTIONS

Dự án này áp dụng tiêu chuẩn phòng thủ an ninh mạng tự hành CTI ({skill_name}).
Mọi gợi ý mã nguồn cần:
1. Áp dụng Input Validation Whitelist nghiêm ngặt.
2. Không sinh mã thực thi lệnh shell trực tiếp (tránh `exec`, `os.system`).
3. Dùng Parameterized Queries cho cơ sở dữ liệu.
4. Tham khảo mẫu mã nguồn an toàn tại: `defense_skills/{skill_name}/examples/`.
""", encoding="utf-8")
    print(f"  [+] 10. GitHub Copilot: Đã sinh .github/copilot-instructions.md")

    # 11. ZED EDITOR
    zed_dir = target_path / ".zed"
    zed_prompts_dir = zed_dir / "prompts"
    zed_prompts_dir.mkdir(parents=True, exist_ok=True)
    
    (zed_dir / "settings.json").write_text(json.dumps({
        "assistant": {
            "default_model": {
                "provider": "anthropic",
                "model": "claude-3-5-sonnet-latest"
            }
        }
    }, indent=2), encoding="utf-8")

    (zed_prompts_dir / "security.md").write_text(f"""# Zed AI Security Assistant Prompt
Follow CTI Defense guidelines in `defense_skills/{skill_name}/SKILL.md`.
Enforce zero arbitrary command execution and parameterized database access.
""", encoding="utf-8")
    print(f"  [+] 11. Zed Editor: Đã sinh .zed/settings.json và .zed/prompts/")

    # 12. JETBRAINS AI ASSISTANT / JUNIE
    jetbrains_dir = target_path / ".jetbrains"
    jetbrains_dir.mkdir(parents=True, exist_ok=True)
    (jetbrains_dir / "ai-instructions.md").write_text(f"""# JETBRAINS AI ASSISTANT GUIDELINES — {skill_name}

Project: `{pname}`
Enforce secure coding conventions:
- Consult `defense_skills/{skill_name}/examples/` for language-specific fixtures.
- Sinks to harden: see `references/project_context_blueprint.json`.
- Execute verification: `python defense_skills/{skill_name}/scripts/verify_exploit.py http://localhost:8766`.
""", encoding="utf-8")

    idea_dir = target_path / ".idea"
    if idea_dir.exists():
        (idea_dir / "ai-instructions.md").write_text((jetbrains_dir / "ai-instructions.md").read_text(encoding="utf-8"), encoding="utf-8")
    print(f"  [+] 12. JetBrains AI Assistant / Junie: Đã sinh .jetbrains/ai-instructions.md")

    # 13. AMAZON Q DEVELOPER (AWS CODEWHISPERER)
    amazonq_dir = target_path / ".amazonq"
    amazonq_dir.mkdir(parents=True, exist_ok=True)
    (amazonq_dir / "rules.md").write_text(f"""# AMAZON Q DEVELOPER RULES — {skill_name}

All code recommendations must comply with CTI Defense Skill `{skill_name}`.
Validate user input, avoid shell execution concatenation, and utilize parameterized queries.
""", encoding="utf-8")
    print(f"  [+] 13. Amazon Q Developer: Đã sinh .amazonq/rules.md")

    # 14. SOURCEGRAPH CODY
    cody_dir = target_path / ".cody"
    cody_prompts_dir = cody_dir / "prompts"
    cody_prompts_dir.mkdir(parents=True, exist_ok=True)
    (cody_prompts_dir / "cody-instructions.md").write_text(f"""# SOURCEGRAPH CODY INSTRUCTIONS
Always adhere to security guidelines specified in `defense_skills/{skill_name}/SKILL.md`.
""", encoding="utf-8")
    (cody_dir / "project.json").write_text(json.dumps({
        "name": pname,
        "securityPolicy": "CTI_DEFENSE_STRICT"
    }, indent=2), encoding="utf-8")
    print(f"  [+] 14. Sourcegraph Cody: Đã sinh .cody/prompts/ và project.json")

    # 15. OPENAI / GENERIC AGENTS CATALOG & RFC STANDARDS
    defense_skills_dir = target_path / "defense_skills" / skill_name
    defense_skills_dir.mkdir(parents=True, exist_ok=True)
    shutil.copytree(skill_bundle_path, defense_skills_dir, dirs_exist_ok=True)
    print(f"  [+] 15. Standard Agent Package: Đã nạp defense_skills/{skill_name}/")
    print("[*] HOÀN TẤT ĐỒNG BỘ 15 NỀN TẢNG AGENT LỚN NHẤT THẾ GIỚI!")
