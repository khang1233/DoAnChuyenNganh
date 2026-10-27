# AGENTS.md — Repository Guidelines for Autonomous Agents

This document defines the behavioral contract, authority boundaries, and integration standards for all AI coding agents working in or integrating with this repository.

---

## 1. Core Principles

1. **Evidence-Driven Operation (Grounding Truth)**:
   - All defensive recommendations, firewall blocklists, and vulnerability assessments must be grounded in raw evidence extracted from verified CTI feeds.
   - Agents must never invent hypothetical CVEs, IP addresses, or exploit mechanics.
2. **Fail-Closed Security Posture**:
   - If an indicator has high ambiguity or conflicts with essential public infrastructure (e.g. DNS servers `8.8.8.8`, `1.1.1.1`), the system must fail-safe: mark as clean, drop from blocklists, and flag for passive monitoring.
3. **Actionable Over Static**:
   - Rather than merely generating static regex text, defense outputs must be packaged into full **Agentic Skill Packages** equipped with executable verification probes (`scripts/`) and implementation fixtures (`examples/`).

---

## 2. Agent Workflow: How to Protect a Project

When an agent is asked to integrate this CTI defense system into an external project:

```
[Agent reads AGENTS.md]
        │
        ▼
[Run apply_to_project.py --target <project_dir>]
        │
        ├─► Scans file signatures (composer.json, package.json, requirements.txt)
        ├─► Maps project to optimal Scope (SCOPE_WEB, SCOPE_NETWORK, etc.)
        ├─► Installs matching skill into .cursor/rules/ and .gemini/skills/
        └─► Generates AGENT_REMEDIATION_GUIDE.md inside the target project
        │
        ▼
[Target Agent reads installed SKILL.md & SOP]
        │
        ├─► Refactors vulnerable code using examples/patched_secure_sample.php
        ├─► Executes scripts/verify_exploit.py to confirm zero vulnerability
        └─► Commits changes with verified audit trail
```

---

## 3. Skill Package Directory Standard

All skills in `skills/` must strictly conform to this structure:

| Path | Purpose | Consumption Mode |
| :--- | :--- | :--- |
| `SKILL.md` | Main prompt instructions, metadata frontmatter, SOP playbook | Read by LLM Agent |
| `manifest.json` | Package metadata, tools schema, engine bindings | Parsed by Agent Loaders |
| `scripts/verify_exploit.py` | Standalone script to probe target application | Executed via tool-call |
| `scripts/apply_virtual_patch.py` | Standalone script to activate WAF & Firewall | Executed via tool-call |
| `rules/*.conf, *.rules, *.xml` | Real production rules for ModSecurity, Suricata, Wazuh | Ingested by defense engines |
| `references/cti_verbatim_report.txt` | 100% full-text source article for Ctrl+F grounding | Cross-referenced for audit |
| `references/xai_audit_trail.json` | Mathematical feature attribution & counterfactuals | Audited for Trust validation |
| `examples/vulnerable_sample.*` | Negative test fixture (unsafe code before fix) | Read for pattern matching |
| `examples/patched_secure_sample.*` | Positive test fixture (hardened code after fix) | Read as refactoring target |

---

## 4. Environment & Execution Guidelines

- **Python**: Version 3.10+ required.
- **SQLite Database**: Located at `khang_sandbox_full_cti/cti_multi_source_archive.sqlite` (contains full-text articles and learned IOCs).
- **FastAPI Backend**: Run `1_BAT_HE_THONG.bat` to launch on port `8765` (Dashboard) and port `8766` (WAF Proxy).
- **Firewall Integration**: Any Windows Firewall modification via `openclaw_firewall_bridge.py` requires elevated permissions and must support instant rollback via `rollback_firewall.bat`.
