# GitHub Copilot Instructions for Autonomous CTI Platform

When assisting in this repository:
- This is a Cyber Threat Intelligence (CTI) and Agentic Defense system.
- When generating defense artifacts, refer to the structure in `skills/` and scripts in `khang_sandbox_full_cti/`.
- Respect the mathematical Trust Score framework defined in `khang_sandbox_full_cti/agentic_defense_skill_engine.py`.
- To connect defenses to another repository, use `apply_to_project.py --target <path>`.
- Do not introduce mock data into `cti_multi_source_archive.sqlite` — all articles must be full-text verbatim crawled from official feeds.
