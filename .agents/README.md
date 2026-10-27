# Agent Skills & Directives

This directory provides compatibility for AI Agent frameworks (such as AutoGPT, Claude Code, and REA-style Agent loaders).

The full, production-grade Agentic Defense Skill Packages are located in the top-level `skills/` directory:
- `skills/agentic-defense-cve-2026-109618-php2shell-exploit-attempt/`
  - `manifest.json`
  - `SKILL.md`
  - `scripts/`
  - `rules/`
  - `references/`
  - `examples/`

To apply any skill to an external project, run:
```bash
python apply_to_project.py --target /path/to/target-project
```
