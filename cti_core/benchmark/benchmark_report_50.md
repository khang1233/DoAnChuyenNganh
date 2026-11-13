# BAO CAO THUC NGHIEM CTI AI AGENT SINH AGENTIC SKILL (50 BAN TIN GAN TAY)
- **Mo hinh cuc bo (Local LLM):** `qwen3:8b`
- **So ban tin doi chuan Ground Truth:** `50` bai bao CTI dau nam 2026
- **Ty le IOC co bang chung xAI Grounding nguyen van:** `100.0%`

## BANG 1: DO DUNG KHI TRICH XUAT IOC (AGENT vs GROUND TRUTH GAN TAY)
| Loai IOC | So luong GT | Agent trich | TP | FP | FN | Precision (%) | Recall (%) | F1-Score (%) |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| IP | 67 | 66 | 64 | 2 | 3 | 96.97% | 95.52% | 96.24% |
| DOMAIN | 218 | 163 | 163 | 0 | 55 | 100.00% | 74.77% | 85.56% |
| URL | 119 | 115 | 106 | 9 | 13 | 92.17% | 89.08% | 90.60% |
| MD5 | 287 | 286 | 286 | 0 | 1 | 100.00% | 99.65% | 99.83% |
| SHA256 | 10 | 9 | 9 | 0 | 1 | 100.00% | 90.00% | 94.74% |
| CVE | 67 | 67 | 67 | 0 | 0 | 100.00% | 100.00% | 100.00% |
| **TONG HOP (Micro)** | **768** | **706** | **695** | **11** | **73** | **98.44%** | **90.49%** | **94.30%** |

## BANG 2: TY LE GOI SKILL HOP LE CAU TRUC & CU PHAP (SKILL VALIDITY RATE)
| Thanh phan Skill | Cong cu kiem dinh | Tong so goi | Dung cu phap tho (LLM) | Hop le sau kiem dinh | Ty le hop le (%) |
| :--- | :--- | :---: | :---: | :---: | :---: |
| `SKILL.md` | PyYAML Frontmatter + SOP | 50 | 47/50 (94.0%) | 50/50 | **100.00%** |
| `manifest.json` | JSON Schema (`AGENTS.md`) | 50 | 43/50 (86.0%) | 50/50 | **100.00%** |
| `scripts/verify_threat.py` | Python AST `compile()` | 50 | 37/50 (74.0%) | 50/50 | **100.00%** |
| `references/c2_ip_indicators.txt` | IPv4/Domain + Whitelist Check | 50 | 50/50 | 50/50 | **100.00%** |

## BANG 3: TY LE SKILL THUC THI BAT DUOC MAU THU (DETECTION & FALSE POSITIVE RATE)
| Kenh kiem thu trong Skill | Co che thuc thi | So bo mau thu | Bat trung mau doc hai (TP) | Detection Rate (%) | Bao nham mau sach (FP) |
| :--- | :--- | :---: | :---: | :---: | :---: |
| Log Telemetry Events | `scripts/verify_threat.py` (`scan_artifact(log_event)`) | 50 | 49/50 | **98.00%** | 0/50 |
| Binary / Payload Buffer | `scripts/verify_threat.py` (`scan_artifact(payload_bytes)`) | 50 | 48/50 | **96.00%** | 0/50 |
| Network C2 Indicators | `references/c2_ip_indicators.txt` vs Clean DNS/Domains | 43 | 36/43 | **83.72%** | 0/43 |