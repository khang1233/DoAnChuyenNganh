# -*- coding: utf-8 -*-
"""
OPENCLAW LOCAL AI AGENT — INTERACTIVE CLI CHAT (KHANG-AI • GOOGLE GEMMA 3 • 100% GPU RX 6600)
Cho phép Khang vừa chat hỏi đáp tự do có bộ nhớ ngữ cảnh (Multi-turn Memory) với AI Local (Offline),
vừa có thể gõ IP/CVE/Domain để AI tự động gọi Tool chấm điểm VirusTotal/AbuseIPDB/Shodan ngay trên CLI!
"""

import os
import sys
from pathlib import Path
import requests

os.environ["OLLAMA_MODELS"] = r"D:\mkhang\DoAnChuyenNganh\ollama_models"

REPO_ROOT = Path(__file__).resolve().parents[1] / "ai-devsecops-agent"
SANDBOX_DIR = Path(__file__).resolve().parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))
if str(SANDBOX_DIR) not in sys.path:
    sys.path.insert(0, str(SANDBOX_DIR))

import re
from src.security.enrichment_service import enrich_ioc_list
from phuc_core_ai_agent import MultiProviderLLMBrain, tool6_extract_iocs_hybrid


def main() -> None:
    model_name = sys.argv[1] if len(sys.argv) > 1 else "khang-qwen3"
    MultiProviderLLMBrain._ensure_and_detect_local_ollama_model(model_name)

    print("=" * 86)
    print(f"🧠 OPENCLAW LOCAL AI AGENT CLI — MODEL: {model_name.upper()} (QWEN 3 - 8B • 100% GPU RX 6600 8GB)")
    print("   • Đã tích hợp Bộ nhớ Hội thoại (Multi-turn Memory) + Hiểu tiếng Việt không dấu & Zero Tiếng Trung.")
    print("   • MẸO: Để gõ tiếng Việt CÓ DẤU mượt nhất, hãy mở tab '💬 Chat AI Có Dấu' trên http://127.0.0.1:8765")
    print("   • Gõ câu có kèm IP / Domain / CVE (VD: 'kiểm tra IP 202.182.109.151 và CVE-2026-72898')")
    print("     để AI tự động kích hoạt Tool VirusTotal + AbuseIPDB + Shodan trước khi trả lời!")
    print("   • Gõ 'exit' hoặc 'quit' để thoát.")
    print("=" * 86)

    history = []

    while True:
        try:
            user_input = input("\nroot@khang-cti:~$ ").strip()
        except (EOFError, KeyboardInterrupt):
            print("\n[OK] Đã thoát CLI AI Agent.")
            break

        if not user_input:
            continue
        if user_input.lower() in {"exit", "quit", "q"}:
            print("[OK] Đã thoát CLI AI Agent.")
            break

        # Kiểm tra xem câu hỏi có chứa IP / Domain / CVE / SHA256 nào không để tự động gọi Tool!
        extracted_iocs = tool6_extract_iocs_hybrid(user_input)
        tool_context = ""
        if extracted_iocs:
            print(f"⚡ [OpenClaw Tool-Calling] Phát hiện {len(extracted_iocs)} IOC -> Đang tra cứu VirusTotal, AbuseIPDB & Shodan...")
            enriched = enrich_ioc_list(extracted_iocs, call_vt_http=True)
            lines = []
            for item in enriched:
                vt = item.raw_lookup_details.get("virustotal", {}).get("detection_ratio", "N/A")
                ab = item.raw_lookup_details.get("abuseipdb", {}).get("abuse_confidence_score", 0)
                sh = item.raw_lookup_details.get("shodan_internetdb", {}).get("ports", [])
                verdict = "ĐỘC HẠI (>80 - CẦN CHẶN & SINH RULE)" if item.is_malicious else "AN TOÀN (<=80 - BẢO VỆ)"
                line = f"  - {item.ioc.ioc_type} `{item.ioc.value}`: Điểm={item.reputation_score}/100 ({verdict}) | VT={vt} | AbuseIPDB={ab}% | Shodan Ports={sh}"
                print(line)
                lines.append(line)
            tool_context = "\n\n[DỮ LIỆU THỰC TẾ TỪ CÔNG CỤ VIRUSTOTAL + ABUSEIPDB + SHODAN CỦA KHANG]:\n" + "\n".join(lines)

        history.append({"role": "user", "content": user_input + tool_context})
        try:
            resp = requests.post(
                "http://127.0.0.1:11434/api/chat",
                json={"model": model_name, "messages": history, "stream": False, "think": False},
                timeout=90,
            )
            ans = resp.json().get("message", {}).get("content", "").strip()
            ans = re.sub(r"<think>.*?</think>", "", ans, flags=re.DOTALL).strip()
            history.append({"role": "assistant", "content": ans})
            print(f"\n[OpenClaw-AI // {model_name}] >\n{ans}")
        except Exception as exc:
            print(f"\n[ERR] Không kết nối được Ollama: {exc}")


if __name__ == "__main__":
    main()
