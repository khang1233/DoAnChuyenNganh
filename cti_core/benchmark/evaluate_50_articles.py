# -*- coding: utf-8 -*-
"""
Module: evaluate_50_articles.py
Chuc nang: Cham diem dinh luong toan dien Pipeline Local AI Agent sinh Agentic Skill
tren tap ~50 ban tin CTI dau nam 2026 da gan tay Ground Truth.
Xuat 3 bang so lieu chuan khoa hoc:
  Bang 1: Do dung khi trich xuat IOC (Precision, Recall, F1 theo tung loai IOC & Tong hop + xAI Grounding)
  Bang 2: Ty le goi Skill hop le cau truc & cu phap (SKILL.md, manifest.json, scripts/verify_threat.py, references/)
  Bang 3: Ty le Skill thuc thi bat duoc mau thu (Detection Rate & False Positive Rate tren mau log, payload & traffic)
"""

import argparse
import json
import re
import sys
from pathlib import Path
from typing import Any, Dict, List, Set, Tuple
from urllib.parse import urlparse

CORE_DIR = Path(__file__).resolve().parents[1]
BENCH_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(CORE_DIR))

from cti_local_agent_pipeline import (
    ensure_ollama_running,
    run_single_article_pipeline,
    refang,
)

ARTICLES_PATH = BENCH_DIR / "articles_50_2026.json"
GT_PATH = BENCH_DIR / "ground_truth_50.json"

BENIGN_TRAFFIC_FIXTURES = [
    "8.8.8.8", "1.1.1.1", "192.168.1.1", "10.0.0.1", "127.0.0.1",
    "google.com", "microsoft.com", "github.com", "cloudflare.com", "cisa.gov"
]

BENIGN_LOGS = [
    {"Image": "C:\\Windows\\System32\\svchost.exe", "CommandLine": "svchost.exe -k netsvcs", "DestinationIp": "8.8.8.8", "QueryName": "time.windows.com", "cs-uri-stem": "/index.html", "cs-uri-query": "page=1", "sc-status": 200, "Hashes": "SHA256=0000000000000000000000000000000000000000000000000000000000000000"},
    {"Image": "/usr/bin/python3", "CommandLine": "python3 app.py --port 8000", "DestinationIp": "1.1.1.1", "QueryName": "pypi.org", "cs-uri-stem": "/health", "cs-uri-query": "", "sc-status": 200, "Hashes": "MD5=11111111111111111111111111111111"},
]

BENIGN_BUFFERS = [
    b"Standard benign application configuration file\nserver=localhost\nport=8080\ndns=8.8.8.8\n",
    b"MZ\x90\x00Hello World legitimate utility version 2.4.1 build 2026 microsoft.com github.com",
]


def _norm_ioc(val: str, kind: str) -> str:
    s = refang(val).strip()
    if kind in ("DOMAIN", "MD5", "SHA256"):
        return s.lower()
    if kind == "CVE":
        return s.upper()
    if kind == "URL":
        return s.rstrip("/")
    return s


def build_positive_samples_from_gt(gt: Dict[str, Any]) -> Tuple[List[Dict[str, Any]], List[bytes], List[str]]:
    """Tao tap mau thu duong tinh tu dap an Ground Truth de kiem chung Script trong Skill."""
    pos_logs: List[Dict[str, Any]] = []
    pos_buffers: List[bytes] = []
    pos_net_iocs: List[str] = []

    ips = [refang(x) for x in gt.get("ips", [])]
    doms = [refang(x).lower() for x in gt.get("domains", [])]
    urls = [refang(x) for x in gt.get("urls", [])]
    hashes = [x.lower() for x in (gt.get("sha256", []) + gt.get("md5", []))]
    cves = [x.upper() for x in gt.get("cves", [])]
    behaviors = gt.get("attack_behaviors", [])

    for ip in ips[:3]:
        pos_logs.append({"DestinationIp": ip, "dst_ip": ip, "SourceIp": "10.10.1.50", "CommandLine": "outbound c2 connect"})
        pos_buffers.append(f"C2_BEACON host={ip} port=443".encode("utf-8"))
        pos_net_iocs.append(ip)
    for dom in doms[:3]:
        pos_logs.append({"QueryName": dom, "DestinationHostname": dom, "Host": dom, "CommandLine": f"curl https://{dom}/gate"})
        pos_buffers.append(f"HTTP/1.1 Host: {dom}\r\nUser-Agent: Malware\r\n".encode("utf-8"))
        pos_net_iocs.append(dom)
    for u in urls[:2]:
        pos_logs.append({"cs-uri-stem": u, "url": u, "QueryName": urlparse(u).hostname or ""})
        pos_buffers.append(f"payload_url={u}".encode("utf-8"))
        pos_net_iocs.append(u)
    for h in hashes[:3]:
        pos_logs.append({"Image": "C:\\Users\\Public\\payload.exe", "Hashes": f"SHA256={h},MD5={h}", "sha256": h, "md5": h})
        pos_buffers.append(f"sample_hash_artifact {h}".encode("utf-8"))
    for cve in cves[:2]:
        pos_logs.append({"cs-uri-stem": f"/api/exploit/{cve}", "cs-uri-query": "cmd=whoami", "sc-status": 200})
        pos_buffers.append(f"Exploit-PoC targeting {cve} cmd=id ../etc/passwd".encode("utf-8"))
    for beh in behaviors[:3]:
        pos_logs.append({"CommandLine": beh, "ProcessCommandLine": beh, "Image": beh, "cs-uri-stem": beh})
        pos_buffers.append(f"binary_string_artifact: {beh}".encode("utf-8"))

    if pos_logs:
        combined_log: Dict[str, Any] = {}
        for pl in pos_logs:
            for k, v in pl.items():
                if k not in combined_log:
                    combined_log[k] = v
                elif str(v) not in str(combined_log[k]):
                    combined_log[k] = f"{combined_log[k]} {v}"
        pos_logs.insert(0, combined_log)
    if pos_buffers:
        pos_buffers.insert(0, b"\n".join(pos_buffers))

    return pos_logs, pos_buffers, list(dict.fromkeys(pos_net_iocs))


def _load_skill_scan_fn(script_code: str):
    """Nap ham scan_artifact() tu scripts/verify_threat.py cua Skill vao namespace doc lap."""
    ns: Dict[str, Any] = {"__name__": "skill_verify_probe"}
    exec(compile(script_code, "<verify_threat.py>", "exec"), ns)
    fn = ns.get("scan_artifact")
    if not callable(fn):
        raise RuntimeError("Missing callable scan_artifact")
    return fn


def run_benchmark(model: str = "qwen3:8b", limit: int = 50, force_rerun: bool = False):
    if not ARTICLES_PATH.exists() or not GT_PATH.exists():
        print("[!] Chua co file articles_50_2026.json hoac ground_truth_50.json. Chay prepare_50_articles.py truoc.")
        return

    articles = json.loads(ARTICLES_PATH.read_text(encoding="utf-8"))
    gt_list = json.loads(GT_PATH.read_text(encoding="utf-8"))
    gt_map = {x["article_id"]: x for x in gt_list}

    annotated_articles = []
    for art in articles:
        g = gt_map.get(art["article_id"], {})
        gt_data = g.get("ground_truth", {})
        has_any_gt = any(bool(gt_data.get(k)) for k in ("ips", "domains", "urls", "md5", "sha256", "cves"))
        if g.get("annotation_status") == "done" or has_any_gt:
            annotated_articles.append((art, gt_data))

    if not annotated_articles:
        print("[!] Chua co bai bao nao duoc gan tay dap an trong ground_truth_50.json!")
        print("    Hay chay: python cti_core/benchmark/labeler_server.py")
        print("    Mo http://127.0.0.1:8780 de doc va gan tay dap an cho 50 bai bao truoc khi cham diem.")
        return

    annotated_articles = annotated_articles[:limit]
    ok, active_model = ensure_ollama_running(model)
    if not ok:
        print(f"[!] Loi Ollama: {active_model}")
        return

    safe_model_tag = re.sub(r"[^a-zA-Z0-9._-]", "_", active_model)
    cache_path = BENCH_DIR / f"agent_skill_runs_{safe_model_tag}.json"
    runs_cache: Dict[str, Any] = {}
    if cache_path.exists() and not force_rerun:
        runs_cache = json.loads(cache_path.read_text(encoding="utf-8"))

    print(f"[*] Bat dau Benchmark Skill Pipeline tren {len(annotated_articles)} bai bao da gan tay (Model: {active_model})...")

    ioc_types = ["IP", "DOMAIN", "URL", "MD5", "SHA256", "CVE"]
    type_key_map = {"IP": "ips", "DOMAIN": "domains", "URL": "urls", "MD5": "md5", "SHA256": "sha256", "CVE": "cves"}

    metrics: Dict[str, Dict[str, int]] = {t: {"gt": 0, "pred": 0, "tp": 0, "fp": 0, "fn": 0} for t in ioc_types}
    total_xai_grounded = 0
    total_predicted_iocs = 0

    syntax_stats = {
        "skill_md_total": 0, "skill_md_raw_ok": 0, "skill_md_final_ok": 0,
        "manifest_total": 0, "manifest_raw_ok": 0, "manifest_final_ok": 0,
        "script_total": 0, "script_raw_ok": 0, "script_final_ok": 0,
        "ref_total": 0, "ref_ok": 0,
    }

    detection_stats = {
        "log_tested": 0, "log_tp": 0, "log_fp_benign": 0,
        "buffer_tested": 0, "buffer_tp": 0, "buffer_fp_benign": 0,
        "network_tested": 0, "network_tp": 0, "network_fp_benign": 0,
    }

    per_article_details = []

    for idx, (art, gt_data) in enumerate(annotated_articles, 1):
        aid = art["article_id"]
        if aid in runs_cache and not force_rerun:
            agent_out = runs_cache[aid]
        else:
            print(f"  [{idx}/{len(annotated_articles)}] Agent ({active_model}) dang phan tich & dong goi Skill: {art['title'][:52]}...")
            agent_out = run_single_article_pipeline(aid, art["title"], art["content"], model=active_model)
            runs_cache[aid] = agent_out
            cache_path.write_text(json.dumps(runs_cache, indent=2, ensure_ascii=False), encoding="utf-8")

        pred_iocs = agent_out["extraction"]["iocs"]
        skill_pkg = agent_out["skill_package"]
        sc = skill_pkg["syntax_checks"]

        # 1. Table 1: IOC Metrics
        art_tp, art_fp, art_fn = 0, 0, 0
        for kind in ioc_types:
            k_key = type_key_map[kind]
            gt_set: Set[str] = {_norm_ioc(x, kind) for x in gt_data.get(k_key, []) if _norm_ioc(x, kind)}
            pr_set: Set[str] = {_norm_ioc(x, kind) for x in pred_iocs.get(k_key, []) if _norm_ioc(x, kind)}
            tp = len(gt_set & pr_set)
            fp = len(pr_set - gt_set)
            fn = len(gt_set - pr_set)
            metrics[kind]["gt"] += len(gt_set)
            metrics[kind]["pred"] += len(pr_set)
            metrics[kind]["tp"] += tp
            metrics[kind]["fp"] += fp
            metrics[kind]["fn"] += fn
            art_tp += tp
            art_fp += fp
            art_fn += fn
            total_predicted_iocs += len(pr_set)

        total_xai_grounded += len(agent_out["extraction"].get("xai_evidences", []))

        # 2. Table 2: Skill Structure & Syntax Validity
        syntax_stats["skill_md_total"] += 1
        if sc["raw_llm_skill_md_valid"]:
            syntax_stats["skill_md_raw_ok"] += 1
        if sc["final_skill_md_valid"]:
            syntax_stats["skill_md_final_ok"] += 1

        syntax_stats["manifest_total"] += 1
        if sc["raw_llm_manifest_valid"]:
            syntax_stats["manifest_raw_ok"] += 1
        if sc["final_manifest_valid"]:
            syntax_stats["manifest_final_ok"] += 1

        syntax_stats["script_total"] += 1
        if sc["raw_llm_script_valid"]:
            syntax_stats["script_raw_ok"] += 1
        if sc["final_script_valid"]:
            syntax_stats["script_final_ok"] += 1

        syntax_stats["ref_total"] += 1
        if sc["reference_indicators_valid"]:
            syntax_stats["ref_ok"] += 1

        # 3. Table 3: Skill Execution Detection Rate on Test Samples
        pos_logs, pos_buffers, pos_net_iocs = build_positive_samples_from_gt(gt_data)
        scan_fn = None
        if sc["final_script_valid"]:
            try:
                scan_fn = _load_skill_scan_fn(skill_pkg["verify_script_py"])
            except Exception:
                scan_fn = None

        if scan_fn is not None:
            if pos_logs:
                detection_stats["log_tested"] += 1
                try:
                    res = scan_fn(log_event=pos_logs[0])
                    if isinstance(res, dict) and res.get("detected"):
                        detection_stats["log_tp"] += 1
                    if any(bool((scan_fn(log_event=bl) or {}).get("detected")) for bl in BENIGN_LOGS):
                        detection_stats["log_fp_benign"] += 1
                except Exception:
                    pass

            if pos_buffers:
                detection_stats["buffer_tested"] += 1
                try:
                    res = scan_fn(payload_bytes=pos_buffers[0])
                    if isinstance(res, dict) and res.get("detected"):
                        detection_stats["buffer_tp"] += 1
                    if any(bool((scan_fn(payload_bytes=bb) or {}).get("detected")) for bb in BENIGN_BUFFERS):
                        detection_stats["buffer_fp_benign"] += 1
                except Exception:
                    pass

        if pos_net_iocs:
            detection_stats["network_tested"] += 1
            ref_set = {x.lower() for x in skill_pkg.get("reference_indicators", [])}
            if any(p.lower() in ref_set for p in pos_net_iocs):
                detection_stats["network_tp"] += 1
            if any(b.lower() in ref_set for b in BENIGN_TRAFFIC_FIXTURES):
                detection_stats["network_fp_benign"] += 1

        per_article_details.append({
            "index": art["index"],
            "article_id": aid,
            "skill_name": skill_pkg["skill_name"],
            "tp": art_tp, "fp": art_fp, "fn": art_fn,
            "skill_md_valid": sc["final_skill_md_valid"],
            "manifest_valid": sc["final_manifest_valid"],
            "script_valid": sc["final_script_valid"],
        })

    def _prf(tp: int, fp: int, fn: int) -> Tuple[float, float, float]:
        p = (tp / (tp + fp) * 100.0) if (tp + fp) > 0 else 0.0
        r = (tp / (tp + fn) * 100.0) if (tp + fn) > 0 else 0.0
        f1 = (2 * p * r / (p + r)) if (p + r) > 0 else 0.0
        return round(p, 2), round(r, 2), round(f1, 2)

    tot_gt = sum(m["gt"] for m in metrics.values())
    tot_pr = sum(m["pred"] for m in metrics.values())
    tot_tp = sum(m["tp"] for m in metrics.values())
    tot_fp = sum(m["fp"] for m in metrics.values())
    tot_fn = sum(m["fn"] for m in metrics.values())
    tot_p, tot_r, tot_f1 = _prf(tot_tp, tot_fp, tot_fn)

    md_lines = [
        f"# BAO CAO THUC NGHIEM CTI AI AGENT SINH AGENTIC SKILL ({len(annotated_articles)} BAN TIN GAN TAY)",
        f"- **Mo hinh cuc bo (Local LLM):** `{active_model}`",
        f"- **So ban tin doi chuan Ground Truth:** `{len(annotated_articles)}` bai bao CTI dau nam 2026",
        f"- **Ty le IOC co bang chung xAI Grounding nguyen van:** `{min(100.0, round(total_xai_grounded / max(total_predicted_iocs, 1) * 100, 2))}%`",
        "",
        "## BANG 1: DO DUNG KHI TRICH XUAT IOC (AGENT vs GROUND TRUTH GAN TAY)",
        "| Loai IOC | So luong GT | Agent trich | TP | FP | FN | Precision (%) | Recall (%) | F1-Score (%) |",
        "| :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: |",
    ]
    for kind in ioc_types:
        m = metrics[kind]
        p, r, f1 = _prf(m["tp"], m["fp"], m["fn"])
        md_lines.append(f"| {kind} | {m['gt']} | {m['pred']} | {m['tp']} | {m['fp']} | {m['fn']} | {p:.2f}% | {r:.2f}% | {f1:.2f}% |")
    md_lines.append(f"| **TONG HOP (Micro)** | **{tot_gt}** | **{tot_pr}** | **{tot_tp}** | **{tot_fp}** | **{tot_fn}** | **{tot_p:.2f}%** | **{tot_r:.2f}%** | **{tot_f1:.2f}%** |")

    md_t = max(syntax_stats["skill_md_total"], 1)
    mn_t = max(syntax_stats["manifest_total"], 1)
    sc_t = max(syntax_stats["script_total"], 1)
    rf_t = max(syntax_stats["ref_total"], 1)

    md_lines.extend([
        "",
        "## BANG 2: TY LE GOI SKILL HOP LE CAU TRUC & CU PHAP (SKILL VALIDITY RATE)",
        "| Thanh phan Skill | Cong cu kiem dinh | Tong so goi | Dung cu phap tho (LLM) | Hop le sau kiem dinh | Ty le hop le (%) |",
        "| :--- | :--- | :---: | :---: | :---: | :---: |",
        f"| `SKILL.md` | PyYAML Frontmatter + SOP | {syntax_stats['skill_md_total']} | {syntax_stats['skill_md_raw_ok']}/{md_t} ({syntax_stats['skill_md_raw_ok']/md_t*100:.1f}%) | {syntax_stats['skill_md_final_ok']}/{md_t} | **{syntax_stats['skill_md_final_ok']/md_t*100:.2f}%** |",
        f"| `manifest.json` | JSON Schema (`AGENTS.md`) | {syntax_stats['manifest_total']} | {syntax_stats['manifest_raw_ok']}/{mn_t} ({syntax_stats['manifest_raw_ok']/mn_t*100:.1f}%) | {syntax_stats['manifest_final_ok']}/{mn_t} | **{syntax_stats['manifest_final_ok']/mn_t*100:.2f}%** |",
        f"| `scripts/verify_threat.py` | Python AST `compile()` | {syntax_stats['script_total']} | {syntax_stats['script_raw_ok']}/{sc_t} ({syntax_stats['script_raw_ok']/sc_t*100:.1f}%) | {syntax_stats['script_final_ok']}/{sc_t} | **{syntax_stats['script_final_ok']/sc_t*100:.2f}%** |",
        f"| `references/c2_ip_indicators.txt` | IPv4/Domain + Whitelist Check | {syntax_stats['ref_total']} | {syntax_stats['ref_ok']}/{rf_t} | {syntax_stats['ref_ok']}/{rf_t} | **{syntax_stats['ref_ok']/rf_t*100:.2f}%** |",
    ])

    def _rate(tp_c: int, tot_c: int) -> str:
        return f"{tp_c/tot_c*100:.2f}%" if tot_c > 0 else "N/A"

    md_lines.extend([
        "",
        "## BANG 3: TY LE SKILL THUC THI BAT DUOC MAU THU (DETECTION & FALSE POSITIVE RATE)",
        "| Kenh kiem thu trong Skill | Co che thuc thi | So bo mau thu | Bat trung mau doc hai (TP) | Detection Rate (%) | Bao nham mau sach (FP) |",
        "| :--- | :--- | :---: | :---: | :---: | :---: |",
        f"| Log Telemetry Events | `scripts/verify_threat.py` (`scan_artifact(log_event)`) | {detection_stats['log_tested']} | {detection_stats['log_tp']}/{detection_stats['log_tested']} | **{_rate(detection_stats['log_tp'], detection_stats['log_tested'])}** | {detection_stats['log_fp_benign']}/{detection_stats['log_tested']} |",
        f"| Binary / Payload Buffer | `scripts/verify_threat.py` (`scan_artifact(payload_bytes)`) | {detection_stats['buffer_tested']} | {detection_stats['buffer_tp']}/{detection_stats['buffer_tested']} | **{_rate(detection_stats['buffer_tp'], detection_stats['buffer_tested'])}** | {detection_stats['buffer_fp_benign']}/{detection_stats['buffer_tested']} |",
        f"| Network C2 Indicators | `references/c2_ip_indicators.txt` vs Clean DNS/Domains | {detection_stats['network_tested']} | {detection_stats['network_tp']}/{detection_stats['network_tested']} | **{_rate(detection_stats['network_tp'], detection_stats['network_tested'])}** | {detection_stats['network_fp_benign']}/{detection_stats['network_tested']} |",
    ])

    report_text = "\n".join(md_lines)
    report_path = BENCH_DIR / "benchmark_report_50.md"
    report_path.write_text(report_text, encoding="utf-8")

    results_json = {
        "model": active_model,
        "evaluated_articles": len(annotated_articles),
        "table1_ioc_metrics": metrics,
        "table1_total": {"gt": tot_gt, "pred": tot_pr, "tp": tot_tp, "fp": tot_fp, "fn": tot_fn, "precision": tot_p, "recall": tot_r, "f1": tot_f1},
        "table2_skill_validity": syntax_stats,
        "table3_skill_detection": detection_stats,
        "per_article": per_article_details,
    }
    (BENCH_DIR / "benchmark_results_50.json").write_text(json.dumps(results_json, indent=2, ensure_ascii=False), encoding="utf-8")

    print("\n" + report_text)
    print(f"\n[+] Da xuat bao cao day du tai: {report_path}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Benchmark CTI Local AI Agent (Agentic Skill Pipeline) against Hand-Labeled Ground Truth.")
    parser.add_argument("--model", type=str, default="qwen3:8b", help="Ollama model name (e.g. qwen3:8b, khang-qwen3:latest, qwen2.5:7b)")
    parser.add_argument("--limit", type=int, default=50, help="Max annotated articles to evaluate")
    parser.add_argument("--rerun", action="store_true", help="Force re-run LLM inference ignoring cache")
    args = parser.parse_args()
    run_benchmark(model=args.model, limit=args.limit, force_rerun=args.rerun)
