# -*- coding: utf-8 -*-
"""
Cong cu ho tro doc va gan nhan thu cong (Manual Ground Truth Workbench)
va So sanh truc tiep Tay vs AI Agent (qwen3:8b) cho 50 ban tin CTI dau nam 2026.
Thiet ke dong bo 100% theo giao dien chinh (live_dashboard_app.py).

Chay: python cti_core/benchmark/labeler_server.py
Mo trinh duyet: http://127.0.0.1:8780
"""

import json
import os
import re
import sys
import threading
import time
from pathlib import Path
from typing import Any, Dict, List, Optional
from fastapi import FastAPI, HTTPException
from fastapi.responses import HTMLResponse
from pydantic import BaseModel
import uvicorn

BENCH_DIR = Path(__file__).resolve().parent
CORE_DIR = BENCH_DIR.parent
if str(CORE_DIR) not in sys.path:
    sys.path.insert(0, str(CORE_DIR))

from cti_local_agent_pipeline import ensure_ollama_running, refang, run_single_article_pipeline

ARTICLES_PATH = BENCH_DIR / "articles_50_2026.json"
GT_PATH = BENCH_DIR / "ground_truth_50.json"
DEFAULT_MODEL = "qwen3:8b"

app = FastAPI(title="CTI 50-Article Ground Truth & AI Comparison Workbench")

_cache_lock = threading.Lock()
_batch_lock = threading.Lock()
_batch_state: Dict[str, Any] = {
    "running": False,
    "stop_requested": False,
    "mode": "missing",
    "model": DEFAULT_MODEL,
    "phase": "idle",
    "total_articles": 0,
    "target_count": 0,
    "completed": 0,
    "skipped_cached": 0,
    "failed": 0,
    "current_index": None,
    "current_article_id": None,
    "current_title": "",
    "current_step": "",
    "current_started_at": None,
    "avg_article_sec": None,
    "recent_logs": [],
    "last_error": "",
    "started_at": None,
    "finished_at": None,
}


class SaveAnnotationRequest(BaseModel):
    article_id: str
    annotation_status: str = "done"
    ips: List[str] = []
    domains: List[str] = []
    urls: List[str] = []
    md5: List[str] = []
    sha256: List[str] = []
    cves: List[str] = []
    attack_behaviors: List[str] = []
    annotator_notes: str = ""


class CompareOneRequest(BaseModel):
    article_id: str
    model: str = DEFAULT_MODEL


class CompareAllRequest(BaseModel):
    model: str = DEFAULT_MODEL
    force_rerun: bool = False


def _load_json(path: Path, default: Any = None) -> Any:
    if not path.exists():
        return [] if default is None else default
    return json.loads(path.read_text(encoding="utf-8"))


def _write_json_atomic(path: Path, data: Any) -> None:
    tmp_path = path.with_suffix(path.suffix + ".tmp")
    tmp_path.write_text(json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8")
    os.replace(tmp_path, path)


def _norm_ioc(val: str, kind: str) -> str:
    s = refang(val).strip()
    if kind in ("domains", "md5", "sha256"):
        return s.lower()
    if kind == "cves":
        return s.upper()
    if kind == "urls":
        return s.rstrip("/")
    return s


def _compute_article_diff(gt: Dict[str, Any], pred: Dict[str, Any]) -> Dict[str, Any]:
    kinds = [("ips", "IP"), ("domains", "DOMAIN"), ("urls", "URL"), ("md5", "MD5"), ("sha256", "SHA256"), ("cves", "CVE")]
    tp_items, fp_items, fn_items = [], [], []
    for k, label in kinds:
        gt_set = {_norm_ioc(x, k) for x in (gt.get(k) or []) if str(x).strip()}
        pr_set = {_norm_ioc(x, k) for x in (pred.get(k) or []) if str(x).strip()}
        for x in sorted(gt_set & pr_set):
            tp_items.append({"type": label, "value": x})
        for x in sorted(pr_set - gt_set):
            fp_items.append({"type": label, "value": x})
        for x in sorted(gt_set - pr_set):
            fn_items.append({"type": label, "value": x})
    tp, fp, fn = len(tp_items), len(fp_items), len(fn_items)
    p = round(tp / (tp + fp) * 100, 1) if (tp + fp) > 0 else (100.0 if fn == 0 else 0.0)
    r = round(tp / (tp + fn) * 100, 1) if (tp + fn) > 0 else (100.0 if fp == 0 else 0.0)
    return {
        "tp_items": tp_items,
        "fp_items": fp_items,
        "fn_items": fn_items,
        "tp": tp,
        "fp": fp,
        "fn": fn,
        "precision": p,
        "recall": r,
    }


def _find_latest_run_cache(preferred_model: str = DEFAULT_MODEL) -> tuple[str, Path, Dict[str, Any]]:
    safe_tag = re.sub(r"[^a-zA-Z0-9._-]", "_", preferred_model)
    pref_path = BENCH_DIR / f"agent_skill_runs_{safe_tag}.json"
    if pref_path.exists():
        return preferred_model, pref_path, _load_json(pref_path, {})
    caches = sorted(BENCH_DIR.glob("agent_skill_runs_*.json"), key=lambda p: p.stat().st_mtime, reverse=True)
    if caches:
        data = _load_json(caches[0], {})
        model_name = caches[0].stem.replace("agent_skill_runs_", "").replace("_", ":", 1)
        return model_name, caches[0], data
    return preferred_model, pref_path, {}


@app.get("/api/data")
def get_all_data():
    articles = _load_json(ARTICLES_PATH, [])
    gt_list = _load_json(GT_PATH, [])
    gt_map = {item["article_id"]: item for item in gt_list}
    merged = []
    for art in articles:
        aid = art["article_id"]
        gt_item = gt_map.get(aid, {})
        content = art.get("content") or ""
        word_count = len(content.split())
        read_min = max(1, round(word_count / 200))
        hints = art.get("candidate_hints") or {}
        hint_count = sum(len(hints.get(k) or []) for k in ("ips", "domains", "urls", "md5s", "sha256s", "cves"))
        merged.append({
            **art,
            "word_count": word_count,
            "char_count": len(content),
            "read_minutes": read_min,
            "hint_count": hint_count,
            "annotation_status": gt_item.get("annotation_status", "pending"),
            "ground_truth": gt_item.get("ground_truth", {
                "ips": [], "domains": [], "urls": [], "md5": [], "sha256": [], "cves": [], "attack_behaviors": []
            }),
            "annotator_notes": gt_item.get("annotator_notes", ""),
        })
    return {"total": len(merged), "default_model": DEFAULT_MODEL, "items": merged}


@app.post("/api/save")
def save_annotation(req: SaveAnnotationRequest):
    gt_list = _load_json(GT_PATH, [])
    if not gt_list:
        raise HTTPException(status_code=404, detail="ground_truth_50.json not found")
    updated = False
    for item in gt_list:
        if item["article_id"] == req.article_id:
            item["annotation_status"] = req.annotation_status
            item["ground_truth"] = {
                "ips": [refang(x) for x in req.ips if x.strip()],
                "domains": [refang(x).lower() for x in req.domains if x.strip()],
                "urls": [refang(x) for x in req.urls if x.strip()],
                "md5": [x.strip().lower() for x in req.md5 if x.strip()],
                "sha256": [x.strip().lower() for x in req.sha256 if x.strip()],
                "cves": [x.strip().upper() for x in req.cves if x.strip()],
                "attack_behaviors": [x.strip() for x in req.attack_behaviors if x.strip()],
            }
            item["annotator_notes"] = req.annotator_notes.strip()
            updated = True
            break
    if not updated:
        raise HTTPException(status_code=404, detail="Article ID not found")
    GT_PATH.write_text(json.dumps(gt_list, indent=2, ensure_ascii=False), encoding="utf-8")
    done_count = sum(1 for x in gt_list if x.get("annotation_status") == "done")
    return {"ok": True, "done_count": done_count, "total": len(gt_list)}


@app.get("/api/comparison")
def get_comparison(model: str = DEFAULT_MODEL):
    articles = _load_json(ARTICLES_PATH, [])
    gt_list = _load_json(GT_PATH, [])
    gt_map = {item["article_id"]: item for item in gt_list}
    active_model, _, run_cache = _find_latest_run_cache(model)

    rows = []
    tot_tp = tot_fp = tot_fn = 0
    skill_valid_count = 0

    for art in articles:
        aid = art["article_id"]
        g_item = gt_map.get(aid, {})
        gt_data = g_item.get("ground_truth", {})
        is_done = g_item.get("annotation_status") == "done" or any(
            bool(gt_data.get(k)) for k in ("ips", "domains", "urls", "md5", "sha256", "cves")
        )
        ai_run = run_cache.get(aid)
        if not is_done and not ai_run:
            continue

        pred_iocs = (ai_run or {}).get("extraction", {}).get("iocs", {})
        diff = _compute_article_diff(gt_data, pred_iocs) if ai_run else None
        if is_done and diff:
            tot_tp += diff["tp"]
            tot_fp += diff["fp"]
            tot_fn += diff["fn"]

        sc = (ai_run or {}).get("skill_package", {}).get("syntax_checks", {})
        if ai_run and sc.get("final_skill_md_valid") and sc.get("final_manifest_valid") and sc.get("final_script_valid"):
            skill_valid_count += 1

        rows.append({
            "index": art["index"],
            "article_id": aid,
            "title": art["title"],
            "source_name": art["source_name"],
            "published_date": art["published_date"],
            "annotation_status": "done" if is_done else "pending",
            "ground_truth": gt_data,
            "has_ai_run": bool(ai_run),
            "ai_iocs": pred_iocs,
            "ai_behaviors": (ai_run or {}).get("extraction", {}).get("attack_behaviors", []),
            "ai_context_notes": (ai_run or {}).get("extraction", {}).get("context_notes", []),
            "ai_summary": (ai_run or {}).get("extraction", {}).get("summary", ""),
            "skill_name": (ai_run or {}).get("skill_package", {}).get("skill_name", ""),
            "skill_md": (ai_run or {}).get("skill_package", {}).get("skill_md", ""),
            "verify_script_py": (ai_run or {}).get("skill_package", {}).get("verify_script_py", ""),
            "syntax_checks": sc,
            "diff": diff,
        })

    p = round(tot_tp / (tot_tp + tot_fp) * 100, 2) if (tot_tp + tot_fp) > 0 else 0.0
    r = round(tot_tp / (tot_tp + tot_fn) * 100, 2) if (tot_tp + tot_fn) > 0 else 0.0
    f1 = round(2 * p * r / (p + r), 2) if (p + r) > 0 else 0.0
    compared_count = sum(1 for row in rows if row["annotation_status"] == "done" and row["has_ai_run"])

    return {
        "model": active_model,
        "compared_count": compared_count,
        "ai_cached_count": sum(1 for row in rows if row["has_ai_run"]),
        "summary": {
            "tp": tot_tp, "fp": tot_fp, "fn": tot_fn,
            "precision": p, "recall": r, "f1": f1,
            "skill_valid_count": skill_valid_count,
        },
        "rows": rows,
    }


@app.post("/api/compare_one")
def run_compare_one(req: CompareOneRequest):
    articles = _load_json(ARTICLES_PATH, [])
    art = next((a for a in articles if a["article_id"] == req.article_id), None)
    if not art:
        raise HTTPException(status_code=404, detail="Article ID not found")

    res = run_single_article_pipeline(
        article_id=art["article_id"],
        title=art["title"],
        content=art["content"],
        model=req.model,
        output_root=None,
    )
    active_model = res.get("model", req.model)
    safe_tag = re.sub(r"[^a-zA-Z0-9._-]", "_", active_model)
    cache_path = BENCH_DIR / f"agent_skill_runs_{safe_tag}.json"
    with _cache_lock:
        cache = _load_json(cache_path, {})
        cache[art["article_id"]] = res
        _write_json_atomic(cache_path, cache)

    gt_list = _load_json(GT_PATH, [])
    gt_item = next((g for g in gt_list if g["article_id"] == req.article_id), {})
    gt_data = gt_item.get("ground_truth", {})
    pred_iocs = res.get("extraction", {}).get("iocs", {})
    diff = _compute_article_diff(gt_data, pred_iocs)
    return {
        "ok": True,
        "model": active_model,
        "ai_iocs": pred_iocs,
        "ai_behaviors": res.get("extraction", {}).get("attack_behaviors", []),
        "ai_context_notes": res.get("extraction", {}).get("context_notes", []),
        "ai_summary": res.get("extraction", {}).get("summary", ""),
        "skill_name": res.get("skill_package", {}).get("skill_name", ""),
        "skill_md": res.get("skill_package", {}).get("skill_md", ""),
        "verify_script_py": res.get("skill_package", {}).get("verify_script_py", ""),
        "syntax_checks": res.get("skill_package", {}).get("syntax_checks", {}),
        "diff": diff,
    }


def _append_batch_log(msg: str) -> None:
    ts = time.strftime("%H:%M:%S")
    with _batch_lock:
        logs = list(_batch_state.get("recent_logs") or [])
        logs.append(f"[{ts}] {msg}")
        _batch_state["recent_logs"] = logs[-8:]


def _snapshot_batch_state(model: str = DEFAULT_MODEL) -> Dict[str, Any]:
    with _batch_lock:
        snap = dict(_batch_state)
        snap["recent_logs"] = list(_batch_state.get("recent_logs") or [])
    _, _, run_cache = _find_latest_run_cache(snap.get("model") or model)
    articles = _load_json(ARTICLES_PATH, [])
    snap["cached_count"] = len(run_cache)
    snap["articles_total"] = len(articles)
    snap["server_now"] = time.time()
    return snap


def _batch_worker(model: str, force_rerun: bool) -> None:
    try:
        with _batch_lock:
            _batch_state["current_step"] = f"Đang kiểm tra kết nối Ollama & nạp model {model}..."
        _append_batch_log(f"Kiểm tra Ollama ({model})...")
        ok, active_model_or_err = ensure_ollama_running(model)
        if not ok:
            with _batch_lock:
                _batch_state["phase"] = "error"
                _batch_state["last_error"] = str(active_model_or_err)
                _batch_state["running"] = False
                _batch_state["finished_at"] = time.time()
            _append_batch_log(f"Lỗi Ollama: {active_model_or_err}")
            return

        active_model = active_model_or_err
        safe_tag = re.sub(r"[^a-zA-Z0-9._-]", "_", active_model)
        cache_path = BENCH_DIR / f"agent_skill_runs_{safe_tag}.json"
        articles = _load_json(ARTICLES_PATH, [])

        with _cache_lock:
            existing_cache = _load_json(cache_path, {})

        if force_rerun:
            targets = list(articles)
            skipped_cached = 0
        else:
            targets = [a for a in articles if a["article_id"] not in existing_cache]
            skipped_cached = len(articles) - len(targets)

        with _batch_lock:
            _batch_state["model"] = active_model
            _batch_state["phase"] = "running" if targets else "completed"
            _batch_state["total_articles"] = len(articles)
            _batch_state["target_count"] = len(targets)
            _batch_state["skipped_cached"] = skipped_cached
            _batch_state["current_step"] = ""

        _append_batch_log(f"Bắt đầu phân tích {len(targets)} bài (đã bỏ qua {skipped_cached} bài có cache).")
        durations: List[float] = []

        for art in targets:
            with _batch_lock:
                if _batch_state["stop_requested"]:
                    _batch_state["phase"] = "stopped"
                    _append_batch_log("Đã dừng theo yêu cầu người dùng.")
                    break
                art_t0 = time.time()
                _batch_state["current_index"] = art.get("index")
                _batch_state["current_article_id"] = art.get("article_id")
                _batch_state["current_title"] = art.get("title", "")
                _batch_state["current_step"] = "Bước 1/2: Đang khởi chạy pipeline AI..."
                _batch_state["current_started_at"] = art_t0

            def _on_step(_stage: str, msg: str) -> None:
                with _batch_lock:
                    _batch_state["current_step"] = msg

            try:
                res = run_single_article_pipeline(
                    article_id=art["article_id"],
                    title=art["title"],
                    content=art["content"],
                    model=active_model,
                    output_root=None,
                    progress_callback=_on_step,
                )
                with _cache_lock:
                    cache = _load_json(cache_path, {})
                    cache[art["article_id"]] = res
                    _write_json_atomic(cache_path, cache)
                dt = round(time.time() - art_t0, 1)
                durations.append(dt)
                iocs = res.get("extraction", {}).get("iocs", {})
                ioc_total = sum(len(iocs.get(k) or []) for k in ("ips", "domains", "urls", "md5", "sha256", "cves"))
                with _batch_lock:
                    _batch_state["completed"] += 1
                    _batch_state["avg_article_sec"] = round(sum(durations) / len(durations), 1)
                _append_batch_log(f"Xong #{art.get('index'):02d} trong {dt}s ({ioc_total} IOCs, Skill OK).")
            except Exception as exc:
                with _batch_lock:
                    _batch_state["failed"] += 1
                    _batch_state["last_error"] = f"#{art.get('index')}: {exc}"
                _append_batch_log(f"Lỗi #{art.get('index'):02d}: {exc}")

        with _batch_lock:
            if _batch_state["phase"] == "running":
                _batch_state["phase"] = "stopped" if _batch_state["stop_requested"] else "completed"
    except Exception as exc:
        with _batch_lock:
            _batch_state["phase"] = "error"
            _batch_state["last_error"] = str(exc)
        _append_batch_log(f"Lỗi hệ thống: {exc}")
    finally:
        with _batch_lock:
            _batch_state["running"] = False
            _batch_state["stop_requested"] = False
            _batch_state["current_index"] = None
            _batch_state["current_article_id"] = None
            _batch_state["current_title"] = ""
            _batch_state["current_step"] = ""
            _batch_state["current_started_at"] = None
            _batch_state["finished_at"] = time.time()


@app.post("/api/compare_all")
def start_compare_all(req: CompareAllRequest):
    articles = _load_json(ARTICLES_PATH, [])
    with _batch_lock:
        if _batch_state["running"]:
            return {"ok": True, "already_running": True, "state": _snapshot_batch_state(req.model)}
        _batch_state.update({
            "running": True,
            "stop_requested": False,
            "mode": "all" if req.force_rerun else "missing",
            "model": req.model,
            "phase": "starting",
            "total_articles": len(articles),
            "target_count": len(articles) if req.force_rerun else 0,
            "completed": 0,
            "skipped_cached": 0,
            "failed": 0,
            "current_index": None,
            "current_article_id": None,
            "current_title": "",
            "current_step": f"Đang khởi động worker với {req.model}...",
            "current_started_at": time.time(),
            "avg_article_sec": None,
            "recent_logs": [],
            "last_error": "",
            "started_at": time.time(),
            "finished_at": None,
        })

    t = threading.Thread(target=_batch_worker, args=(req.model, req.force_rerun), daemon=True)
    t.start()
    return {"ok": True, "already_running": False, "state": _snapshot_batch_state(req.model)}


@app.get("/api/compare_all/status")
def get_compare_all_status(model: str = DEFAULT_MODEL):
    return {"ok": True, "state": _snapshot_batch_state(model)}


@app.post("/api/compare_all/stop")
def stop_compare_all():
    with _batch_lock:
        if _batch_state["running"]:
            _batch_state["stop_requested"] = True
        snap = dict(_batch_state)
    return {"ok": True, "state": snap}


HTML_UI = r"""<!DOCTYPE html>
<html lang="vi">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0" />
  <title>CTI DEFENSE AGENT — GROUND TRUTH &amp; AI BENCHMARK</title>
  <link rel="preconnect" href="https://fonts.googleapis.com">
  <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
  <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&family=JetBrains+Mono:wght@400;500;600&display=swap" rel="stylesheet">
  <style>
    :root {
      --bg-page: #f8fafc;
      --bg-card: #ffffff;
      --bg-subtle: #f1f5f9;
      --bg-input: #ffffff;
      --border-main: #e2e8f0;
      --border-dark: #cbd5e1;
      --border-focus: #3b82f6;
      --text-main: #0f172a;
      --text-muted: #64748b;
      --primary: #2563eb;
      --primary-hover: #1d4ed8;
      --primary-subtle: #eff6ff;
      --amber: #b45309;
      --amber-bg: #fffbeb;
      --amber-border: #fcd34d;
      --danger: #b91c1c;
      --danger-bg: #fef2f2;
      --danger-border: #fca5a5;
      --safe: #15803d;
      --safe-bg: #f0fdf4;
      --safe-border: #86efac;
    }

    * { box-sizing: border-box; margin: 0; padding: 0; }

    body {
      background-color: var(--bg-page);
      color: var(--text-main);
      font-family: 'Inter', system-ui, -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
      font-size: 14px;
      line-height: 1.5;
      min-height: 100vh;
      -webkit-font-smoothing: antialiased;
    }

    code, pre, .mono { font-family: 'JetBrains Mono', Consolas, monospace; }

    ::-webkit-scrollbar { width: 6px; height: 6px; }
    ::-webkit-scrollbar-track { background: var(--bg-page); }
    ::-webkit-scrollbar-thumb { background: #cbd5e1; border-radius: 3px; }
    ::-webkit-scrollbar-thumb:hover { background: #94a3b8; }

    /* TOP NAVBAR (Dong bo 100% live_dashboard_app.py) */
    .TopNav {
      display: flex;
      justify-content: space-between;
      align-items: center;
      padding: 12px 28px;
      border-bottom: 1px solid var(--border-main);
      background: #ffffff;
      position: sticky;
      top: 0;
      z-index: 100;
      flex-wrap: wrap;
      gap: 14px;
      box-shadow: 0 1px 2px 0 rgba(0, 0, 0, 0.04);
    }
    .NavBrand {
      display: flex;
      align-items: center;
      gap: 10px;
      font-size: 17px;
      font-weight: 700;
      color: var(--text-main);
      letter-spacing: -0.01em;
    }
    .NavBrandTag {
      font-size: 11px;
      font-weight: 600;
      padding: 2px 8px;
      background: var(--primary-subtle);
      color: var(--primary);
      border: 1px solid #bfdbfe;
      border-radius: 4px;
      letter-spacing: 0.04em;
      text-transform: uppercase;
    }
    .NavLinks { display: flex; align-items: center; gap: 6px; flex-wrap: wrap; }
    .NavLink {
      background: transparent;
      color: var(--text-muted);
      border: 1px solid transparent;
      padding: 6px 14px;
      font-size: 13.5px;
      font-weight: 500;
      cursor: pointer;
      border-radius: 6px;
      transition: all 0.15s ease;
    }
    .NavLink:hover { color: var(--text-main); background: var(--bg-subtle); }
    .NavLink.active {
      color: #ffffff !important;
      background: #2563eb !important;
      border: 1px solid #1d4ed8 !important;
      font-weight: 700 !important;
    }
    .NavRight { display: flex; align-items: center; gap: 10px; flex-wrap: wrap; }

    .MainWrap {
      max-width: 1340px;
      margin: 20px auto 48px;
      padding: 0 22px;
    }

    .StatusStrip {
      display: flex;
      justify-content: space-between;
      align-items: center;
      padding: 10px 16px;
      margin-bottom: 20px;
      border: 1px solid var(--border-main);
      background: #ffffff;
      border-radius: 8px;
      font-size: 13px;
      color: var(--text-muted);
      box-shadow: 0 1px 2px rgba(0, 0, 0, 0.04);
      flex-wrap: wrap;
      gap: 10px;
    }

    .CleanSelect, .CleanInput {
      background: var(--bg-input);
      color: var(--text-main);
      border: 1px solid var(--border-dark);
      padding: 7px 11px;
      font-size: 13px;
      border-radius: 6px;
      outline: none;
      transition: border-color 0.15s ease, box-shadow 0.15s ease;
    }
    .CleanSelect:focus, .CleanInput:focus {
      border-color: var(--border-focus);
      box-shadow: 0 0 0 3px rgba(59, 130, 246, 0.15);
    }

    .CleanBtn {
      background: #ffffff;
      color: var(--text-main);
      border: 1px solid var(--border-dark);
      padding: 7px 14px;
      font-size: 13px;
      font-weight: 600;
      border-radius: 6px;
      cursor: pointer;
      transition: all 0.15s ease;
      text-decoration: none;
      display: inline-flex;
      align-items: center;
      justify-content: center;
      gap: 6px;
      box-shadow: 0 1px 2px rgba(0, 0, 0, 0.04);
    }
    .CleanBtn:hover { background: var(--bg-subtle); border-color: #94a3b8; }
    .CleanBtn.active { background: var(--primary); color: #ffffff; border-color: var(--primary); }
    .CleanBtn.btn-primary { background: var(--primary); color: #ffffff; border-color: var(--primary); }
    .CleanBtn.btn-primary:hover { background: var(--primary-hover); }
    .CleanBtn.btn-safe { background: var(--safe); color: #ffffff; border-color: var(--safe); }
    .CleanBtn.btn-safe:hover { background: #166534; }
    .CleanBtn.btn-danger { background: var(--danger); color: #ffffff; border-color: var(--danger); }
    .CleanBtn.btn-danger:hover { background: #991b1b; }
    .CleanBtn:disabled { opacity: 0.55; cursor: wait; }

    .BatchProgressCard {
      display: none;
      background: #ffffff;
      border: 1px solid #bfdbfe;
      border-radius: 8px;
      padding: 14px 16px;
      margin-bottom: 18px;
      box-shadow: 0 1px 3px rgba(37, 99, 235, 0.08);
    }
    .ProgressTrack {
      width: 100%;
      height: 10px;
      background: var(--bg-subtle);
      border: 1px solid var(--border-main);
      border-radius: 999px;
      overflow: hidden;
      margin: 10px 0 6px;
    }
    .ProgressFill {
      height: 100%;
      width: 0%;
      background: linear-gradient(90deg, var(--primary), var(--safe));
      transition: width 0.3s ease;
    }
    .ProgressFill.is-active {
      background: linear-gradient(90deg, #2563eb 0%, #60a5fa 50%, #16a34a 100%);
      background-size: 200% 100%;
      animation: barFlow 1.6s linear infinite;
    }
    @keyframes barFlow {
      0% { background-position: 200% 0; }
      100% { background-position: -200% 0; }
    }
    .Spinner {
      display: inline-block;
      width: 13px;
      height: 13px;
      border: 2px solid #93c5fd;
      border-top-color: #2563eb;
      border-radius: 50%;
      animation: spin 0.75s linear infinite;
      vertical-align: -2px;
      flex-shrink: 0;
    }
    @keyframes spin {
      to { transform: rotate(360deg); }
    }
    .BadgeRunning {
      display: inline-flex;
      align-items: center;
      gap: 6px;
      background: #eff6ff;
      color: #1d4ed8;
      border: 1px solid #93c5fd;
      padding: 3px 10px;
      border-radius: 5px;
      font-size: 12px;
      font-weight: 600;
    }
    tr.RowActive td {
      background: #eff6ff !important;
      border-top: 1px solid #bfdbfe;
      border-bottom: 1px solid #bfdbfe;
    }
    .BatchLogsBox {
      margin-top: 8px;
      padding: 8px 10px;
      background: #f8fafc;
      border: 1px solid var(--border-main);
      border-radius: 6px;
      font-family: 'JetBrains Mono', monospace;
      font-size: 11.5px;
      color: #334155;
      max-height: 92px;
      overflow-y: auto;
      line-height: 1.5;
    }

    .CyberBox {
      position: relative;
      background: #ffffff;
      border: 1px solid var(--border-main);
      border-radius: 8px;
      box-shadow: 0 1px 3px rgba(0, 0, 0, 0.05), 0 1px 2px rgba(0, 0, 0, 0.03);
      padding: 24px 22px 20px;
      margin-bottom: 22px;
    }
    .BoxLegend {
      position: absolute;
      top: -12px;
      left: 18px;
      background: #ffffff;
      padding: 0 10px;
      color: var(--text-main);
      font-size: 12.5px;
      font-weight: 700;
      text-transform: uppercase;
      letter-spacing: 0.04em;
      border: 1px solid var(--border-main);
      border-radius: 4px;
    }

    .FieldLabel {
      display: flex;
      justify-content: space-between;
      align-items: center;
      font-size: 11.5px;
      font-weight: 600;
      color: var(--text-muted);
      text-transform: uppercase;
      letter-spacing: 0.04em;
      margin-bottom: 5px;
    }
    .CountBadge {
      font-family: 'JetBrains Mono', monospace;
      font-size: 11px;
      font-weight: 600;
      padding: 1px 7px;
      border-radius: 999px;
      background: var(--bg-subtle);
      color: var(--text-muted);
      border: 1px solid var(--border-main);
    }
    .CountBadge.has-val {
      background: var(--primary-subtle);
      color: var(--primary);
      border-color: #bfdbfe;
    }

    .BadgePending {
      background: #fef3c7;
      color: #b45309;
      border: 1px solid #fde68a;
      padding: 2px 9px;
      border-radius: 4px;
      font-size: 11.5px;
      font-weight: 600;
    }
    .BadgeCompleted {
      background: #dcfce7;
      color: #15803d;
      border: 1px solid #86efac;
      padding: 2px 9px;
      border-radius: 4px;
      font-size: 11.5px;
      font-weight: 600;
    }

    .WorkspaceGrid {
      display: grid;
      grid-template-columns: 1.35fr 1fr;
      gap: 20px;
      align-items: start;
    }
    @media (max-width: 1024px) {
      .WorkspaceGrid { grid-template-columns: 1fr; }
    }

    .ArticleHeaderCard {
      background: var(--bg-subtle);
      border: 1px solid var(--border-main);
      border-radius: 6px;
      padding: 14px 16px;
      margin-bottom: 14px;
    }
    .ArticleTitle {
      font-size: 19px;
      font-weight: 700;
      color: var(--text-main);
      line-height: 1.35;
      margin-bottom: 10px;
    }
    .MetaPills {
      display: flex;
      flex-wrap: wrap;
      gap: 8px;
      align-items: center;
      font-size: 12px;
      color: var(--text-muted);
    }
    .MetaPill {
      background: #ffffff;
      border: 1px solid var(--border-main);
      padding: 3px 9px;
      border-radius: 5px;
      display: inline-flex;
      align-items: center;
      gap: 5px;
    }
    .MetaPill b { color: var(--text-main); }

    .LegendBar {
      display: flex;
      flex-wrap: wrap;
      align-items: center;
      gap: 8px;
      padding: 8px 12px;
      margin-bottom: 12px;
      background: #f8fafc;
      border: 1px dashed var(--border-dark);
      border-radius: 6px;
      font-size: 12px;
      color: var(--text-muted);
    }

    .ReaderContent {
      font-size: 14.5px;
      line-height: 1.75;
      color: #1e293b;
      user-select: text;
      max-height: 72vh;
      overflow-y: auto;
      padding-right: 8px;
      word-break: break-word;
    }
    .ReaderContent p { margin: 0 0 12px 0; }
    .ReaderContent h1, .ReaderContent h2, .ReaderContent h3, .ReaderContent h4 {
      color: var(--text-main);
      margin: 18px 0 8px 0;
      line-height: 1.35;
      font-weight: 700;
    }
    .ReaderContent h2 { font-size: 17px; border-bottom: 1px solid var(--border-main); padding-bottom: 4px; }
    .ReaderContent h3 { font-size: 15.5px; }
    .ReaderContent ul, .ReaderContent ol { margin: 8px 0 14px 22px; }
    .ReaderContent li { margin-bottom: 5px; }
    .ReaderContent img {
      max-width: 100%;
      height: auto;
      display: block;
      margin: 12px auto;
      border-radius: 6px;
      border: 1px solid var(--border-main);
      background: #ffffff;
      box-shadow: 0 1px 3px rgba(0, 0, 0, 0.06);
    }
    .ReaderContent pre {
      background: #f8fafc;
      border: 1px solid var(--border-main);
      border-radius: 6px;
      padding: 10px 12px;
      font-family: 'JetBrains Mono', monospace;
      font-size: 12.5px;
      overflow-x: auto;
      margin: 10px 0 14px 0;
      white-space: pre-wrap;
    }
    .ReaderContent code {
      font-family: 'JetBrains Mono', monospace;
      font-size: 12.5px;
      background: var(--bg-subtle);
      padding: 1px 5px;
      border-radius: 4px;
    }
    .ReaderContent blockquote {
      margin: 10px 0 14px 0;
      padding: 8px 14px;
      border-left: 3px solid var(--primary);
      background: var(--bg-subtle);
      border-radius: 0 6px 6px 0;
      color: #334155;
    }
    .ReaderContent table {
      width: 100%;
      border-collapse: collapse;
      margin: 12px 0;
      font-size: 12.5px;
    }
    .ReaderContent th, .ReaderContent td {
      border: 1px solid var(--border-main);
      padding: 6px 8px;
      text-align: left;
    }

    .HlIp1, .HlDom, .HlHash, .HlCve {
      padding: 1px 6px;
      font-family: 'JetBrains Mono', monospace;
      font-size: 12.5px;
      font-weight: 600;
      border-radius: 4px;
      cursor: pointer;
      transition: transform 0.1s ease, box-shadow 0.15s ease;
    }
    .HlIp1:hover, .HlDom:hover, .HlHash:hover, .HlCve:hover {
      box-shadow: 0 0 0 2px rgba(37, 99, 235, 0.35);
    }
    .HlIp1 { background: var(--danger-bg); color: var(--danger); border: 1px solid var(--danger-border); }
    .HlDom { background: var(--primary-subtle); color: var(--primary); border: 1px solid #bfdbfe; }
    .HlHash { background: #f5f3ff; color: #7c3aed; border: 1px solid #ddd6fe; }
    .HlCve { background: var(--amber-bg); color: var(--amber); border: 1px solid var(--amber-border); }

    .FormStack { display: flex; flex-direction: column; gap: 12px; }
    .FormStack textarea {
      width: 100%;
      font-family: 'JetBrains Mono', monospace;
      font-size: 12.5px;
      line-height: 1.5;
      resize: vertical;
    }

    .IocChip {
      display: inline-block;
      max-width: 100%;
      padding: 2px 8px;
      margin: 2px 4px 2px 0;
      font-size: 11.5px;
      font-family: 'JetBrains Mono', monospace;
      border-radius: 4px;
      border: 1px solid var(--border-dark);
      background: #ffffff;
      white-space: normal;
      overflow-wrap: anywhere;
      word-break: break-word;
    }
    .IocChip.tp { background: var(--safe-bg); color: var(--safe); border-color: var(--safe-border); }
    .IocChip.fp { background: var(--danger-bg); color: var(--danger); border-color: var(--danger-border); }
    .IocChip.fn { background: var(--amber-bg); color: var(--amber); border-color: var(--amber-border); }
    .IocChipList {
      max-height: 190px;
      overflow-y: auto;
      padding-right: 4px;
    }

    .HistoryStatsGrid {
      display: grid;
      grid-template-columns: repeat(5, 1fr);
      gap: 12px;
      margin-bottom: 18px;
    }
    @media (max-width: 960px) { .HistoryStatsGrid { grid-template-columns: repeat(2, 1fr); } }
    .HistoryStatCard {
      background: #ffffff;
      border: 1px solid var(--border-main);
      border-radius: 8px;
      padding: 13px 15px;
      box-shadow: 0 1px 2px rgba(0, 0, 0, 0.03);
    }
    .HistoryStatLabel { font-size: 11px; font-weight: 600; text-transform: uppercase; color: var(--text-muted); margin-bottom: 4px; }
    .HistoryStatValue { font-size: 20px; font-weight: 700; color: var(--text-main); }
    .HistoryStatSub { font-size: 11.5px; color: var(--text-muted); margin-top: 2px; }

    .CompareBox {
      margin-top: 14px;
      padding: 12px 14px;
      background: var(--bg-subtle);
      border: 1px solid var(--border-main);
      border-radius: 6px;
    }

    .TableWrap {
      overflow-x: auto;
      border: 1px solid var(--border-main);
      border-radius: 6px;
      background: #ffffff;
    }
    table { width: 100%; border-collapse: collapse; font-size: 13px; }
    .TableWrap table { table-layout: fixed; }
    th {
      background: #f8fafc;
      color: var(--text-muted);
      font-size: 11.5px;
      font-weight: 600;
      text-transform: uppercase;
      letter-spacing: 0.04em;
      padding: 10px 12px;
      text-align: left;
      border-bottom: 1px solid var(--border-main);
      overflow-wrap: anywhere;
    }
    td { padding: 10px 12px; border-bottom: 1px solid var(--border-main); vertical-align: top; overflow-wrap: anywhere; word-break: break-word; }
    tr:hover td { background: #f8fafc; }

    .ToastBanner {
      position: fixed;
      bottom: 20px;
      right: 24px;
      background: #0f172a;
      color: #ffffff;
      padding: 10px 16px;
      border-radius: 8px;
      font-size: 13px;
      font-weight: 500;
      box-shadow: 0 10px 25px rgba(15, 23, 42, 0.2);
      z-index: 999;
      display: none;
    }
  </style>
</head>
<body>

  <!-- TOP NAVBAR -->
  <nav class="TopNav">
    <div class="NavBrand">
      <span>CTI DEFENSE AGENT</span>
      <span class="NavBrandTag">GROUND TRUTH 2026</span>
    </div>

    <div class="NavLinks">
      <button class="NavLink active" id="tabBtnLabel" onclick="switchTab('label')">1. Gán Nhãn Từng Bài</button>
      <button class="NavLink" id="tabBtnCompare" onclick="switchTab('compare')">2. So Sánh Tay vs AI Agent</button>
    </div>

    <div class="NavRight">
      <span class="BadgeCompleted" id="progressPill" style="font-size:12.5px; padding:5px 12px;">0 / 50 đã gán</span>
      <span class="MetaPill" style="font-size:12px;">Model chuẩn: <b class="mono" id="defaultModelLabel">qwen3:8b</b></span>
    </div>
  </nav>

  <div class="MainWrap">

    <!-- VIEW 1: GAN NHAN TUNG BAI -->
    <div id="viewLabel">
      <!-- THANH DIEU HUONG TUNG BAI (KHONG DUNG SIDEBAR ROI MAT) -->
      <div class="StatusStrip">
        <div style="display:flex; align-items:center; gap:8px; flex-wrap:wrap;">
          <button class="CleanBtn active" data-filter="all" onclick="setFilter('all', this)">Tất cả (<span id="cntAll">50</span>)</button>
          <button class="CleanBtn" data-filter="pending" onclick="setFilter('pending', this)">Chưa gán (<span id="cntPend">50</span>)</button>
          <button class="CleanBtn" data-filter="done" onclick="setFilter('done', this)">Đã gán (<span id="cntDone">0</span>)</button>
        </div>

        <div style="display:flex; align-items:center; gap:8px; flex:1; justify-content:flex-end; flex-wrap:wrap;">
          <button class="CleanBtn" onclick="stepArticle(-1)">&larr; Bài trước</button>
          <select id="articleSelect" class="CleanSelect" style="min-width:340px; max-width:520px; font-weight:500;" onchange="selectArticle(this.value)"></select>
          <button class="CleanBtn" onclick="stepArticle(1)">Bài tiếp &rarr;</button>
          <button class="CleanBtn" style="color:var(--primary); border-color:#bfdbfe; background:var(--primary-subtle);" onclick="jumpNextPending()">Tới bài chưa gán</button>
        </div>
      </div>

      <div class="WorkspaceGrid">
        <!-- COT TRAI: BAI BAO CTI -->
        <section class="CyberBox">
          <div class="BoxLegend">1. NỘI DUNG BÀI BÁO CTI</div>
          <div id="readerHeaderArea" class="ArticleHeaderCard">
            <div style="color:var(--text-muted)">Đang tải dữ liệu 50 bài báo...</div>
          </div>
          <div class="LegendBar" style="justify-content:space-between;">
            <label style="display:inline-flex; align-items:center; gap:7px; cursor:pointer; color:var(--text-main); font-weight:500;">
              <input type="checkbox" id="toggleHighlight" onchange="rerenderArticleBody()" />
              <span>Bật tô màu hỗ trợ click-copy (Mặc định tắt để tự đọc khách quan)</span>
            </label>
            <div id="highlightLegendChips" style="display:none; gap:6px; align-items:center; flex-wrap:wrap;">
              <span class="HlIp1" style="cursor:default;">IP</span>
              <span class="HlDom" style="cursor:default;">Domain/URL</span>
              <span class="HlHash" style="cursor:default;">Hash</span>
              <span class="HlCve" style="cursor:default;">CVE</span>
            </div>
          </div>
          <div id="readerBodyArea" class="ReaderContent"></div>
        </section>

        <!-- COT PHAI: PHIEU GHI NHAN PHAT HIEN -->
        <section class="CyberBox">
          <div class="BoxLegend">2. GHI NHẬN PHÁT HIỆN (ĐÁP ÁN TAY)</div>

          <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:14px; gap:8px; flex-wrap:wrap;">
            <span id="statusBadge" class="BadgePending">Chưa gán</span>
            <button class="CleanBtn" style="padding:5px 10px; font-size:12px; color:var(--danger);" onclick="clearFields()">Xóa trắng ô nhập</button>
          </div>

          <div class="FormStack">
            <div>
              <label class="FieldLabel"><span>IPs Độc Hại / C2 (mỗi dòng 1 IP)</span><span class="CountBadge" id="cnt_ips">0</span></label>
              <textarea id="f_ips" class="CleanInput" rows="2" placeholder="VD: 194.46.59.169" oninput="refreshFieldCounts()"></textarea>
            </div>
            <div>
              <label class="FieldLabel"><span>Domains C2 / Độc Hại (bỏ tên miền sạch)</span><span class="CountBadge" id="cnt_domains">0</span></label>
              <textarea id="f_domains" class="CleanInput" rows="2" placeholder="VD: evil-c2.su" oninput="refreshFieldCounts()"></textarea>
            </div>
            <div>
              <label class="FieldLabel"><span>URLs Phát Tán Mã Độc / Payload</span><span class="CountBadge" id="cnt_urls">0</span></label>
              <textarea id="f_urls" class="CleanInput" rows="2" placeholder="VD: http://45.144.165.65/loader.exe" oninput="refreshFieldCounts()"></textarea>
            </div>
            <div style="display:grid; grid-template-columns:1fr 1fr; gap:10px;">
              <div>
                <label class="FieldLabel"><span>MD5 Hashes</span><span class="CountBadge" id="cnt_md5">0</span></label>
                <textarea id="f_md5" class="CleanInput" rows="2" oninput="refreshFieldCounts()"></textarea>
              </div>
              <div>
                <label class="FieldLabel"><span>CVEs Khai Thác</span><span class="CountBadge" id="cnt_cves">0</span></label>
                <textarea id="f_cves" class="CleanInput" rows="2" placeholder="CVE-2026-..." oninput="refreshFieldCounts()"></textarea>
              </div>
            </div>
            <div>
              <label class="FieldLabel"><span>SHA256 Hashes</span><span class="CountBadge" id="cnt_sha256">0</span></label>
              <textarea id="f_sha256" class="CleanInput" rows="2" oninput="refreshFieldCounts()"></textarea>
            </div>
            <div>
              <label class="FieldLabel"><span>Hành Vi Tấn Công / Dấu Hiệu Phát Hiện</span><span class="CountBadge" id="cnt_behaviors">0</span></label>
              <textarea id="f_behaviors" class="CleanInput" rows="2" placeholder="VD: powershell -enc, ADB port 5555 scan, curl payload..." oninput="refreshFieldCounts()"></textarea>
            </div>
            <div>
              <label class="FieldLabel"><span>Ghi Chú Của Bạn</span></label>
              <input id="f_notes" class="CleanInput" type="text" style="width:100%;" placeholder="Nhận xét thêm về bài báo hoặc ngữ cảnh IOC..." />
            </div>

            <div style="display:flex; gap:8px; margin-top:4px; flex-wrap:wrap;">
              <button class="CleanBtn btn-primary" style="flex:1;" onclick="saveCurrent(true)">Lưu &amp; Sang Bài Tiếp</button>
              <button class="CleanBtn btn-safe" onclick="saveCurrent(false)">Lưu bài này</button>
            </div>

            <button class="CleanBtn" id="btnQuickAi" style="width:100%; border-color:#93c5fd; color:var(--primary); background:var(--primary-subtle);" onclick="runQuickCompareOne()">
              Lưu &amp; Chạy AI (qwen3:8b) So Sánh Bài Này Ngay
            </button>

            <div id="inlineCompareBox" class="CompareBox" style="display:none;"></div>
          </div>
        </section>
      </div>
    </div>

    <!-- VIEW 2: SO SANH TAY VS AI AGENT -->
    <div id="viewCompare" style="display:none;">
      <div class="StatusStrip">
        <div>
          <b>Đối Chiếu Ground Truth Tay vs Local AI Agent (<span id="cmpModelName" class="mono">qwen3:8b</span>)</b>
          <span style="margin:0 8px;">&bull;</span>
          <span>Chạy tuần tự từng bài và tự động lưu cache vào <code class="mono">agent_skill_runs_*.json</code></span>
        </div>
        <div style="display:flex; align-items:center; gap:8px; flex-wrap:wrap;">
          <button class="CleanBtn btn-safe" id="btnRunAllMissing" onclick="startCompareAll(false)">Phân Tích All Bài (Còn Thiếu)</button>
          <button class="CleanBtn" id="btnRunAllForce" onclick="startCompareAll(true)">Chạy Lại Toàn Bộ (50 Bài)</button>
          <button class="CleanBtn btn-danger" id="btnStopAll" style="display:none;" onclick="stopCompareAll()">Dừng Sau Bài Này</button>
          <button class="CleanBtn btn-primary" onclick="loadComparison()">Làm mới kết quả</button>
        </div>
      </div>

      <div id="batchProgressPanel" class="BatchProgressCard">
        <div style="display:flex; justify-content:space-between; align-items:center; gap:10px; flex-wrap:wrap;">
          <div id="batchStatusText" style="font-weight:600; color:var(--text-main); display:flex; align-items:center; gap:8px;">Đang chuẩn bị...</div>
          <div id="batchCountsText" class="mono" style="font-size:12px; color:var(--text-muted);">0 / 50</div>
        </div>
        <div id="batchStepText" style="font-size:12.5px; color:var(--primary); font-weight:500; margin-top:4px; display:none;"></div>
        <div class="ProgressTrack"><div id="batchProgressFill" class="ProgressFill"></div></div>
        <div id="batchSubText" style="font-size:12px; color:var(--text-muted);"></div>
        <div id="batchLogsBox" class="BatchLogsBox" style="display:none;"></div>
      </div>

      <div class="HistoryStatsGrid">
        <div class="HistoryStatCard">
          <div class="HistoryStatLabel">Bài Đã Đối Chiếu</div>
          <div class="HistoryStatValue" id="cmpCount">0</div>
          <div class="HistoryStatSub">Bài đã gán &amp; có kết quả AI</div>
        </div>
        <div class="HistoryStatCard">
          <div class="HistoryStatLabel">Precision (Độ Chính Xác)</div>
          <div class="HistoryStatValue" style="color:var(--primary);" id="cmpPrec">0%</div>
          <div class="HistoryStatSub">TP / (TP + FP)</div>
        </div>
        <div class="HistoryStatCard">
          <div class="HistoryStatLabel">Recall (Độ Phủ IOC)</div>
          <div class="HistoryStatValue" style="color:var(--safe);" id="cmpRec">0%</div>
          <div class="HistoryStatSub">TP / (TP + FN)</div>
        </div>
        <div class="HistoryStatCard">
          <div class="HistoryStatLabel">F1-Score Tổng Hợp</div>
          <div class="HistoryStatValue" id="cmpF1">0%</div>
          <div class="HistoryStatSub" id="cmpCountsSub">TP: 0 | FP: 0 | FN: 0</div>
        </div>
        <div class="HistoryStatCard">
          <div class="HistoryStatLabel">Gói Skill Hợp Lệ</div>
          <div class="HistoryStatValue" style="color:var(--safe);" id="cmpSkillValid">0</div>
          <div class="HistoryStatSub">SKILL.md + manifest + verify_threat.py</div>
        </div>
      </div>

      <section class="CyberBox">
        <div class="BoxLegend">BẢNG ĐỐI CHIẾU CHI TIẾT TỪNG BÀI BÁO</div>
        <div class="TableWrap">
          <table>
            <thead>
              <tr>
                <th style="width:24%;">Bài Báo CTI</th>
                <th style="width:28%;">Khớp Chuẩn (TP) &amp; Sót (FN)</th>
                <th style="width:24%;">AI Bịa / Dư (FP)</th>
                <th style="width:24%;">Gói Agentic Skill AI Sinh</th>
              </tr>
            </thead>
            <tbody id="cmpTableBody">
              <tr><td colspan="4" style="text-align:center; color:var(--text-muted); padding:24px;">Đang tải dữ liệu so sánh...</td></tr>
            </tbody>
          </table>
        </div>
      </section>
    </div>

  </div>

  <div class="ToastBanner" id="toastBanner"></div>

<script>
let items = [];
let currentFilter = 'all';
let currentId = null;
let defaultModel = 'qwen3:8b';

function showToast(msg) {
  const t = document.getElementById('toastBanner');
  t.textContent = msg;
  t.style.display = 'block';
  clearTimeout(window.__toastTimer);
  window.__toastTimer = setTimeout(() => { t.style.display = 'none'; }, 2600);
}

function escapeHtml(s) {
  return (s || '').replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
}

async function init() {
  const res = await fetch('/api/data');
  const data = await res.json();
  items = data.items || [];
  defaultModel = data.default_model || 'qwen3:8b';
  document.getElementById('defaultModelLabel').textContent = defaultModel;
  updateProgress();
  renderDropdown();
  if (items.length > 0) {
    const firstPending = items.find(x => x.annotation_status !== 'done') || items[0];
    selectArticle(firstPending.article_id);
  }
  pollBatchStatus(true);
}

function updateProgress() {
  const done = items.filter(x => x.annotation_status === 'done').length;
  const pend = items.length - done;
  document.getElementById('progressPill').textContent = `${done} / ${items.length} đã gán`;
  document.getElementById('cntAll').textContent = items.length;
  document.getElementById('cntPend').textContent = pend;
  document.getElementById('cntDone').textContent = done;
}

function getFilteredItems() {
  if (currentFilter === 'all') return items;
  return items.filter(x => currentFilter === 'done' ? x.annotation_status === 'done' : x.annotation_status !== 'done');
}

function setFilter(f, btn) {
  currentFilter = f;
  document.querySelectorAll('[data-filter]').forEach(b => b.classList.remove('active'));
  btn.classList.add('active');
  renderDropdown();
  const list = getFilteredItems();
  if (list.length > 0 && !list.some(x => x.article_id === currentId)) {
    selectArticle(list[0].article_id);
  }
}

function renderDropdown() {
  const sel = document.getElementById('articleSelect');
  const list = getFilteredItems();
  sel.innerHTML = '';
  for (const it of list) {
    const opt = document.createElement('option');
    opt.value = it.article_id;
    const tag = it.annotation_status === 'done' ? '[Đã gán]' : '[Chưa gán]';
    const shortTitle = it.title.length > 56 ? it.title.slice(0, 56) + '...' : it.title;
    opt.textContent = `#${String(it.index).padStart(2, '0')} • ${it.published_date} • ${shortTitle} ${tag}`;
    if (it.article_id === currentId) opt.selected = true;
    sel.appendChild(opt);
  }
}

function stepArticle(delta) {
  const list = getFilteredItems();
  if (!list.length) return;
  const idx = list.findIndex(x => x.article_id === currentId);
  const nextIdx = Math.max(0, Math.min(list.length - 1, (idx === -1 ? 0 : idx) + delta));
  selectArticle(list[nextIdx].article_id);
}

function jumpNextPending() {
  const curIdx = items.findIndex(x => x.article_id === currentId);
  const after = items.slice(curIdx + 1).find(x => x.annotation_status !== 'done');
  const target = after || items.find(x => x.annotation_status !== 'done');
  if (target) {
    selectArticle(target.article_id);
  } else {
    showToast('Tất cả 50 bài báo đã được gán nhãn!');
  }
}

function highlightTextNodes(rootEl) {
  const walker = document.createTreeWalker(rootEl, NodeFilter.SHOW_TEXT, null);
  const textNodes = [];
  let node;
  while ((node = walker.nextNode())) {
    if (node.parentElement && !['SCRIPT', 'STYLE', 'CODE', 'PRE'].includes(node.parentElement.tagName)) {
      if (node.nodeValue && node.nodeValue.trim()) textNodes.push(node);
    }
  }
  const combinedRe = /\b([a-fA-F0-9]{64})\b|\b([a-fA-F0-9]{32})\b|\b(CVE-\d{4}-\d{4,7})\b|(hxxps?:\/\/[^\s<>"']+)|\b((?:\d{1,3}(?:\[\.\]|\.)){3}\d{1,3})\b|\b((?:[a-z0-9-]+(?:\[\.\]|\.))*[a-z0-9-]+\[\.\][a-z]{2,12})\b/gi;
  for (const tn of textNodes) {
    const val = tn.nodeValue;
    combinedRe.lastIndex = 0;
    if (!combinedRe.test(val)) continue;
    combinedRe.lastIndex = 0;
    const frag = document.createDocumentFragment();
    let lastIdx = 0;
    let m;
    while ((m = combinedRe.exec(val)) !== null) {
      if (m.index > lastIdx) frag.appendChild(document.createTextNode(val.slice(lastIdx, m.index)));
      const span = document.createElement('span');
      const tok = m[0];
      span.textContent = tok;
      if (m[1]) {
        span.className = 'HlHash';
        span.title = 'Click để thêm SHA256';
        span.onclick = () => appendVal('f_sha256', tok);
      } else if (m[2]) {
        span.className = 'HlHash';
        span.title = 'Click để thêm MD5';
        span.onclick = () => appendVal('f_md5', tok);
      } else if (m[3]) {
        span.className = 'HlCve';
        span.title = 'Click để thêm CVE';
        span.onclick = () => appendVal('f_cves', tok);
      } else if (m[4]) {
        span.className = 'HlDom';
        span.title = 'Click để thêm URL';
        span.onclick = () => appendVal('f_urls', tok);
      } else if (m[5]) {
        span.className = 'HlIp1';
        span.title = 'Click để thêm IP';
        span.onclick = () => appendVal('f_ips', tok);
      } else {
        span.className = 'HlDom';
        span.title = 'Click để thêm Domain';
        span.onclick = () => appendVal('f_domains', tok);
      }
      frag.appendChild(span);
      lastIdx = combinedRe.lastIndex;
    }
    if (lastIdx < val.length) frag.appendChild(document.createTextNode(val.slice(lastIdx)));
    tn.parentNode.replaceChild(frag, tn);
  }
}

function appendVal(fieldId, val) {
  const el = document.getElementById(fieldId);
  let clean = val.trim().replace(/\[\.\]/g, '.').replace(/hxxp/gi, 'http');
  if (fieldId === 'f_domains') clean = clean.toLowerCase();
  if (fieldId === 'f_cves') clean = clean.toUpperCase();
  const lines = el.value.split(/\r?\n/).map(x => x.trim()).filter(Boolean);
  if (!lines.includes(clean)) {
    lines.push(clean);
    el.value = lines.join('\n');
    refreshFieldCounts();
    showToast(`Đã thêm: ${clean}`);
  } else {
    showToast(`Đã có sẵn: ${clean}`);
  }
}

function rerenderArticleBody() {
  const it = items.find(x => x.article_id === currentId);
  if (!it) return;
  const on = document.getElementById('toggleHighlight')?.checked;
  document.getElementById('highlightLegendChips').style.display = on ? 'inline-flex' : 'none';
  const box = document.getElementById('readerBodyArea');
  if (it.content_html) {
    box.style.whiteSpace = 'normal';
    box.innerHTML = it.content_html;
  } else {
    box.style.whiteSpace = 'pre-wrap';
    box.textContent = it.content || '';
  }
  if (on) {
    highlightTextNodes(box);
  }
}

function selectArticle(aid) {
  currentId = aid;
  renderDropdown();
  const it = items.find(x => x.article_id === aid);
  if (!it) return;

  const badge = it.annotation_status === 'done'
    ? '<span class="BadgeCompleted">Đã gán</span>'
    : '<span class="BadgePending">Chưa gán</span>';

  const imgBadge = it.image_count ? `<span class="MetaPill">Hình ảnh: <b>${it.image_count}</b></span>` : '';
  const authorBadge = it.author ? `<span class="MetaPill">Tác giả: <b>${escapeHtml(it.author)}</b></span>` : '';
  const tagBadge = it.tags ? `<span class="MetaPill">Chủ đề: <b>${escapeHtml(it.tags)}</b></span>` : '';

  document.getElementById('readerHeaderArea').innerHTML = `
    <div style="display:flex; justify-content:space-between; align-items:flex-start; gap:10px;">
      <div class="ArticleTitle">#${String(it.index).padStart(2, '0')} / ${items.length}. ${escapeHtml(it.title)}</div>
      ${badge}
    </div>
    <div class="MetaPills">
      <span class="MetaPill">Ngày đăng: <b>${escapeHtml(it.published_date)}</b></span>
      <span class="MetaPill">Nguồn: <b>${escapeHtml(it.source_name)}</b></span>
      ${authorBadge}
      ${tagBadge}
      <span class="MetaPill">Độ dài: <b>${it.word_count} từ</b> (~${it.read_minutes} phút đọc)</span>
      ${imgBadge}
      <span class="MetaPill">Mã: <code class="mono">${escapeHtml(it.article_id)}</code></span>
      <a class="CleanBtn" style="padding:2px 9px; font-size:11.5px;" href="${escapeHtml(it.url)}" target="_blank">Mở bài gốc &nearr;</a>
    </div>
  `;
  rerenderArticleBody();
  document.getElementById('readerBodyArea').scrollTop = 0;

  const gt = it.ground_truth || {};
  document.getElementById('f_ips').value = (gt.ips || []).join('\n');
  document.getElementById('f_domains').value = (gt.domains || []).join('\n');
  document.getElementById('f_urls').value = (gt.urls || []).join('\n');
  document.getElementById('f_md5').value = (gt.md5 || []).join('\n');
  document.getElementById('f_sha256').value = (gt.sha256 || []).join('\n');
  document.getElementById('f_cves').value = (gt.cves || []).join('\n');
  document.getElementById('f_behaviors').value = (gt.attack_behaviors || []).join('\n');
  document.getElementById('f_notes').value = it.annotator_notes || '';

  const stBadge = document.getElementById('statusBadge');
  stBadge.className = it.annotation_status === 'done' ? 'BadgeCompleted' : 'BadgePending';
  stBadge.textContent = it.annotation_status === 'done' ? 'Trạng thái: Đã lưu' : 'Trạng thái: Chưa gán';
  document.getElementById('inlineCompareBox').style.display = 'none';
  refreshFieldCounts();
}

function linesOf(fid) {
  return document.getElementById(fid).value.split(/\r?\n/).map(x => x.trim()).filter(Boolean);
}

function refreshFieldCounts() {
  const map = [
    ['f_ips', 'cnt_ips'], ['f_domains', 'cnt_domains'], ['f_urls', 'cnt_urls'],
    ['f_md5', 'cnt_md5'], ['f_sha256', 'cnt_sha256'], ['f_cves', 'cnt_cves'], ['f_behaviors', 'cnt_behaviors']
  ];
  for (const [fid, cid] of map) {
    const n = linesOf(fid).length;
    const el = document.getElementById(cid);
    el.textContent = n;
    el.className = 'CountBadge' + (n > 0 ? ' has-val' : '');
  }
}

function clearFields() {
  ['f_ips', 'f_domains', 'f_urls', 'f_md5', 'f_sha256', 'f_cves', 'f_behaviors', 'f_notes'].forEach(id => {
    document.getElementById(id).value = '';
  });
  refreshFieldCounts();
}

function fillHints() {
  const it = items.find(x => x.article_id === currentId);
  if (!it || !it.candidate_hints) return;
  const h = it.candidate_hints;
  const merge = (fid, arr) => {
    const el = document.getElementById(fid);
    const cur = el.value.split(/\r?\n/).map(x => x.trim()).filter(Boolean);
    for (const v of (arr || [])) {
      const refanged = v.replace(/\[\.\]/g, '.').replace(/hxxp/gi, 'http');
      if (!cur.includes(refanged)) cur.push(refanged);
    }
    el.value = cur.join('\n');
  };
  merge('f_ips', h.ips);
  merge('f_domains', h.domains);
  merge('f_urls', h.urls);
  merge('f_md5', h.md5s);
  merge('f_sha256', h.sha256s);
  merge('f_cves', h.cves);
  refreshFieldCounts();
  showToast('Đã nạp gợi ý ứng viên — hãy rà soát lại trước khi lưu.');
}

async function saveCurrent(goNext, silent = false) {
  if (!currentId) return false;
  const payload = {
    article_id: currentId,
    annotation_status: 'done',
    ips: linesOf('f_ips'),
    domains: linesOf('f_domains'),
    urls: linesOf('f_urls'),
    md5: linesOf('f_md5'),
    sha256: linesOf('f_sha256'),
    cves: linesOf('f_cves'),
    attack_behaviors: linesOf('f_behaviors'),
    annotator_notes: document.getElementById('f_notes').value
  };
  const res = await fetch('/api/save', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(payload)
  });
  const data = await res.json();
  if (data.ok) {
    const idx = items.findIndex(x => x.article_id === currentId);
    items[idx].annotation_status = 'done';
    items[idx].ground_truth = payload;
    items[idx].annotator_notes = payload.annotator_notes;
    updateProgress();
    renderDropdown();
    const stBadge = document.getElementById('statusBadge');
    stBadge.className = 'BadgeCompleted';
    stBadge.textContent = 'Trạng thái: Đã lưu';
    if (!silent) showToast(`Đã lưu bài #${items[idx].index}!`);
    if (goNext) stepArticle(1);
    return true;
  }
  return false;
}

async function runQuickCompareOne() {
  if (!currentId) return;
  await saveCurrent(false, true);
  const btn = document.getElementById('btnQuickAi');
  const box = document.getElementById('inlineCompareBox');
  const t0 = Date.now();
  btn.disabled = true;
  btn.innerHTML = `<span class="Spinner"></span> Đang chạy AI (${escapeHtml(defaultModel)})... (<span id="quickTimerBtn">0s</span>)`;
  box.style.display = 'block';
  box.innerHTML = `<div style="display:flex; align-items:center; gap:8px; color:var(--primary); font-weight:600;">
    <span class="Spinner"></span>
    <span>AI (${escapeHtml(defaultModel)}) đang đọc bài báo, trích xuất IOC &amp; sinh Agentic Skill... (<span id="quickTimerBox" class="mono">0s</span>)</span>
  </div>
  <div style="font-size:12px; color:var(--text-muted); margin-top:4px;">Bước 1/2: Trích xuất IOC + xAI Grounding &rarr; Bước 2/2: Tổng hợp SKILL.md &amp; verify_threat.py</div>`;

  const quickTick = setInterval(() => {
    const sec = Math.max(0, Math.round((Date.now() - t0) / 1000));
    const el1 = document.getElementById('quickTimerBtn');
    const el2 = document.getElementById('quickTimerBox');
    if (el1) el1.textContent = `${sec}s`;
    if (el2) el2.textContent = `${sec}s`;
  }, 500);

  try {
    const res = await fetch('/api/compare_one', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ article_id: currentId, model: defaultModel })
    });
    const d = await res.json();
    const diff = d.diff;
    const chips = (arr, cls) => arr.length
      ? arr.map(x => `<span class="IocChip ${cls}">${escapeHtml(x.type)}: ${escapeHtml(x.value)}</span>`).join('')
      : '<span style="color:var(--text-muted); font-size:12px;">Không có</span>';
    const sc = d.syntax_checks || {};
    const validBadge = (sc.final_skill_md_valid && sc.final_manifest_valid && sc.final_script_valid)
      ? '<span class="BadgeCompleted">Skill hợp lệ 100%</span>'
      : '<span class="BadgePending">Cần kiểm tra Skill</span>';

    const notesHtml = (d.ai_context_notes && d.ai_context_notes.length)
      ? `<div style="margin-top:8px; padding-top:8px; border-top:1px dashed var(--border-dark);">
           <b style="font-size:12px; color:var(--primary);">Ghi chú phân tích ngữ cảnh (AI Agent):</b>
           <ul style="margin:4px 0 0 18px; font-size:12px; color:var(--text-main);">
             ${d.ai_context_notes.map(n => `<li>${escapeHtml(n)}</li>`).join('')}
           </ul>
         </div>`
      : '';

    box.innerHTML = `
      <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:8px;">
        <b>Kết quả so sánh ngay (${escapeHtml(d.model)})</b>
        <span>Precision: <b>${diff.precision}%</b> | Recall: <b>${diff.recall}%</b> ${validBadge}</span>
      </div>
      <div style="margin-bottom:6px;"><b style="font-size:12px; color:var(--safe);">Khớp chuẩn (TP: ${diff.tp}):</b><br/>${chips(diff.tp_items, 'tp')}</div>
      <div style="margin-bottom:6px;"><b style="font-size:12px; color:var(--danger);">AI bịa / dư (FP: ${diff.fp}):</b><br/>${chips(diff.fp_items, 'fp')}</div>
      <div style="margin-bottom:6px;"><b style="font-size:12px; color:var(--amber);">AI bỏ sót (FN: ${diff.fn}):</b><br/>${chips(diff.fn_items, 'fn')}</div>
      ${notesHtml}
      <div style="margin-top:6px; font-size:12px; color:var(--text-muted);">Skill sinh ra: <code class="mono">${escapeHtml(d.skill_name)}</code></div>
    `;
  } catch (e) {
    box.innerHTML = `<div style="color:var(--danger);">Lỗi khi gọi AI: ${escapeHtml(String(e))}</div>`;
  } finally {
    clearInterval(quickTick);
    btn.disabled = false;
    btn.textContent = `Lưu & Chạy AI (${defaultModel}) So Sánh Bài Này Ngay`;
  }
}

function switchTab(tab) {
  const isLabel = tab === 'label';
  document.getElementById('viewLabel').style.display = isLabel ? 'block' : 'none';
  document.getElementById('viewCompare').style.display = isLabel ? 'none' : 'block';
  document.getElementById('tabBtnLabel').classList.toggle('active', isLabel);
  document.getElementById('tabBtnCompare').classList.toggle('active', !isLabel);
  if (!isLabel) {
    loadComparison();
    pollBatchStatus(true);
  }
}

let __batchPollTimer = null;
let __batchUiTickTimer = null;
let __lastSeenCompleted = -1;
let __lastActiveArticleId = null;
let __lastBatchState = null;
let __clientArtStartedMs = null;
let __singleRunningId = null;
let __singleRunningStartedMs = null;

function fmtDur(sec) {
  const s = Math.max(0, Math.round(sec || 0));
  const m = Math.floor(s / 60);
  const r = s % 60;
  return m > 0 ? `${m}m ${r}s` : `${r}s`;
}

function updateLiveTimersOnly() {
  if (__lastBatchState && __lastBatchState.running) {
    const artElapsed = __clientArtStartedMs ? Math.max(0, Math.round((Date.now() - __clientArtStartedMs) / 1000)) : 0;
    document.querySelectorAll('.active-art-timer').forEach(el => {
      el.textContent = fmtDur(artElapsed);
    });
    const st = __lastBatchState;
    const totalArticles = st.articles_total || st.total_articles || 50;
    const cached = st.cached_count || 0;
    const target = st.target_count || totalArticles;
    const processed = (st.completed || 0) + (st.failed || 0);
    const pct = target > 0 ? Math.min(100, Math.round((processed / target) * 100)) : 100;
    const totalElapsed = st.started_at
      ? Math.max(0, Math.round(((st.server_now || Date.now() / 1000) - st.started_at) + ((Date.now() - (st.__fetchedAt || Date.now())) / 1000)))
      : 0;
    const etaRemain = st.avg_article_sec && target > processed
      ? ` • Ước tính còn: ~${fmtDur(st.avg_article_sec * (target - processed))}`
      : '';
    const countsEl = document.getElementById('batchCountsText');
    if (countsEl) {
      countsEl.textContent = `Tiến độ: ${processed}/${target} (${pct}%) • Đang chạy bài này: ${fmtDur(artElapsed)} • Tổng: ${fmtDur(totalElapsed)}${etaRemain} • Cache: ${cached}/${totalArticles}`;
    }
  }
  if (__singleRunningId && __singleRunningStartedMs) {
    const sSec = Math.max(0, Math.round((Date.now() - __singleRunningStartedMs) / 1000));
    document.querySelectorAll('.single-art-timer').forEach(el => {
      el.textContent = fmtDur(sSec);
    });
  }
}

function renderBatchState(st) {
  if (!st) return;
  st.__fetchedAt = Date.now();
  __lastBatchState = st;

  const panel = document.getElementById('batchProgressPanel');
  const btnMissing = document.getElementById('btnRunAllMissing');
  const btnForce = document.getElementById('btnRunAllForce');
  const btnStop = document.getElementById('btnStopAll');
  const statusEl = document.getElementById('batchStatusText');
  const stepEl = document.getElementById('batchStepText');
  const countsEl = document.getElementById('batchCountsText');
  const fillEl = document.getElementById('batchProgressFill');
  const subEl = document.getElementById('batchSubText');
  const logsEl = document.getElementById('batchLogsBox');

  const totalArticles = st.articles_total || st.total_articles || 50;
  const cached = st.cached_count || 0;
  const remaining = Math.max(0, totalArticles - cached);

  btnMissing.disabled = !!st.running;
  btnForce.disabled = !!st.running;
  btnStop.style.display = st.running ? 'inline-flex' : 'none';
  btnStop.disabled = !!st.stop_requested;
  btnStop.textContent = st.stop_requested ? 'Đang chờ dừng...' : 'Dừng Sau Bài Này';

  btnMissing.innerHTML = st.running
    ? `<span class="Spinner" style="border-color:rgba(255,255,255,0.4); border-top-color:#ffffff;"></span> Đang Phân Tích... (${st.completed || 0}/${st.target_count || '?'})`
    : (remaining > 0 ? `Phân Tích All Bài (${remaining} bài chưa chạy)` : `Đã Đủ ${cached}/${totalArticles} Bài`);

  const showPanel = st.running || ['completed', 'stopped', 'error'].includes(st.phase);
  panel.style.display = showPanel ? 'block' : 'none';
  if (!showPanel) return;

  const target = st.target_count || totalArticles;
  const processed = (st.completed || 0) + (st.failed || 0);
  const pct = target > 0 ? Math.min(100, Math.round((processed / target) * 100)) : 100;
  fillEl.style.width = `${st.running && pct < 4 ? 6 : pct}%`;
  fillEl.classList.toggle('is-active', !!st.running);

  if (st.running && st.current_article_id !== __lastActiveArticleId) {
    const serverArtAgeMs = (st.server_now && st.current_started_at)
      ? Math.max(0, (st.server_now - st.current_started_at) * 1000)
      : 0;
    __clientArtStartedMs = Date.now() - serverArtAgeMs;
  } else if (!st.running) {
    __clientArtStartedMs = null;
  }

  if (st.running) {
    if (st.phase === 'starting') {
      statusEl.innerHTML = `<span class="Spinner"></span> <span>Đang kiểm tra Ollama và nạp model ${escapeHtml(st.model || defaultModel)}...</span>`;
    } else if (st.current_index != null) {
      statusEl.innerHTML = `<span class="Spinner"></span> <span>AI đang phân tích #${String(st.current_index).padStart(2, '0')}: ${escapeHtml(st.current_title || '')}</span>`;
    } else {
      statusEl.innerHTML = `<span class="Spinner"></span> <span>Đang chạy batch phân tích với ${escapeHtml(st.model || defaultModel)}...</span>`;
    }
    stepEl.style.display = st.current_step ? 'block' : 'none';
    stepEl.textContent = st.current_step || '';
  } else if (st.phase === 'completed') {
    statusEl.textContent = `Hoàn tất phân tích! Đã có kết quả AI cho ${cached} / ${totalArticles} bài.`;
    stepEl.style.display = 'none';
  } else if (st.phase === 'stopped') {
    statusEl.textContent = `Đã dừng theo yêu cầu. Đã lưu cache ${cached} / ${totalArticles} bài (có thể bấm chạy tiếp bất cứ lúc nào).`;
    stepEl.style.display = 'none';
  } else if (st.phase === 'error') {
    statusEl.textContent = `Lỗi batch AI: ${st.last_error || 'Không xác định'}`;
    stepEl.style.display = 'none';
  }

  const totalElapsed = st.started_at
    ? Math.max(0, Math.round(((st.finished_at || st.server_now || Date.now() / 1000) - st.started_at)))
    : 0;
  const avgTxt = st.avg_article_sec ? ` • Tốc độ TB: <b>${st.avg_article_sec}s/bài</b>` : '';
  const errHtml = st.last_error ? ` <span style="color:var(--danger);">• Lỗi gần nhất: ${escapeHtml(st.last_error)}</span>` : '';
  subEl.innerHTML = `Thành công: <b>${st.completed || 0}</b> • Bỏ qua (có sẵn): <b>${st.skipped_cached || 0}</b> • Lỗi: <b>${st.failed || 0}</b>${avgTxt}${errHtml}`;

  if (!st.running) {
    countsEl.textContent = `Tiến độ: ${processed}/${target} (${pct}%) • Cache: ${cached}/${totalArticles} • Tổng thời gian: ${fmtDur(totalElapsed)}`;
  }

  const logs = st.recent_logs || [];
  if (logs.length) {
    logsEl.style.display = 'block';
    logsEl.innerHTML = logs.map(line => `<div>${escapeHtml(line)}</div>`).join('');
    logsEl.scrollTop = logsEl.scrollHeight;
  } else {
    logsEl.style.display = 'none';
  }

  clearInterval(__batchUiTickTimer);
  if (st.running || __singleRunningId) {
    updateLiveTimersOnly();
    __batchUiTickTimer = setInterval(updateLiveTimersOnly, 1000);
  }
}

async function pollBatchStatus(forceOnce = false) {
  try {
    const res = await fetch(`/api/compare_all/status?model=${encodeURIComponent(defaultModel)}`);
    const data = await res.json();
    const st = data.state || {};
    const curDone = (st.completed || 0) + (st.failed || 0);
    const activeChanged = st.current_article_id !== __lastActiveArticleId;
    const stepChanged = __lastBatchState && st.current_step !== __lastBatchState.current_step;

    renderBatchState(st);
    __lastActiveArticleId = st.current_article_id || null;

    if ((__lastSeenCompleted !== -1 && curDone !== __lastSeenCompleted) || activeChanged || stepChanged) {
      loadComparison();
    }
    __lastSeenCompleted = curDone;

    clearTimeout(__batchPollTimer);
    if (st.running) {
      __batchPollTimer = setTimeout(() => pollBatchStatus(false), 1200);
    } else if (!forceOnce && ['completed', 'stopped'].includes(st.phase)) {
      loadComparison();
    }
  } catch (e) {
    // ignore transient poll errors
  }
}

async function startCompareAll(forceRerun) {
  if (forceRerun) {
    const ok = confirm('Chạy lại toàn bộ 50 bài từ đầu (ghi đè cache hiện có)? Quá trình chạy local LLM có thể mất vài chục phút.');
    if (!ok) return;
  }
  __lastSeenCompleted = 0;
  __lastActiveArticleId = null;
  const res = await fetch('/api/compare_all', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ model: defaultModel, force_rerun: !!forceRerun })
  });
  const data = await res.json();
  renderBatchState(data.state);
  loadComparison();
  showToast(forceRerun ? 'Bắt đầu phân tích lại toàn bộ 50 bài...' : 'Bắt đầu phân tích các bài còn thiếu...');
  clearTimeout(__batchPollTimer);
  __batchPollTimer = setTimeout(() => pollBatchStatus(false), 800);
}

async function stopCompareAll() {
  const res = await fetch('/api/compare_all/stop', { method: 'POST' });
  const data = await res.json();
  renderBatchState(data.state);
  showToast('Đã gửi lệnh dừng — sẽ dừng ngay sau khi xong bài đang xử lý.');
}

async function runCompareRow(aid, btnEl) {
  __singleRunningId = aid;
  __singleRunningStartedMs = Date.now();
  if (btnEl) {
    btnEl.disabled = true;
    btnEl.innerHTML = `<span class="Spinner"></span> Đang phân tích...`;
  }
  loadComparison();
  clearInterval(__batchUiTickTimer);
  __batchUiTickTimer = setInterval(updateLiveTimersOnly, 1000);
  try {
    const res = await fetch('/api/compare_one', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ article_id: aid, model: defaultModel })
    });
    const d = await res.json();
    if (d.ok) {
      showToast(`Đã phân tích xong với ${d.model}!`);
    } else {
      showToast('Chạy AI thất bại!');
    }
  } catch (e) {
    showToast(`Lỗi: ${e}`);
  } finally {
    __singleRunningId = null;
    __singleRunningStartedMs = null;
    await loadComparison();
    await pollBatchStatus(true);
  }
}

async function loadComparison() {
  const res = await fetch(`/api/comparison?model=${encodeURIComponent(defaultModel)}`);
  const data = await res.json();
  document.getElementById('cmpModelName').textContent = data.model || defaultModel;
  const s = data.summary || {};
  document.getElementById('cmpCount').textContent = data.compared_count || 0;
  document.getElementById('cmpPrec').textContent = `${s.precision || 0}%`;
  document.getElementById('cmpRec').textContent = `${s.recall || 0}%`;
  document.getElementById('cmpF1').textContent = `${s.f1 || 0}%`;
  document.getElementById('cmpCountsSub').textContent = `TP: ${s.tp || 0} | FP: ${s.fp || 0} | FN: ${s.fn || 0}`;
  document.getElementById('cmpSkillValid').textContent = `${s.skill_valid_count || 0} / ${data.ai_cached_count || 0}`;

  const tbody = document.getElementById('cmpTableBody');
  const rows = data.rows || [];
  if (!rows.length) {
    tbody.innerHTML = '<tr><td colspan="4" style="text-align:center; color:var(--text-muted); padding:26px;">Chưa có bài nào được gán nhãn hoặc chưa chạy AI Agent. Hãy gán nhãn ở Tab 1 trước!</td></tr>';
    return;
  }

  const chips = (arr, cls) => arr && arr.length
    ? `<div class="IocChipList">${arr.map(x => `<span class="IocChip ${cls}">${escapeHtml(x.type)}: ${escapeHtml(x.value)}</span>`).join('')}</div>`
    : '<span style="color:var(--text-muted); font-size:12px;">-</span>';

  const batchActiveId = (__lastBatchState && __lastBatchState.running) ? __lastBatchState.current_article_id : null;
  const batchStep = (__lastBatchState && __lastBatchState.running) ? (__lastBatchState.current_step || 'AI đang phân tích...') : '';

  tbody.innerHTML = rows.map(r => {
    const isBatchActive = batchActiveId && batchActiveId === r.article_id;
    const isSingleActive = __singleRunningId && __singleRunningId === r.article_id;
    const isActive = isBatchActive || isSingleActive;
    const d = r.diff;

    let tpHtml;
    if (isBatchActive) {
      tpHtml = `<div class="BadgeRunning"><span class="Spinner"></span> AI đang phân tích... (<span class="active-art-timer mono">0s</span>)</div>
        <div style="margin-top:5px; font-size:12px; color:var(--primary); font-weight:500;">${escapeHtml(batchStep)}</div>`;
    } else if (isSingleActive) {
      tpHtml = `<div class="BadgeRunning"><span class="Spinner"></span> AI đang phân tích bài này... (<span class="single-art-timer mono">0s</span>)</div>
        <div style="margin-top:5px; font-size:12px; color:var(--primary);">Đang đọc bài, trích xuất IOC &amp; sinh Agentic Skill...</div>`;
    } else if (d) {
      tpHtml = `<div><b style="font-size:11.5px; color:var(--safe);">TP (${d.tp}):</b> ${chips(d.tp_items, 'tp')}</div>
      <div style="margin-top:4px;"><b style="font-size:11.5px; color:var(--amber);">FN (${d.fn}):</b> ${chips(d.fn_items, 'fn')}</div>`;
    } else {
      tpHtml = `<div style="display:flex; align-items:center; gap:8px; flex-wrap:wrap;">
           <span class="BadgePending">Chưa chạy AI</span>
           <button class="CleanBtn" style="padding:3px 9px; font-size:11.5px;" onclick="runCompareRow('${escapeHtml(r.article_id)}', this)">Chạy AI bài này</button>
         </div>`;
    }

    const fpHtml = isActive
      ? '<span style="color:var(--primary); font-size:12px;">Đang xử lý...</span>'
      : (d ? chips(d.fp_items, 'fp') : '-');
    const sc = r.syntax_checks || {};
    const aiNotesHtml = (r.ai_context_notes && r.ai_context_notes.length)
      ? `<div style="margin-top:6px; font-size:11.5px; color:var(--text-main);"><b>Ghi chú AI:</b> ${r.ai_context_notes.map(n => escapeHtml(n)).join(' &bull; ')}</div>`
      : '';
    const skillHtml = isActive
      ? '<span style="color:var(--primary); font-size:12px;">Đang tổng hợp Skill...</span>'
      : (r.has_ai_run
        ? `<div style="display:flex; justify-content:space-between; align-items:center; gap:6px; flex-wrap:wrap;">
             <code class="mono" style="font-size:12px;">${escapeHtml(r.skill_name)}</code>
             <button class="CleanBtn" style="padding:2px 7px; font-size:11px;" onclick="runCompareRow('${escapeHtml(r.article_id)}', this)">Chạy lại</button>
           </div>
           <div style="margin-top:4px; font-size:11.5px; color:var(--text-muted);">
             SKILL.md: <b>${sc.final_skill_md_valid ? 'OK' : 'Err'}</b> &bull;
             manifest: <b>${sc.final_manifest_valid ? 'OK' : 'Err'}</b> &bull;
             verify_threat.py: <b>${sc.final_script_valid ? 'OK' : 'Err'}</b>
           </div>${aiNotesHtml}`
        : '<span style="color:var(--text-muted);">-</span>');
    return `
      <tr class="${isActive ? 'RowActive' : ''}">
        <td>
          <div style="font-weight:600; color:var(--text-main);">#${String(r.index).padStart(2, '0')}. ${escapeHtml(r.title)}</div>
          <div style="font-size:11.5px; color:var(--text-muted); margin-top:3px;">${escapeHtml(r.published_date)} &bull; ${escapeHtml(r.source_name)}</div>
        </td>
        <td>${tpHtml}</td>
        <td>${fpHtml}</td>
        <td>${skillHtml}</td>
      </tr>
    `;
  }).join('');
  updateLiveTimersOnly();
}

init();
</script>
</body>
</html>
"""


@app.get("/", response_class=HTMLResponse)
def index():
    return HTML_UI


if __name__ == "__main__":
    print("[*] Khoi dong CTI 50-Article Ground Truth & Comparison Workbench tai: http://127.0.0.1:8780")
    uvicorn.run(app, host="127.0.0.1", port=8780, log_level="warning")
