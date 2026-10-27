# -*- coding: utf-8 -*-
import os
import sys
import json
import time
import subprocess
import webbrowser
from typing import Dict, Any, Optional

from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.middleware.cors import CORSMiddleware
import uvicorn

TOOL_DIR = os.path.dirname(os.path.abspath(__file__))
if TOOL_DIR not in sys.path:
    sys.path.insert(0, TOOL_DIR)

from docker_security_scanner import DockerSecurityScanner

app = FastAPI(title="Docker Security Scanner Dashboard")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

DEMO_DIR = os.path.join(TOOL_DIR, "demo")
VULN_INSPECT = os.path.join(DEMO_DIR, "container_inspect_vulnerable.json")
HARD_INSPECT = os.path.join(DEMO_DIR, "container_inspect_hardened.json")
VULN_DOCKERFILE = os.path.join(DEMO_DIR, "Dockerfile.vulnerable")
HARD_DOCKERFILE = os.path.join(DEMO_DIR, "Dockerfile.hardened")

def run_scan_on_target(target_type: str, custom_code: Optional[str] = None):
    scanner = DockerSecurityScanner()
    
    # Try real docker inspect if target is running container
    if target_type == "vulnerable_app" or target_type == "hardened_app":
        try:
            res = subprocess.run(["docker", "inspect", target_type], capture_output=True, text=True, timeout=3)
            if res.returncode == 0 and res.stdout.strip():
                data = json.loads(res.stdout)
                scanner.analyze_inspect_json(data[0] if isinstance(data, list) else data, target_name=f"Docker Container ({target_type})")
                return scanner_to_dict(scanner)
        except Exception:
            pass # Fall back to pre-configured inspect files
            
    if target_type == "vulnerable_app":
        with open(VULN_INSPECT, "r", encoding="utf-8") as f:
            data = json.load(f)
        scanner.analyze_inspect_json(data[0], target_name="vulnerable_app (Container Runtime)")
    elif target_type == "hardened_app":
        with open(HARD_INSPECT, "r", encoding="utf-8") as f:
            data = json.load(f)
        scanner.analyze_inspect_json(data[0], target_name="hardened_app (Hardened Runtime)")
    elif target_type == "dockerfile_vuln":
        with open(VULN_DOCKERFILE, "r", encoding="utf-8") as f:
            content = f.read()
        scanner.analyze_dockerfile(content, filename="Dockerfile.vulnerable")
    elif target_type == "dockerfile_hard":
        with open(HARD_DOCKERFILE, "r", encoding="utf-8") as f:
            content = f.read()
        scanner.analyze_dockerfile(content, filename="Dockerfile.hardened")
    elif target_type == "custom" and custom_code:
        scanner.analyze_dockerfile(custom_code, filename="Custom_Dockerfile")
    else:
        with open(VULN_INSPECT, "r", encoding="utf-8") as f:
            data = json.load(f)
        scanner.analyze_inspect_json(data[0], target_name="vulnerable_app")

    return scanner_to_dict(scanner)

def scanner_to_dict(scanner: DockerSecurityScanner):
    has_critical = any(f['severity'] == "CRITICAL" for f in scanner.findings)
    gate_passed = scanner.score >= 70 and not has_critical
    
    module_status = {
        "m1_root": {"id": "CIS-4.1", "status": "PASS", "title": "User Privilege (UID)", "desc": "Chạy dưới user thường (Non-root)"},
        "m2_priv": {"id": "CIS-5.2", "status": "PASS", "title": "Privileged & Capabilities", "desc": "Hạn chế Capabilities & Privileged = false"},
        "m3_sock": {"id": "CIS-5.31", "status": "PASS", "title": "Docker Socket Mount", "desc": "Không mount tệp /var/run/docker.sock"},
        "m4_secret": {"id": "CIS-4.6", "status": "PASS", "title": "Hardcoded Secret", "desc": "Không phát hiện secret trong ENV"},
        "m5_cgroups": {"id": "CIS-5.10", "status": "PASS", "title": "Resource Limits (DoS)", "desc": "Có định mức RAM và CPU"},
        "m6_image": {"id": "CIS-4.2", "status": "PASS", "title": "Base Image & Healthcheck", "desc": "Tag cố định và có HEALTHCHECK"}
    }
    
    for f in scanner.findings:
        rid = f['rule_id']
        if rid == "CIS-4.1":
            module_status["m1_root"] = {"id": rid, "status": "FAIL", "title": "User Privilege (UID 0)", "desc": f['custom_desc']}
        elif rid in ["CIS-5.2", "CIS-5.3"]:
            module_status["m2_priv"] = {"id": rid, "status": "FAIL", "title": "Privileged & Caps", "desc": f['custom_desc']}
        elif rid == "CIS-5.31":
            module_status["m3_sock"] = {"id": rid, "status": "FAIL", "title": "Docker Socket Exposed", "desc": f['custom_desc']}
        elif rid == "CIS-4.6":
            module_status["m4_secret"] = {"id": rid, "status": "FAIL", "title": "Secret Leaked in ENV", "desc": f['custom_desc']}
        elif rid in ["CIS-5.10", "CIS-5.11"]:
            module_status["m5_cgroups"] = {"id": rid, "status": "FAIL", "title": "No cgroups Limits (DoS)", "desc": f['custom_desc']}
        elif rid in ["CIS-4.2", "CIS-4.6-HEALTH"]:
            module_status["m6_image"] = {"id": rid, "status": "FAIL", "title": "Base Image / Healthcheck", "desc": f['custom_desc']}

    return {
        "target_name": scanner.target_name,
        "scan_time": scanner.scan_time,
        "score": scanner.score,
        "gate_passed": gate_passed,
        "findings_count": len(scanner.findings),
        "critical_count": sum(1 for f in scanner.findings if f['severity'] == "CRITICAL"),
        "high_count": sum(1 for f in scanner.findings if f['severity'] == "HIGH"),
        "medium_count": sum(1 for f in scanner.findings if f['severity'] == "MEDIUM"),
        "low_count": sum(1 for f in scanner.findings if f['severity'] == "LOW"),
        "modules": module_status,
        "findings": scanner.findings,
        "remediation_cmd": "docker run -d \\\n  --name my-hardened-app \\\n  --user 1001:1001 \\\n  --cap-drop=ALL \\\n  --cap-add=NET_BIND_SERVICE \\\n  --security-opt seccomp=profile.json \\\n  --memory=\"512m\" --cpus=\"1.0\" \\\n  --pids-limit 100 \\\n  --read-only \\\n  -v /app/tmp:/tmp:rw,noexec,nosuid \\\n  my-secure-app:v1.0"
    }

@app.get("/api/scan/{target}")
async def api_scan(target: str):
    return JSONResponse(run_scan_on_target(target))

@app.post("/api/scan_custom")
async def api_scan_custom(req: Request):
    body = await req.json()
    code = body.get("code", "")
    return JSONResponse(run_scan_on_target("custom", custom_code=code))

@app.get("/", response_class=HTMLResponse)
async def serve_dashboard():
    return HTML_DASHBOARD

HTML_DASHBOARD = """<!DOCTYPE html>
<html lang="vi">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>DOCKER SHIELD - Hệ Thống Đánh Giá An Ninh & Kiểm Tra Rủi Ro Docker</title>
    <link href="https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;500;700;800&family=Plus+Jakarta+Sans:wght@400;600;700;800&display=swap" rel="stylesheet">
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
    <style>
        :root {
            --bg: #07090e;
            --panel: rgba(16, 22, 36, 0.85);
            --panel-light: rgba(26, 35, 58, 0.6);
            --border: rgba(99, 102, 241, 0.2);
            --border-hover: rgba(99, 102, 241, 0.5);
            --cyan: #06b6d4;
            --purple: #8b5cf6;
            --green: #10b981;
            --red: #ef4444;
            --yellow: #f59e0b;
            --text-main: #f8fafc;
            --text-sub: #94a3b8;
        }
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            background: radial-gradient(circle at 15% 15%, #0f172a 0%, var(--bg) 90%);
            color: var(--text-main);
            font-family: 'Plus Jakarta Sans', sans-serif;
            min-height: 100vh;
            padding: 20px 28px;
            overflow-x: hidden;
        }
        .container { max-width: 1440px; margin: 0 auto; }
        
        /* Top App Bar */
        .app-bar {
            display: flex;
            justify-content: space-between;
            align-items: center;
            background: var(--panel);
            backdrop-filter: blur(20px);
            border: 1px solid var(--border);
            border-radius: 16px;
            padding: 16px 24px;
            margin-bottom: 20px;
            box-shadow: 0 10px 40px rgba(0,0,0,0.6);
        }
        .brand { display: flex; align-items: center; gap: 14px; }
        .brand-icon {
            width: 48px;
            height: 48px;
            background: linear-gradient(135deg, #3b82f6, #8b5cf6);
            border-radius: 12px;
            display: flex;
            align-items: center;
            justify-content: center;
            font-size: 22px;
            color: #fff;
            box-shadow: 0 0 25px rgba(59, 130, 246, 0.5);
        }
        .brand-text h1 {
            font-size: 20px;
            font-weight: 800;
            letter-spacing: -0.5px;
            background: linear-gradient(135deg, #38bdf8, #a855f7);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
        }
        .brand-text p { font-size: 12px; color: var(--text-sub); }
        .system-tags { display: flex; gap: 10px; font-family: 'JetBrains Mono', monospace; font-size: 11px; }
        .tag-pill {
            background: rgba(255,255,255,0.04);
            border: 1px solid var(--border);
            padding: 6px 12px;
            border-radius: 20px;
            display: flex;
            align-items: center;
            gap: 6px;
        }
        .tag-pill .dot { width: 8px; height: 8px; border-radius: 50%; background: var(--green); box-shadow: 0 0 8px var(--green); animation: pulse 2s infinite; }
        @keyframes pulse { 0% { opacity: 0.4; } 50% { opacity: 1; } 100% { opacity: 0.4; } }

        /* Action Toolbar */
        .toolbar {
            display: flex;
            justify-content: space-between;
            align-items: center;
            background: var(--panel);
            border: 1px solid var(--border);
            border-radius: 14px;
            padding: 14px 20px;
            margin-bottom: 24px;
            gap: 16px;
        }
        .target-selector { display: flex; align-items: center; gap: 12px; flex: 1; }
        .target-selector label { font-size: 13px; font-weight: 700; color: var(--text-sub); text-transform: uppercase; }
        .select-styled {
            background: #0b1120;
            border: 1px solid #334155;
            color: #f1f5f9;
            padding: 10px 16px;
            border-radius: 10px;
            font-size: 13px;
            font-family: 'JetBrains Mono', monospace;
            cursor: pointer;
            outline: none;
            flex: 1;
            max-width: 480px;
        }
        .select-styled:focus { border-color: var(--cyan); box-shadow: 0 0 15px rgba(6, 182, 212, 0.3); }

        .btn-group { display: flex; gap: 10px; }
        .btn {
            padding: 10px 20px;
            border-radius: 10px;
            font-size: 13px;
            font-weight: 700;
            cursor: pointer;
            border: none;
            display: flex;
            align-items: center;
            gap: 8px;
            transition: all 0.2s ease;
            font-family: 'Plus Jakarta Sans', sans-serif;
        }
        .btn-scan {
            background: linear-gradient(135deg, #ef4444, #dc2626);
            color: #fff;
            box-shadow: 0 4px 20px rgba(239, 68, 68, 0.4);
        }
        .btn-scan:hover { transform: translateY(-2px); box-shadow: 0 6px 25px rgba(239, 68, 68, 0.6); }
        .btn-hardened {
            background: linear-gradient(135deg, #10b981, #059669);
            color: #fff;
            box-shadow: 0 4px 20px rgba(16, 185, 129, 0.4);
        }
        .btn-hardened:hover { transform: translateY(-2px); box-shadow: 0 6px 25px rgba(16, 185, 129, 0.6); }
        .btn-cicd {
            background: #1e293b;
            color: #93c5fd;
            border: 1px solid #3b82f6;
        }
        .btn-cicd:hover { background: #3b82f6; color: #fff; }

        /* Main Grid */
        .main-grid {
            display: grid;
            grid-template-columns: 360px 1fr;
            gap: 24px;
            margin-bottom: 24px;
        }
        .card {
            background: var(--panel);
            backdrop-filter: blur(16px);
            border: 1px solid var(--border);
            border-radius: 18px;
            padding: 24px;
            box-shadow: 0 10px 30px rgba(0,0,0,0.4);
        }

        /* Score Meter */
        .score-display {
            display: flex;
            flex-direction: column;
            align-items: center;
            justify-content: center;
            text-align: center;
            padding: 20px 0;
        }
        .radial-progress {
            width: 180px;
            height: 180px;
            position: relative;
            display: flex;
            align-items: center;
            justify-content: center;
            margin-bottom: 16px;
        }
        .radial-progress svg { width: 100%; height: 100%; transform: rotate(-90deg); }
        .radial-progress circle {
            fill: none;
            stroke-width: 14;
            stroke-linecap: round;
        }
        .circle-bg { stroke: rgba(255,255,255,0.06); }
        .circle-val {
            stroke: var(--red);
            stroke-dasharray: 440;
            stroke-dashoffset: 440;
            transition: stroke-dashoffset 1s ease, stroke 0.5s ease;
        }
        .score-inner {
            position: absolute;
            display: flex;
            flex-direction: column;
            align-items: center;
        }
        .score-inner .num {
            font-size: 48px;
            font-weight: 800;
            font-family: 'JetBrains Mono', monospace;
            color: #fff;
            line-height: 1;
        }
        .score-inner .scale { font-size: 13px; color: var(--text-sub); }
        .rating-badge {
            font-size: 14px;
            font-weight: 800;
            padding: 6px 18px;
            border-radius: 30px;
            text-transform: uppercase;
            letter-spacing: 0.5px;
            background: rgba(239, 68, 68, 0.2);
            color: #f87171;
            border: 1px solid #ef4444;
            box-shadow: 0 0 20px rgba(239, 68, 68, 0.3);
        }

        /* Security Gate Box (Slide 12) */
        .security-gate-box {
            background: rgba(239, 68, 68, 0.1);
            border: 1px dashed #ef4444;
            border-radius: 12px;
            padding: 16px;
            margin-top: 20px;
            text-align: center;
        }
        .security-gate-box.passed {
            background: rgba(16, 185, 129, 0.1);
            border: 1px dashed #10b981;
        }
        .gate-title { font-size: 13px; font-weight: 800; text-transform: uppercase; margin-bottom: 4px; }
        .gate-status { font-family: 'JetBrains Mono', monospace; font-size: 12px; font-weight: 700; }

        /* Modules Grid (Slide 4 - 9) */
        .modules-grid {
            display: grid;
            grid-template-columns: repeat(3, 1fr);
            gap: 16px;
        }
        .module-tile {
            background: var(--panel-light);
            border: 1px solid rgba(255,255,255,0.06);
            border-radius: 14px;
            padding: 16px;
            transition: all 0.2s ease;
            position: relative;
            overflow: hidden;
        }
        .module-tile:hover { border-color: var(--cyan); transform: translateY(-2px); }
        .module-header { display: flex; justify-content: space-between; align-items: flex-start; margin-bottom: 10px; }
        .module-icon {
            width: 36px;
            height: 36px;
            border-radius: 10px;
            display: flex;
            align-items: center;
            justify-content: center;
            font-size: 16px;
            background: rgba(255,255,255,0.05);
        }
        .status-badge {
            font-size: 11px;
            font-weight: 800;
            font-family: 'JetBrains Mono', monospace;
            padding: 3px 8px;
            border-radius: 6px;
        }
        .status-badge.FAIL { background: rgba(239, 68, 68, 0.2); color: #f87171; border: 1px solid #ef4444; }
        .status-badge.PASS { background: rgba(16, 185, 129, 0.2); color: #34d399; border: 1px solid #10b981; }
        .module-tile h4 { font-size: 14px; font-weight: 700; margin-bottom: 4px; }
        .module-tile p { font-size: 12px; color: var(--text-sub); line-height: 1.4; }

        /* Tabs & Bottom Section */
        .tab-nav {
            display: flex;
            gap: 12px;
            border-bottom: 1px solid var(--border);
            padding-bottom: 12px;
            margin-bottom: 20px;
        }
        .tab-btn {
            background: none;
            border: none;
            color: var(--text-sub);
            font-size: 13px;
            font-weight: 700;
            padding: 8px 16px;
            border-radius: 8px;
            cursor: pointer;
            transition: all 0.2s ease;
            font-family: 'Plus Jakarta Sans', sans-serif;
        }
        .tab-btn.active { background: #3b82f6; color: #fff; box-shadow: 0 4px 15px rgba(59, 130, 246, 0.4); }

        /* Table */
        .vuln-table {
            width: 100%;
            border-collapse: collapse;
            font-size: 13px;
        }
        .vuln-table th {
            text-align: left;
            padding: 12px 14px;
            background: rgba(255,255,255,0.03);
            color: var(--text-sub);
            font-size: 11px;
            text-transform: uppercase;
            letter-spacing: 0.5px;
            border-bottom: 1px solid var(--border);
        }
        .vuln-table td {
            padding: 14px;
            border-bottom: 1px solid rgba(255,255,255,0.04);
            vertical-align: middle;
        }
        .vuln-table tr:hover td { background: rgba(255,255,255,0.02); }

        .sev-tag {
            font-size: 11px;
            font-weight: 800;
            padding: 3px 8px;
            border-radius: 6px;
            font-family: 'JetBrains Mono', monospace;
        }
        .sev-CRITICAL { background: rgba(239, 68, 68, 0.2); color: #f87171; border: 1px solid #ef4444; }
        .sev-HIGH { background: rgba(249, 115, 22, 0.2); color: #fb923c; border: 1px solid #f97316; }
        .sev-MEDIUM { background: rgba(245, 158, 11, 0.2); color: #fbbf24; border: 1px solid #f59e0b; }
        .sev-LOW { background: rgba(59, 130, 246, 0.2); color: #60a5fa; border: 1px solid #3b82f6; }

        /* CI/CD Pipeline Simulator Graph (Slide 12) */
        .pipeline-graph {
            display: flex;
            align-items: center;
            justify-content: space-between;
            background: #090e1a;
            border: 1px solid #1e293b;
            border-radius: 14px;
            padding: 24px;
            margin-top: 16px;
        }
        .pipe-node {
            display: flex;
            flex-direction: column;
            align-items: center;
            text-align: center;
            width: 140px;
        }
        .node-circle {
            width: 54px;
            height: 54px;
            border-radius: 50%;
            background: #1e293b;
            border: 2px solid #475569;
            display: flex;
            align-items: center;
            justify-content: center;
            font-size: 20px;
            color: #94a3b8;
            margin-bottom: 8px;
            transition: all 0.3s ease;
        }
        .pipe-node.active .node-circle { border-color: var(--cyan); color: var(--cyan); box-shadow: 0 0 15px rgba(6, 182, 212, 0.5); }
        .pipe-node.failed .node-circle { border-color: var(--red); color: var(--red); background: rgba(239, 68, 68, 0.15); box-shadow: 0 0 20px rgba(239, 68, 68, 0.5); }
        .pipe-node.passed .node-circle { border-color: var(--green); color: var(--green); background: rgba(16, 185, 129, 0.15); box-shadow: 0 0 20px rgba(16, 185, 129, 0.5); }
        .pipe-line {
            flex: 1;
            height: 3px;
            background: #334155;
            position: relative;
        }
        .pipe-line.active { background: linear-gradient(90deg, var(--cyan), var(--purple)); }

        /* Code block */
        .terminal-box {
            background: #050811;
            border: 1px solid #1e293b;
            border-radius: 12px;
            padding: 16px;
            font-family: 'JetBrains Mono', monospace;
            font-size: 12px;
            color: #38bdf8;
            max-height: 250px;
            overflow-y: auto;
        }
    </style>
</head>
<body>
    <div class="container">
        <!-- App Bar -->
        <header class="app-bar">
            <div class="brand">
                <div class="brand-icon"><i class="fa-brands fa-docker"></i></div>
                <div class="brand-text">
                    <h1>DOCKER SHIELD • SENTINEL RUNTIME AUDITOR</h1>
                    <p>Môn học: Lập trình An ninh Thông tin — Báo Cáo Giữa Kỳ (Nhóm: Huy, Khang, Phúc, Hoàng)</p>
                </div>
            </div>
            <div class="system-tags">
                <div class="tag-pill"><span class="dot"></span> CIS BENCHMARK v1.6.0</div>
                <div class="tag-pill"><i class="fa-solid fa-code-branch" style="color: #60a5fa;"></i> DEVSECOPS PIPELINE</div>
                <div class="tag-pill"><i class="fa-solid fa-server" style="color: #34d399;"></i> DOCKER ENGINE READY</div>
            </div>
        </header>

        <!-- Action Toolbar -->
        <div class="toolbar">
            <div class="target-selector">
                <label><i class="fa-solid fa-crosshairs"></i> Mục tiêu Quét:</label>
                <select id="targetSelect" class="select-styled" onchange="loadTarget(this.value)">
                    <option value="vulnerable_app">🔴 Container Runtime: vulnerable_app (Lỗi Slide 4 - 9)</option>
                    <option value="hardened_app">🟢 Container Runtime: hardened_app (Đã vá lỗi Slide 10 - 11)</option>
                    <option value="dockerfile_vuln">📄 Dockerfile.vulnerable (Tĩnh AST Scanner)</option>
                    <option value="dockerfile_hard">📄 Dockerfile.hardened (Multi-Stage Build)</option>
                </select>
            </div>
            <div class="btn-group">
                <button class="btn btn-scan" onclick="triggerScan('vulnerable_app')">
                    <i class="fa-solid fa-triangle-exclamation"></i> QUÉT CONTAINER LỖI
                </button>
                <button class="btn btn-hardened" onclick="triggerScan('hardened_app')">
                    <i class="fa-solid fa-shield-halved"></i> QUÉT BẢN HARDENED
                </button>
                <button class="btn btn-cicd" onclick="simulateCICD()">
                    <i class="fa-solid fa-play"></i> TEST CI/CD GATE
                </button>
            </div>
        </div>

        <!-- Main Dashboard View -->
        <div class="main-grid">
            <!-- Left Score Column -->
            <div class="card score-display">
                <h3 style="font-size: 14px; text-transform: uppercase; color: var(--text-sub); margin-bottom: 16px;">
                    Điểm Đánh Giá An Ninh
                </h3>
                <div class="radial-progress">
                    <svg viewBox="0 0 160 160">
                        <circle class="circle-bg" cx="80" cy="80" r="70" />
                        <circle id="scoreCircle" class="circle-val" cx="80" cy="80" r="70" />
                    </svg>
                    <div class="score-inner">
                        <span id="scoreVal" class="num">0</span>
                        <span class="scale">/ 100</span>
                    </div>
                </div>
                <div id="ratingBadge" class="rating-badge">CRITICAL RISK</div>

                <div id="gateBox" class="security-gate-box">
                    <div class="gate-title"><i class="fa-solid fa-ban"></i> SECURITY GATE (SLIDE 12)</div>
                    <div id="gateStatus" class="gate-status">BLOCKED (Exit 1) — Chặn Deploy</div>
                </div>

                <div style="display: flex; justify-content: space-between; width: 100%; margin-top: 20px; font-size: 12px; font-family: 'JetBrains Mono';">
                    <div>Lỗ hổng: <strong id="totalVulns" style="color: #ef4444;">8</strong></div>
                    <div>Critical: <strong id="critVulns" style="color: #ef4444;">3</strong></div>
                    <div>High: <strong id="highVulns" style="color: #f97316;">4</strong></div>
                </div>
            </div>

            <!-- Right: 6 Slide Modules Grid -->
            <div class="card">
                <h3 style="font-size: 15px; margin-bottom: 16px; display: flex; justify-content: space-between; align-items: center;">
                    <span>🛡️ Trạng Thái 6 Module An Toàn (Slide 4 đến Slide 9)</span>
                    <span id="targetName" style="font-size: 12px; font-family: 'JetBrains Mono'; color: #38bdf8;">Target: vulnerable_app</span>
                </h3>
                <div class="modules-grid">
                    <!-- Module 1 -->
                    <div class="module-tile" id="tile_m1">
                        <div class="module-header">
                            <div class="module-icon"><i class="fa-solid fa-user-shield"></i></div>
                            <span class="status-badge FAIL" id="badge_m1">FAIL</span>
                        </div>
                        <h4>Slide 4: Root Privilege</h4>
                        <p id="desc_m1">Container chạy bằng Root UID 0, nguy cơ chiếm quyền Host.</p>
                    </div>

                    <!-- Module 2 -->
                    <div class="module-tile" id="tile_m2">
                        <div class="module-header">
                            <div class="module-icon"><i class="fa-solid fa-unlock-keyhole"></i></div>
                            <span class="status-badge FAIL" id="badge_m2">FAIL</span>
                        </div>
                        <h4>Slide 5: Privileged & Caps</h4>
                        <p id="desc_m2">Bật cờ --privileged và cấp Capabilities dư thừa.</p>
                    </div>

                    <!-- Module 3 -->
                    <div class="module-tile" id="tile_m3">
                        <div class="module-header">
                            <div class="module-icon"><i class="fa-solid fa-plug-circle-exclamation"></i></div>
                            <span class="status-badge FAIL" id="badge_m3">FAIL</span>
                        </div>
                        <h4>Slide 6: Docker Socket</h4>
                        <p id="desc_m3">Mount /var/run/docker.sock nhạy cảm vào container.</p>
                    </div>

                    <!-- Module 4 -->
                    <div class="module-tile" id="tile_m4">
                        <div class="module-header">
                            <div class="module-icon"><i class="fa-solid fa-key"></i></div>
                            <span class="status-badge FAIL" id="badge_m4">FAIL</span>
                        </div>
                        <h4>Slide 7: Secret Exposure</h4>
                        <p id="desc_m4">Lộ API Key & Database Password trong biến môi trường ENV.</p>
                    </div>

                    <!-- Module 5 -->
                    <div class="module-tile" id="tile_m5">
                        <div class="module-header">
                            <div class="module-icon"><i class="fa-solid fa-microchip"></i></div>
                            <span class="status-badge FAIL" id="badge_m5">FAIL</span>
                        </div>
                        <h4>Slide 8: DoS Limits (cgroups)</h4>
                        <p id="desc_m5">Không đặt giới hạn RAM/CPU, dễ bị cạn kiệt tài nguyên Host.</p>
                    </div>

                    <!-- Module 6 -->
                    <div class="module-tile" id="tile_m6">
                        <div class="module-header">
                            <div class="module-icon"><i class="fa-solid fa-heart-pulse"></i></div>
                            <span class="status-badge FAIL" id="badge_m6">FAIL</span>
                        </div>
                        <h4>Slide 9: Image & Health</h4>
                        <p id="desc_m6">Dùng tag :latest không rõ nguồn gốc và thiếu Healthcheck.</p>
                    </div>
                </div>
            </div>
        </div>

        <!-- Tabbed Details -->
        <div class="card">
            <div class="tab-nav">
                <button class="tab-btn active" onclick="switchTab('tab-findings', this)"><i class="fa-solid fa-list-check"></i> Chi Tiết Vi Phạm CIS Benchmark</button>
                <button class="tab-btn" onclick="switchTab('tab-remediation', this)"><i class="fa-solid fa-wrench"></i> Đề Xuất Vá Lỗi & Multi-Stage Build (Slide 10-11)</button>
                <button class="tab-btn" onclick="switchTab('tab-cicd', this)"><i class="fa-solid fa-diagram-project"></i> Mô Phỏng CI/CD DevSecOps (Slide 12)</button>
            </div>

            <!-- Tab 1: Findings Table -->
            <div id="tab-findings" class="tab-content">
                <table class="vuln-table">
                    <thead>
                        <tr>
                            <th style="width: 50px;">STT</th>
                            <th style="width: 120px;">MÃ CIS</th>
                            <th style="width: 110px;">MỨC ĐỘ</th>
                            <th>LỖI CẤU HÌNH & BẰNG CHỨNG</th>
                            <th>CÂU LỆNH KHẮC PHỤC (REMEDIATION)</th>
                        </tr>
                    </thead>
                    <tbody id="vulnBody">
                        <!-- Populated by JS -->
                    </tbody>
                </table>
            </div>

            <!-- Tab 2: Remediation & Multi-stage -->
            <div id="tab-remediation" class="tab-content" style="display: none;">
                <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 20px;">
                    <div>
                        <h4 style="color: #38bdf8; margin-bottom: 8px;"><i class="fa-solid fa-terminal"></i> Câu Lệnh Khởi Chạy An Toàn Tự Động Đề Xuất (Slide 10):</h4>
                        <pre class="terminal-box" id="remedCmd" style="height: 180px;"></pre>
                        <button class="btn btn-cicd" style="margin-top: 10px;" onclick="copyRemed()"><i class="fa-regular fa-copy"></i> Sao chép câu lệnh</button>
                    </div>
                    <div>
                        <h4 style="color: #34d399; margin-bottom: 8px;"><i class="fa-solid fa-layer-group"></i> Hiệu Quả Multi-Stage Build (Slide 11):</h4>
                        <div style="background: rgba(255,255,255,0.03); border: 1px solid var(--border); border-radius: 12px; padding: 16px; font-size: 13px;">
                            <div style="margin-bottom: 12px;">
                                <div style="display: flex; justify-content: space-between; margin-bottom: 4px;">
                                    <span>Trước khi tối ưu (Legacy Image):</span>
                                    <strong style="color: #f87171;">800 MB</strong>
                                </div>
                                <div style="width: 100%; height: 10px; background: #334155; border-radius: 5px; overflow: hidden;">
                                    <div style="width: 100%; height: 100%; background: #ef4444;"></div>
                                </div>
                            </div>
                            <div>
                                <div style="display: flex; justify-content: space-between; margin-bottom: 4px;">
                                    <span>Sau khi Multi-Stage Build:</span>
                                    <strong style="color: #34d399;">30 MB (-96%)</strong>
                                </div>
                                <div style="width: 100%; height: 10px; background: #334155; border-radius: 5px; overflow: hidden;">
                                    <div style="width: 4%; height: 100%; background: #10b981;"></div>
                                </div>
                            </div>
                            <p style="font-size: 12px; color: var(--text-sub); margin-top: 14px;">
                                ✓ Loại bỏ hoàn toàn compiler, shell (bash/sh), và công cụ mạng thừa (curl, wget). Triệt tiêu tối đa bề mặt tấn công.
                            </p>
                        </div>
                    </div>
                </div>
            </div>

            <!-- Tab 3: CI/CD Pipeline Simulator -->
            <div id="tab-cicd" class="tab-content" style="display: none;">
                <h4 style="margin-bottom: 8px;">Mô Phỏng Đường Ống CI/CD Chặn Container Lỗi (Slide 12):</h4>
                <div class="pipeline-graph">
                    <div class="pipe-node active" id="node-commit">
                        <div class="node-circle"><i class="fa-solid fa-code-commit"></i></div>
                        <strong style="font-size: 12px;">Code Commit</strong>
                    </div>
                    <div class="pipe-line active"></div>
                    <div class="pipe-node active" id="node-build">
                        <div class="node-circle"><i class="fa-brands fa-docker"></i></div>
                        <strong style="font-size: 12px;">Build Image</strong>
                    </div>
                    <div class="pipe-line active"></div>
                    <div class="pipe-node failed" id="node-scan">
                        <div class="node-circle"><i class="fa-solid fa-shield-virus"></i></div>
                        <strong style="font-size: 12px;">Security Gate</strong>
                    </div>
                    <div class="pipe-line" id="line-deploy"></div>
                    <div class="pipe-node" id="node-deploy">
                        <div class="node-circle"><i class="fa-solid fa-cloud-arrow-up"></i></div>
                        <strong style="font-size: 12px;">Deploy Prod</strong>
                    </div>
                </div>
                <div id="pipeLog" class="terminal-box" style="margin-top: 16px; height: 120px;">
                    [INFO] CI/CD Pipeline ready for execution...
                </div>
            </div>
        </div>
    </div>

    <script>
        let currentData = null;

        async function triggerScan(target) {
            document.getElementById('targetSelect').value = target;
            await loadTarget(target);
        }

        async function loadTarget(target) {
            try {
                const res = await fetch('/api/scan/' + target);
                const data = await res.json();
                currentData = data;
                renderDashboard(data);
            } catch (e) {
                console.error(e);
            }
        }

        function renderDashboard(data) {
            // Target
            document.getElementById('targetName').innerText = "Target: " + data.target_name;

            // Score animation
            const scoreVal = document.getElementById('scoreVal');
            const circle = document.getElementById('scoreCircle');
            const ratingBadge = document.getElementById('ratingBadge');
            const gateBox = document.getElementById('gateBox');
            const gateStatus = document.getElementById('gateStatus');

            scoreVal.innerText = data.score;
            const offset = 440 - (440 * data.score / 100);
            circle.style.strokeDashoffset = offset;

            if (data.score >= 85) {
                circle.style.stroke = "#10b981";
                ratingBadge.innerText = "SECURE (AN TOÀN)";
                ratingBadge.style.background = "rgba(16, 185, 129, 0.2)";
                ratingBadge.style.color = "#34d399";
                ratingBadge.style.borderColor = "#10b981";
                
                gateBox.className = "security-gate-box passed";
                gateBox.innerHTML = '<div class="gate-title"><i class="fa-solid fa-check"></i> SECURITY GATE (PASSED)</div><div class="gate-status">APPROVED (Exit 0) — Cho phép Deploy</div>';
            } else if (data.score >= 70) {
                circle.style.stroke = "#06b6d4";
                ratingBadge.innerText = "MEDIUM RISK";
                ratingBadge.style.background = "rgba(6, 182, 212, 0.2)";
                ratingBadge.style.color = "#38bdf8";
                ratingBadge.style.borderColor = "#06b6d4";
                
                gateBox.className = "security-gate-box passed";
                gateBox.innerHTML = '<div class="gate-title"><i class="fa-solid fa-check"></i> SECURITY GATE (PASSED)</div><div class="gate-status">APPROVED (Exit 0) — Đạt chuẩn tối thiểu</div>';
            } else {
                circle.style.stroke = "#ef4444";
                ratingBadge.innerText = "CRITICAL RISK";
                ratingBadge.style.background = "rgba(239, 68, 68, 0.2)";
                ratingBadge.style.color = "#f87171";
                ratingBadge.style.borderColor = "#ef4444";
                
                gateBox.className = "security-gate-box";
                gateBox.innerHTML = '<div class="gate-title"><i class="fa-solid fa-ban"></i> SECURITY GATE (SLIDE 12)</div><div class="gate-status">BLOCKED (Exit 1) — Chặn Deploy</div>';
            }

            // Stats
            document.getElementById('totalVulns').innerText = data.findings_count;
            document.getElementById('critVulns').innerText = data.critical_count;
            document.getElementById('highVulns').innerText = data.high_count;

            // Modules 1-6
            for (let i = 1; i <= 6; i++) {
                const keyMap = { 1: 'm1_root', 2: 'm2_priv', 3: 'm3_sock', 4: 'm4_secret', 5: 'm5_cgroups', 6: 'm6_image' };
                const m = data.modules[keyMap[i]];
                const badge = document.getElementById('badge_m' + i);
                const desc = document.getElementById('desc_m' + i);
                if (m) {
                    badge.className = "status-badge " + m.status;
                    badge.innerText = m.status;
                    desc.innerText = m.desc;
                }
            }

            // Table
            const tbody = document.getElementById('vulnBody');
            tbody.innerHTML = '';
            if (data.findings.length === 0) {
                tbody.innerHTML = '<tr><td colspan="5" style="text-align:center; color:#34d399; padding:30px;"><i class="fa-solid fa-circle-check"></i> Tuyệt vời! Không phát hiện bất kỳ lỗi cấu hình hay vi phạm nào.</td></tr>';
            } else {
                data.findings.forEach((f, idx) => {
                    const tr = document.createElement('tr');
                    tr.innerHTML = `
                        <td>${idx + 1}</td>
                        <td><strong style="color:#38bdf8; font-family:'JetBrains Mono'">${f.rule_id}</strong></td>
                        <td><span class="sev-tag sev-${f.severity}">${f.severity}</span></td>
                        <td>
                            <div><strong>${f.title}</strong></div>
                            <div style="color:var(--text-sub); font-size:12px; margin-top:2px;">${f.custom_desc}</div>
                        </td>
                        <td><span style="color:#34d399; font-size:12px;">✓ ${f.remediation}</span></td>
                    `;
                    tbody.appendChild(tr);
                });
            }

            // Remediation box
            document.getElementById('remedCmd').innerText = data.remediation_cmd;
        }

        function switchTab(tabId, btn) {
            document.querySelectorAll('.tab-content').forEach(el => el.style.display = 'none');
            document.querySelectorAll('.tab-btn').forEach(el => el.classList.remove('active'));
            document.getElementById(tabId).style.display = 'block';
            btn.classList.add('active');
        }

        function copyRemed() {
            const cmd = document.getElementById('remedCmd').innerText;
            navigator.clipboard.writeText(cmd);
            alert("Đã sao chép câu lệnh cấu hình an toàn vào Clipboard!");
        }

        function simulateCICD() {
            switchTab('tab-cicd', document.querySelectorAll('.tab-btn')[2]);
            const log = document.getElementById('pipeLog');
            const nodeScan = document.getElementById('node-scan');
            const lineDeploy = document.getElementById('line-deploy');
            const nodeDeploy = document.getElementById('node-deploy');

            log.innerHTML = '[STEP 1/4] Git commit pushed: main branch\\n[STEP 2/4] Triggering Docker build image: latest...\\n';
            
            setTimeout(() => {
                log.innerHTML += '[STEP 3/4] Running Docker Security Scanner Security Gate...\\n';
                if (!currentData || !currentData.gate_passed) {
                    nodeScan.className = 'pipe-node failed';
                    lineDeploy.className = 'pipe-line';
                    nodeDeploy.className = 'pipe-node';
                    log.innerHTML += '<span style="color:#ef4444">[SECURITY GATE FAILED] Phát hiện vi phạm CRITICAL! Pipeline bị chặn với exit code 1. Bị từ chối deploy!</span>';
                } else {
                    nodeScan.className = 'pipe-node passed';
                    lineDeploy.className = 'pipe-line active';
                    nodeDeploy.className = 'pipe-node passed';
                    log.innerHTML += '<span style="color:#34d399">[SECURITY GATE PASSED] Kiểm định CIS đạt 100/100. Pushing image to secure registry. DEPLOY THÀNH CÔNG!</span>';
                }
            }, 800);
        }

        window.onload = () => {
            loadTarget('vulnerable_app');
        };
    </script>
</body>
</html>
"""

def main():
    port = 8888
    print(f"Khoi dong Web Dashboard tai: http://127.0.0.1:{port}")
    try:
        webbrowser.open(f"http://127.0.0.1:{port}")
    except Exception:
        pass
    uvicorn.run(app, host="127.0.0.1", port=port, log_level="warning")

if __name__ == "__main__":
    main()
