"""
DOCKER SECURITY CONFIGURATION & RISK SCANNER
Mon hoc: Lap trinh An ninh Thong tin
De tai: Xay dung cong cu kiem tra cau hinh va phat hien rui ro Docker
Nhom: Pham Gia Huy, Tran Minh Khang, Nguyen Phi Phuc, Vo Le Nhat Hoang
"""

import os
import sys
import json
import re
import argparse
from typing import Dict, List, Any
from datetime import datetime

try:
    from colorama import init, Fore, Back, Style
    init(autoreset=True)
    HAS_COLORAMA = True
except ImportError:
    HAS_COLORAMA = False
    class DummyColor:
        def __getattr__(self, name):
            return ""
    Fore = Back = Style = DummyColor()

# CIS Benchmark Rule Definitions
RULES = {
    "CIS-4.1": {
        "title": "Chay Container bang quyen Root (UID 0)",
        "module": "Module 1 (Slide 4): Root User Check",
        "severity": "CRITICAL",
        "penalty": 25,
        "description": "Container khong chi dinh USER hoac chay voi UID 0. Ke tan cong co the loi dung de chiem quyen Host.",
        "remediation": "Them 'USER appuser' vao Dockerfile hoac truyen '--user 1001:1001' khi docker run."
    },
    "CIS-5.2": {
        "title": "Su dung co Privileged cap toan quyen phan cung",
        "module": "Module 2 (Slide 5): Privileged & Capabilities",
        "severity": "CRITICAL",
        "penalty": 30,
        "description": "Co --privileged go bo moi lop vo cach ly, cho phep Container truy cap truc tiep vao /dev va hardware Host.",
        "remediation": "Tuyet doi khong dung '--privileged'. Thay vao do chi cap quyen can thiet qua '--cap-add'."
    },
    "CIS-5.3": {
        "title": "Chua han che Linux Capabilities du thua",
        "module": "Module 2 (Slide 5): Privileged & Capabilities",
        "severity": "HIGH",
        "penalty": 15,
        "description": "Container chua ap dung --cap-drop=ALL, cac capability mac dinh co the bi khai thac de Container Escape.",
        "remediation": "Su dung '--cap-drop=ALL' va chi them capability toi thieu nhu '--cap-add=NET_BIND_SERVICE'."
    },
    "CIS-5.31": {
        "title": "Gan ket Docker Socket (/var/run/docker.sock)",
        "module": "Module 3 (Slide 6): Docker Socket & Volume Mounts",
        "severity": "CRITICAL",
        "penalty": 30,
        "description": "Mount docker.sock cho phep Container giao tiep truc tiep Docker Daemon de spawn container doc hai chiem Host.",
        "remediation": "Go bo mount '/var/run/docker.sock'. Su dung Docker API proxy co xac thuc neu bat buoc phai goi API."
    },
    "CIS-4.6": {
        "title": "Lo lot Secret / API Key trong Image hoac Bien moi truong",
        "module": "Module 4 (Slide 7): Hardcoded Secrets",
        "severity": "HIGH",
        "penalty": 20,
        "description": "Phat hien Password, API Key, Token ghi cung trong ENV/Dockerfile. Secret de bi trich xuat qua 'docker history'.",
        "remediation": "Su dung Docker Secrets, HashiCorp Vault hoac mount file secret duoi dang tmpfs."
    },
    "CIS-5.10": {
        "title": "Thieu cau hinh gioi han Bo nho RAM (cgroups)",
        "module": "Module 5 (Slide 8): Resource Limits DoS",
        "severity": "HIGH",
        "penalty": 15,
        "description": "Khong dat gioi han Memory, Container co the bi loi Memory Leak hoac bi tan cong gay OOM sập Host.",
        "remediation": "Cau hinh '--memory=512m' hoac gioi han trong file docker-compose.yml."
    },
    "CIS-5.11": {
        "title": "Thieu cau hinh dinh muc CPU (cgroups)",
        "module": "Module 5 (Slide 8): Resource Limits DoS",
        "severity": "HIGH",
        "penalty": 15,
        "description": "Khong gioi han CPU, ma doc co the chay Fork-bomb hoac dao tien ao chiem 100% CPU Host.",
        "remediation": "Cau hinh '--cpus=1.0' hoac '--cpu-quota' de kiem soat tai nguyen."
    },
    "CIS-4.2": {
        "title": "Su dung Base Image voi the :latest khong co dinh",
        "module": "Module 6 (Slide 9): Base Image & Network",
        "severity": "MEDIUM",
        "penalty": 10,
        "description": "Tag :latest de bi thay doi ma nguon bat ngo, tao rui ro Supply Chain Attack hoac chua san ma doc.",
        "remediation": "Ghim phien ban cu the va su dung sha256 digest: 'node:20.11-alpine@sha256:...'"
    },
    "CIS-4.6-HEALTH": {
        "title": "Thieu co che giam sat trang thai HEALTHCHECK",
        "module": "Module 6 (Slide 9): Base Image & Network",
        "severity": "LOW",
        "penalty": 5,
        "description": "Thieu HEALTHCHECK khien Docker khong the phat hien Container bi treo, zombie hoac bi chiem quyen.",
        "remediation": "Khai bao 'HEALTHCHECK --interval=30s --timeout=5s CMD curl -f http://localhost:8080/health || exit 1'"
    }
}

class DockerSecurityScanner:
    def __init__(self):
        self.findings = []
        self.score = 100
        self.target_name = ""
        self.scan_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    def analyze_dockerfile(self, content: str, filename: str = "Dockerfile"):
        self.target_name = filename
        lines = content.splitlines()

        has_user = False
        has_healthcheck = False
        uses_latest = False
        secrets_found = []

        secret_patterns = [
            (r'(?i)(API[_-]?KEY|SECRET[_-]?KEY|ACCESS[_-]?TOKEN|PASSWORD|PASS|DB_PASS)\s*[:=]\s*[\'"]?([a-zA-Z0-9_\-@#$%^&*]{6,})[\'"]?', "Hardcoded Credential")
        ]

        for idx, line in enumerate(lines, start=1):
            line_strip = line.strip()
            if not line_strip or line_strip.startswith('#'):
                continue

            # Slide 4: Check USER
            if re.match(r'^USER\s+', line_strip, re.IGNORECASE):
                user_val = re.sub(r'^USER\s+', '', line_strip, flags=re.IGNORECASE).strip()
                if user_val and user_val not in ['0', 'root', '0:0']:
                    has_user = True

            # Slide 9: Check HEALTHCHECK
            if re.match(r'^HEALTHCHECK\s+', line_strip, re.IGNORECASE):
                has_healthcheck = True

            # Slide 9: Check Base image :latest
            if re.match(r'^FROM\s+', line_strip, re.IGNORECASE):
                from_val = re.sub(r'^FROM\s+', '', line_strip, flags=re.IGNORECASE).split()[0]
                if ':latest' in from_val or (':' not in from_val and '@' not in from_val):
                    uses_latest = True

            # Slide 7: Check Hardcoded Secrets
            for pat, desc in secret_patterns:
                match = re.search(pat, line_strip)
                if match and not any(kw in line_strip.lower() for kw in ['example', 'placeholder', '${']):
                    secrets_found.append((idx, match.group(1), match.group(2)[:3] + "****"))

        # Evaluate rules
        if not has_user:
            self._add_finding("CIS-4.1", "Khong tim thay chi thi 'USER' hop le trong Dockerfile (Mac dinh Container chay voi ROOT)")

        if secrets_found:
            details = ", ".join([f"Dong {ln}: {k}={v}" for ln, k, v in secrets_found])
            self._add_finding("CIS-4.6", f"Phat hien bi mat ghi cung trong Dockerfile: {details}")

        if uses_latest:
            self._add_finding("CIS-4.2", "Base Image dang su dung tag mac dinh ':latest' hoac khong co dinh version")

        if not has_healthcheck:
            self._add_finding("CIS-4.6-HEALTH", "Dockerfile chua khai bao chi thi HEALTHCHECK")

    def analyze_inspect_json(self, data: Dict[str, Any], target_name: str = "Container Inspect"):
        self.target_name = target_name
        config = data.get("Config", {})
        host_config = data.get("HostConfig", {})

        # Slide 4: Root user
        user = config.get("User", "")
        if not user or user in ["0", "root", "0:0"]:
            self._add_finding("CIS-4.1", f"Container dang chay bang quyen Root (Config.User='{user or 'DEFAULT_ROOT'}')")

        # Slide 5: Privileged
        if host_config.get("Privileged") is True:
            self._add_finding("CIS-5.2", "Container duoc khoi chay voi co HostConfig.Privileged = true")

        # Slide 5: Capabilities
        cap_add = host_config.get("CapAdd") or []
        cap_drop = host_config.get("CapDrop") or []
        if "ALL" in [c.upper() for c in cap_add] or "SYS_ADMIN" in [c.upper() for c in cap_add]:
            self._add_finding("CIS-5.3", f"Container duoc cap cac Linux Capability nguy hiem: {cap_add}")
        elif "ALL" not in [c.upper() for c in cap_drop]:
            self._add_finding("CIS-5.3", "Container chua go bo toan bo Linux Capabilities mac dinh (--cap-drop=ALL)")

        # Slide 6: Docker socket & volume mounts
        binds = host_config.get("Binds") or []
        mounts = data.get("Mounts") or []
        has_sock = False
        for b in binds:
            if "/var/run/docker.sock" in str(b):
                has_sock = True
        for m in mounts:
            if "/var/run/docker.sock" in str(m.get("Source", "")):
                has_sock = True
        if has_sock:
            self._add_finding("CIS-5.31", "Phat hien file nhay cam /var/run/docker.sock duoc gan ket (mount) vao trong Container")

        # Slide 7: Secrets in Env
        envs = config.get("Env") or []
        secret_keys = ["API_KEY", "SECRET", "PASSWORD", "PASS", "DB_PASS", "AWS_SECRET"]
        found_env_secrets = []
        for e in envs:
            for sk in secret_keys:
                if re.match(rf'^{sk}=', e, re.IGNORECASE):
                    k, _, v = e.partition("=")
                    found_env_secrets.append(f"{k}={v[:3]}****")
        if found_env_secrets:
            self._add_finding("CIS-4.6", f"Phat hien bien moi truong chua khoa bi mat/mat khau: {', '.join(found_env_secrets)}")

        # Slide 8: Resource limits (cgroups)
        memory = host_config.get("Memory", 0)
        nano_cpus = host_config.get("NanoCpus", 0)
        cpu_quota = host_config.get("CpuQuota", 0)

        if memory == 0:
            self._add_finding("CIS-5.10", "Khong gioi han Bo nho RAM (HostConfig.Memory = 0), co nguy co bi tan cong DoS gay OOM")

        if nano_cpus == 0 and cpu_quota == 0:
            self._add_finding("CIS-5.11", "Khong gioi han dinh muc CPU (HostConfig.NanoCpus/CpuQuota = 0), nguy co bi chiem dung 100% CPU")

        # Slide 9: Healthcheck
        if not config.get("Healthcheck"):
            self._add_finding("CIS-4.6-HEALTH", "Khong tim thay co che Healthcheck trong cau hinh Container")

    def _add_finding(self, rule_id: str, custom_desc: str = ""):
        rule = RULES.get(rule_id, {})
        self.findings.append({
            "rule_id": rule_id,
            "title": rule.get("title", rule_id),
            "module": rule.get("module", ""),
            "severity": rule.get("severity", "MEDIUM"),
            "penalty": rule.get("penalty", 10),
            "custom_desc": custom_desc or rule.get("description", ""),
            "remediation": rule.get("remediation", "")
        })
        self.score -= rule.get("penalty", 10)
        if self.score < 0:
            self.score = 0

    def print_terminal_report(self, is_ci: bool = False, fail_threshold: int = 70):
        print(f"\n{Fore.CYAN}{Style.BRIGHT}{'='*80}")
        print(f"{Fore.YELLOW}{Style.BRIGHT}  HE THONG KIEM TRA AN NINH & DANH GIA RUI RO CAU HINH DOCKER")
        print(f"{Fore.CYAN}  Mon hoc: Lap trinh An ninh Thong tin - Nhom Sinh vien Thuc hien")
        print(f"{Fore.CYAN}{'='*80}{Style.RESET_ALL}\n")

        print(f"Target Scan : {Fore.WHITE}{Style.BRIGHT}{self.target_name}{Style.RESET_ALL}")
        print(f"Thoi gian   : {Fore.WHITE}{self.scan_time}{Style.RESET_ALL}")
        print(f"Chuan kiem  : {Fore.GREEN}CIS Docker Community Edition Benchmark v1.6.0{Style.RESET_ALL}")
        print(f"So loi phat hien: {Fore.RED if self.findings else Fore.GREEN}{len(self.findings)} vi pham{Style.RESET_ALL}\n")

        # Table Header
        print(f"{Back.BLUE}{Fore.WHITE}{Style.BRIGHT} {'STT':^4} | {'MA CIS':^10} | {'MUC DO':^10} | {'LOI / NGUY CO PHAT HIEN':<45} {Style.RESET_ALL}")
        print(f"{Fore.BLUE}{'-'*80}{Style.RESET_ALL}")

        if not self.findings:
            print(f"{Fore.GREEN}{Style.BRIGHT}  [OK] XUAT SAC! Khong phat hien bat ky rui ro cau hinh nao.{Style.RESET_ALL}\n")
        else:
            for idx, f in enumerate(self.findings, start=1):
                sev = f['severity']
                if sev == "CRITICAL":
                    sev_color = f"{Back.RED}{Fore.WHITE}{Style.BRIGHT} CRITICAL {Style.RESET_ALL}"
                elif sev == "HIGH":
                    sev_color = f"{Fore.RED}{Style.BRIGHT}   HIGH   {Style.RESET_ALL}"
                elif sev == "MEDIUM":
                    sev_color = f"{Fore.YELLOW}{Style.BRIGHT}  MEDIUM  {Style.RESET_ALL}"
                else:
                    sev_color = f"{Fore.BLUE}{Style.BRIGHT}   LOW    {Style.RESET_ALL}"

                title_trunc = (f['title'][:42] + '...') if len(f['title']) > 45 else f['title']
                print(f" {idx:^4} | {f['rule_id']:^10} | {sev_color} | {Fore.WHITE}{title_trunc:<45}{Style.RESET_ALL}")
                print(f"      {Fore.BLACK}{Style.BRIGHT}--> Chi tiet: {f['custom_desc']}{Style.RESET_ALL}")
                print(f"      {Fore.GREEN}--> Khac phuc: {f['remediation']}{Style.RESET_ALL}")
                print(f"{Fore.BLUE}{'-'*80}{Style.RESET_ALL}")

        # Score Banner (Slide 10)
        print(f"\n{Style.BRIGHT}{'='*80}")
        if self.score >= 85:
            score_color = f"{Back.GREEN}{Fore.WHITE} DIEM AN NINH: {self.score}/100 - [SECURE - AN TOAN TUYET DOI] "
        elif self.score >= 70:
            score_color = f"{Back.CYAN}{Fore.BLACK} DIEM AN NINH: {self.score}/100 - [MEDIUM RISK - CHAP NHAN DUOC] "
        elif self.score >= 40:
            score_color = f"{Back.YELLOW}{Fore.BLACK} DIEM AN NINH: {self.score}/100 - [HIGH RISK - NGUY CO CAO] "
        else:
            score_color = f"{Back.RED}{Fore.WHITE} DIEM AN NINH: {self.score}/100 - [CRITICAL - CUC KY NGUY HIEM] "
        print(f"{score_color}{Style.RESET_ALL}")
        print(f"{Style.BRIGHT}{'='*80}\n")

        # Remediation command display (Slide 10)
        print(f"{Fore.MAGENTA}{Style.BRIGHT}>>> KHUYEN NGHI CAU LENH KHOI CHAY CHUAN AN NINH (REMEDIATION):{Style.RESET_ALL}")
        print(f"{Fore.CYAN}```bash")
        print("docker run -d \\")
        print("  --name my-hardened-app \\")
        print("  --user 1001:1001 \\")
        print("  --cap-drop=ALL \\")
        print("  --cap-add=NET_BIND_SERVICE \\")
        print("  --security-opt seccomp=profile.json \\")
        print("  --memory=\"512m\" --cpus=\"1.0\" \\")
        print("  --pids-limit 100 \\")
        print("  --read-only \\")
        print("  -v /app/tmp:/tmp:rw,noexec,nosuid \\")
        print("  my-secure-app:v1.0")
        print(f"```{Style.RESET_ALL}\n")

        # CI/CD Security Gate (Slide 12)
        if is_ci:
            print(f"{Fore.YELLOW}{Style.BRIGHT}[CI/CD DEVSECOPS SECURITY GATE CHECK]{Style.RESET_ALL}")
            has_critical = any(f['severity'] == "CRITICAL" for f in self.findings)
            if self.score < fail_threshold or has_critical:
                print(f"{Back.RED}{Fore.WHITE}{Style.BRIGHT} [FAILED] SECURITY GATE DA CHAN CONTAINER NAY! {Style.RESET_ALL}")
                print(f"{Fore.RED}Nguyen nhan: Diem an ninh {self.score} < nguong {fail_threshold} hoac ton tai loi CRITICAL.")
                print(f"{Fore.RED}Ket qua: TU DONG CHAN MERGE VA KHONG CHO PHEP DEPLOY LEN PRODUCTION.{Style.RESET_ALL}")
                return 1
            else:
                print(f"{Back.GREEN}{Fore.WHITE}{Style.BRIGHT} [PASSED] SECURITY GATE CHAP THUAN CONTAINER! {Style.RESET_ALL}")
                print(f"{Fore.GREEN}Ket qua: Dat chuan bao mat. Tien trinh tiep tuc push vao Secure Registry.{Style.RESET_ALL}")
                return 0
        return 0

    def generate_html_report(self, output_path: str = "docker_security_report.html"):
        findings_json = json.dumps(self.findings, ensure_ascii=False)
        has_critical = any(f['severity'] == "CRITICAL" for f in self.findings)
        score_badge = "CRITICAL RISK" if self.score < 40 else ("HIGH RISK" if self.score < 70 else "SECURE")
        badge_color = "#ef4444" if self.score < 40 else ("#f59e0b" if self.score < 70 else "#10b981")

        html_content = f"""<!DOCTYPE html>
<html lang="vi">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Báo Cáo An Ninh Docker - Nhóm Sinh Viên</title>
    <link href="https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;600;700&family=Plus+Jakarta+Sans:wght@400;600;700;800&display=swap" rel="stylesheet">
    <style>
        :root {{
            --bg: #090d16;
            --card-bg: rgba(22, 30, 49, 0.7);
            --border: rgba(255, 255, 255, 0.08);
            --accent: #3b82f6;
            --accent-glow: rgba(59, 130, 246, 0.3);
            --critical: #ef4444;
            --high: #f97316;
            --medium: #f59e0b;
            --low: #3b82f6;
            --pass: #10b981;
            --text-main: #f1f5f9;
            --text-sub: #94a3b8;
        }}
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        body {{
            background: radial-gradient(circle at 10% 20%, #0d172e 0%, var(--bg) 90%);
            color: var(--text-main);
            font-family: 'Plus Jakarta Sans', sans-serif;
            min-height: 100vh;
            padding: 30px 20px;
        }}
        .container {{ max-width: 1200px; margin: 0 auto; }}
        header {{
            display: flex;
            justify-content: space-between;
            align-items: center;
            padding: 24px 32px;
            background: var(--card-bg);
            backdrop-filter: blur(16px);
            border: 1px solid var(--border);
            border-radius: 20px;
            margin-bottom: 24px;
            box-shadow: 0 10px 30px rgba(0,0,0,0.5);
        }}
        .header-title h1 {{
            font-size: 24px;
            font-weight: 800;
            background: linear-gradient(135deg, #60a5fa, #a78bfa);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
        }}
        .header-title p {{ color: var(--text-sub); font-size: 13px; margin-top: 4px; }}
        .header-meta {{ text-align: right; font-family: 'JetBrains Mono', monospace; font-size: 12px; color: var(--text-sub); }}
        
        .grid-stats {{
            display: grid;
            grid-template-columns: 320px 1fr;
            gap: 24px;
            margin-bottom: 24px;
        }}
        .card {{
            background: var(--card-bg);
            backdrop-filter: blur(16px);
            border: 1px solid var(--border);
            border-radius: 20px;
            padding: 24px;
            box-shadow: 0 10px 30px rgba(0,0,0,0.3);
        }}
        .score-box {{
            display: flex;
            flex-direction: column;
            align-items: center;
            justify-content: center;
            text-align: center;
            position: relative;
        }}
        .score-circle {{
            width: 160px;
            height: 160px;
            border-radius: 50%;
            border: 8px solid {badge_color};
            display: flex;
            flex-direction: column;
            align-items: center;
            justify-content: center;
            box-shadow: 0 0 40px {badge_color}44;
            margin-bottom: 16px;
        }}
        .score-number {{ font-size: 48px; font-weight: 800; color: #fff; font-family: 'JetBrains Mono', monospace; }}
        .score-max {{ font-size: 14px; color: var(--text-sub); }}
        .score-label {{
            font-size: 14px;
            font-weight: 700;
            padding: 6px 16px;
            border-radius: 30px;
            background: {badge_color}22;
            color: {badge_color};
            border: 1px solid {badge_color}66;
            text-transform: uppercase;
        }}
        
        .modules-summary {{
            display: grid;
            grid-template-columns: repeat(3, 1fr);
            gap: 16px;
        }}
        .module-card {{
            background: rgba(255,255,255,0.03);
            border: 1px solid var(--border);
            border-radius: 14px;
            padding: 16px;
        }}
        .module-card h4 {{ font-size: 13px; color: var(--text-sub); text-transform: uppercase; margin-bottom: 8px; }}
        .module-card .val {{ font-size: 18px; font-weight: 700; }}
        
        /* Table */
        .table-wrap {{ margin-top: 16px; overflow-x: auto; }}
        table {{
            width: 100%;
            border-collapse: collapse;
            font-size: 13px;
        }}
        th {{
            background: rgba(255,255,255,0.04);
            color: var(--text-sub);
            text-align: left;
            padding: 14px 16px;
            font-size: 12px;
            text-transform: uppercase;
            font-weight: 600;
            border-bottom: 1px solid var(--border);
        }}
        td {{
            padding: 16px;
            border-bottom: 1px solid rgba(255,255,255,0.05);
            vertical-align: middle;
        }}
        tr:hover td {{ background: rgba(255,255,255,0.02); }}
        .badge {{
            display: inline-block;
            padding: 4px 10px;
            border-radius: 6px;
            font-size: 11px;
            font-weight: 700;
            font-family: 'JetBrains Mono', monospace;
        }}
        .badge-CRITICAL {{ background: rgba(239, 68, 68, 0.2); color: #f87171; border: 1px solid #ef4444; }}
        .badge-HIGH {{ background: rgba(249, 115, 22, 0.2); color: #fb923c; border: 1px solid #f97316; }}
        .badge-MEDIUM {{ background: rgba(245, 158, 11, 0.2); color: #fbbf24; border: 1px solid #f59e0b; }}
        .badge-LOW {{ background: rgba(59, 130, 246, 0.2); color: #60a5fa; border: 1px solid #3b82f6; }}
        
        .code-block {{
            background: #050811;
            border: 1px solid #1e293b;
            border-radius: 12px;
            padding: 16px;
            font-family: 'JetBrains Mono', monospace;
            font-size: 12px;
            color: #38bdf8;
            overflow-x: auto;
            margin-top: 12px;
            position: relative;
        }}
        .comparison {{
            display: grid;
            grid-template-columns: 1fr 1fr;
            gap: 20px;
            margin-top: 24px;
        }}
        .comp-box {{
            background: rgba(255,255,255,0.02);
            border: 1px solid var(--border);
            border-radius: 14px;
            padding: 20px;
        }}
        .tag {{ font-size: 11px; font-weight: 700; padding: 2px 8px; border-radius: 4px; }}
        .tag-bad {{ background: #ef444422; color: #f87171; }}
        .tag-good {{ background: #10b98122; color: #34d399; }}
    </style>
</head>
<body>
    <div class="container">
        <header>
            <div class="header-title">
                <h1>🛡️ Báo Cáo Phân Tích Cấu Hình & Rủi Ro Docker</h1>
                <p>Môn học: Lập trình An ninh Thông tin • Chuẩn kiểm định: CIS Docker Benchmark v1.6.0</p>
            </div>
            <div class="header-meta">
                <div>Mục tiêu: <strong>{self.target_name}</strong></div>
                <div>Thời gian quét: {self.scan_time}</div>
                <div>Nhóm: Gia Huy • Minh Khang • Phi Phúc • Nhật Hoàng</div>
            </div>
        </header>

        <div class="grid-stats">
            <div class="card score-box">
                <div class="score-circle">
                    <span class="score-number">{self.score}</span>
                    <span class="score-max">/ 100</span>
                </div>
                <div class="score-label">{score_badge}</div>
                <p style="font-size: 12px; color: var(--text-sub); margin-top: 12px;">
                    {'❌ Không vượt qua Security Gate' if has_critical else '✅ Vượt qua chuẩn an toàn'}
                </p>
            </div>

            <div class="card">
                <h3 style="margin-bottom: 16px; font-size: 16px;">📊 Tổng Quan Phân Tích Các Module (Slide 4 - 9)</h3>
                <div class="modules-summary">
                    <div class="module-card">
                        <h4>M1: Quyền Quản Trị (Root)</h4>
                        <div class="val" style="color: {'#ef4444' if any(f['rule_id']=='CIS-4.1' for f in self.findings) else '#10b981'};">
                            {'Phát hiện Root (UID 0)' if any(f['rule_id']=='CIS-4.1' for f in self.findings) else 'Non-root OK'}
                        </div>
                    </div>
                    <div class="module-card">
                        <h4>M2: Privileged & Cap</h4>
                        <div class="val" style="color: {'#ef4444' if any(f['rule_id'] in ['CIS-5.2','CIS-5.3'] for f in self.findings) else '#10b981'};">
                            {'Quyền thừa / Privileged' if any(f['rule_id'] in ['CIS-5.2','CIS-5.3'] for f in self.findings) else 'Restricted OK'}
                        </div>
                    </div>
                    <div class="module-card">
                        <h4>M3: Docker Socket Mount</h4>
                        <div class="val" style="color: {'#ef4444' if any(f['rule_id']=='CIS-5.31' for f in self.findings) else '#10b981'};">
                            {'Lộ Docker.sock!' if any(f['rule_id']=='CIS-5.31' for f in self.findings) else 'No Socket Mount'}
                        </div>
                    </div>
                    <div class="module-card">
                        <h4>M4: Lộ Lọt Secret (ENV)</h4>
                        <div class="val" style="color: {'#f97316' if any(f['rule_id']=='CIS-4.6' for f in self.findings) else '#10b981'};">
                            {'Phát hiện Hardcoded API/Pass' if any(f['rule_id']=='CIS-4.6' for f in self.findings) else 'No Secret Leak'}
                        </div>
                    </div>
                    <div class="module-card">
                        <h4>M5: DoS & cgroups Limit</h4>
                        <div class="val" style="color: {'#f59e0b' if any(f['rule_id'] in ['CIS-5.10','CIS-5.11'] for f in self.findings) else '#10b981'};">
                            {'Thiếu RAM/CPU Limit' if any(f['rule_id'] in ['CIS-5.10','CIS-5.11'] for f in self.findings) else 'Limits Configured'}
                        </div>
                    </div>
                    <div class="module-card">
                        <h4>M6: Base Image & Health</h4>
                        <div class="val" style="color: {'#3b82f6' if any(f['rule_id'] in ['CIS-4.2','CIS-4.6-HEALTH'] for f in self.findings) else '#10b981'};">
                            {'Dùng :latest / No Health' if any(f['rule_id'] in ['CIS-4.2','CIS-4.6-HEALTH'] for f in self.findings) else 'Pinned & Healthcheck'}
                        </div>
                    </div>
                </div>
            </div>
        </div>

        <!-- Chi tiết lỗ hổng -->
        <div class="card" style="margin-bottom: 24px;">
            <h3 style="font-size: 16px; margin-bottom: 8px;">📋 Bảng Chi Tiết Vi Phạm Chuẩn CIS Benchmark</h3>
            <p style="font-size: 13px; color: var(--text-sub); margin-bottom: 16px;">Đối chiếu trực tiếp với các tiêu chuẩn an toàn của Center for Internet Security (CIS).</p>
            <div class="table-wrap">
                <table>
                    <thead>
                        <tr>
                            <th style="width: 50px;">#</th>
                            <th style="width: 110px;">Mã CIS</th>
                            <th style="width: 120px;">Mức Độ</th>
                            <th>Mô Tả Rủi Ro</th>
                            <th>Khuyến Nghị Khắc Phục (Remediation)</th>
                        </tr>
                    </thead>
                    <tbody>
                        {"".join([f'''
                        <tr>
                            <td>{i}</td>
                            <td><strong style="color: #60a5fa; font-family: 'JetBrains Mono';">{f['rule_id']}</strong></td>
                            <td><span class="badge badge-{f['severity']}">{f['severity']}</span></td>
                            <td>
                                <div><strong>{f['title']}</strong></div>
                                <div style="color: var(--text-sub); font-size: 12px; margin-top: 4px;">{f['custom_desc']}</div>
                            </td>
                            <td>
                                <div style="color: #34d399; font-size: 12px;">✓ {f['remediation']}</div>
                            </td>
                        </tr>
                        ''' for i, f in enumerate(self.findings, 1)])}
                    </tbody>
                </table>
            </div>
        </div>

        <!-- Remediation box (Slide 10) & Multi-stage Comparison (Slide 11) -->
        <div class="comparison">
            <div class="comp-box">
                <span class="tag tag-bad">CẤU HÌNH GẶP LỖI (VULNERABLE)</span>
                <h4 style="margin: 12px 0 8px 0;">Trước khi tối ưu</h4>
                <ul style="font-size: 12px; color: var(--text-sub); line-height: 1.8; margin-left: 20px;">
                    <li>Kích thước Image lớn (~800MB) do chứa compiler & build cache.</li>
                    <li>Chạy trực tiếp dưới quyền Root (UID 0).</li>
                    <li>Sẵn sàng công cụ curl, bash, netcat cho kẻ tấn công leo thang.</li>
                    <li>Lộ thông tin nhạy cảm qua ENV.</li>
                </ul>
                <div class="code-block" style="color: #f87171;">
$ docker run -d --privileged \\<br>
&nbsp;&nbsp;-v /var/run/docker.sock:/var/run/docker.sock \\<br>
&nbsp;&nbsp;-e API_KEY=AKIAIOSFODNN7EX \\<br>
&nbsp;&nbsp;vulnerable-app:latest
                </div>
            </div>

            <div class="comp-box">
                <span class="tag tag-good">ĐỀ XUẤT VÁ LỖI TỰ ĐỘNG (REMEDIATION - SLIDE 10 & 11)</span>
                <h4 style="margin: 12px 0 8px 0;">Sau khi áp dụng Multi-stage build & Hardening</h4>
                <ul style="font-size: 12px; color: var(--text-sub); line-height: 1.8; margin-left: 20px;">
                    <li>Kích thước giảm còn <strong>30MB</strong>, loại bỏ toàn bộ shell thừa.</li>
                    <li>Cắt giảm toàn bộ quyền với <code>--cap-drop=ALL</code>.</li>
                    <li>Lọc cuộc gọi hệ thống bảo vệ Kernel qua <code>Seccomp profile</code>.</li>
                    <li>Giới hạn RAM 512MB & 1.0 CPU chống sập hệ thống (DoS).</li>
                </ul>
                <div class="code-block">
$ docker run -d \\<br>
&nbsp;&nbsp;--user 1001:1001 \\<br>
&nbsp;&nbsp;--cap-drop=ALL --cap-add=NET_BIND_SERVICE \\<br>
&nbsp;&nbsp;--security-opt seccomp=profile.json \\<br>
&nbsp;&nbsp;--memory="512m" --cpus="1.0" \\<br>
&nbsp;&nbsp;--read-only \\<br>
&nbsp;&nbsp;hardened-app:v1.0
                </div>
            </div>
        </div>
    </div>
</body>
</html>"""
        with open(output_path, "w", encoding="utf-8") as f:
            f.write(html_content)
        return output_path

def main():
    parser = argparse.ArgumentParser(description="Docker Security Configuration Scanner")
    parser.add_argument("target", help="Duong dan den Dockerfile hoac file container inspect JSON")
    parser.add_argument("--ci", action="store_true", help="Chay o che do CI/CD Security Gate (tra ve ma loi neu khong dat)")
    parser.add_argument("--threshold", type=int, default=70, help="Nguong diem toi thieu de pass CI/CD (mac dinh: 70)")
    parser.add_argument("--html", type=str, default="docker_security_report.html", help="Duong dan xuat file HTML bao cao")
    parser.add_argument("--open-browser", action="store_true", help="Tu dong mo trinh duyet xem bao cao HTML")

    args = parser.parse_args()

    scanner = DockerSecurityScanner()

    data = None
    if not os.path.exists(args.target):
        # Try inspecting real running docker container
        import subprocess
        try:
            res = subprocess.run(["docker", "inspect", args.target], capture_output=True, text=True)
            if res.returncode == 0 and res.stdout.strip():
                raw = json.loads(res.stdout)
                data = raw[0] if isinstance(raw, list) else raw
                scanner.analyze_inspect_json(data, target_name=f"Live Docker Container ({args.target})")
            else:
                print(f"{Fore.RED}[LOI] Khong tim thay tep hoac container Docker dang chay: {args.target}{Style.RESET_ALL}")
                sys.exit(2)
        except Exception as e:
            print(f"{Fore.RED}[LOI] Khong the goi Docker Daemon: {e}{Style.RESET_ALL}")
            sys.exit(2)
    else:
        with open(args.target, "r", encoding="utf-8", errors="ignore") as f:
            content = f.read()

        # Determine if it's JSON inspect or Dockerfile
        if args.target.endswith(".json") or content.strip().startswith("{"):
            try:
                data = json.loads(content)
                if isinstance(data, list) and len(data) > 0:
                    data = data[0]
                scanner.analyze_inspect_json(data, target_name=os.path.basename(args.target))
            except Exception as e:
                print(f"{Fore.RED}[LOI] Khong the phan tich JSON Inspect: {e}{Style.RESET_ALL}")
                sys.exit(2)
        else:
            scanner.analyze_dockerfile(content, filename=os.path.basename(args.target))

    # Output terminal report
    exit_code = scanner.print_terminal_report(is_ci=args.ci, fail_threshold=args.threshold)

    # Generate HTML
    report_file = scanner.generate_html_report(args.html)
    print(f"{Fore.GREEN}[OK] Da xuat bao cao truc quan ra: {os.path.abspath(report_file)}{Style.RESET_ALL}")

    if args.open_browser:
        try:
            import webbrowser
            webbrowser.open(os.path.abspath(report_file))
        except Exception:
            pass

    if args.ci and exit_code != 0:
        sys.exit(exit_code)

if __name__ == "__main__":
    main()
