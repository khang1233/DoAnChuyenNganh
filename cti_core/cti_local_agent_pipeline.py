# -*- coding: utf-8 -*-
"""
Module: cti_local_agent_pipeline.py
Chuc nang: Pipeline AI Agent CTI su dung Mo hinh Ngon ngu Cuc bo (Local LLM - Ollama)
Luong chuan 100% Agentic Skill:
  [Ban tin CTI] -> [Local LLM Agent (Ollama) + xAI Grounding] -> [IOC + Hanh vi]
                -> [Local LLM Skill Synthesis + Validator]      -> [Agentic Skill Package:
                     SKILL.md, manifest.json, scripts/verify_threat.py, references/]
"""

import ast
import difflib
import ipaddress
import json
import os
import re
import subprocess
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urlparse

import requests
import yaml

ROOT_DIR = Path(__file__).resolve().parents[1]
OLLAMA_MODELS_DIR = ROOT_DIR / "ollama_models"
OLLAMA_HOST = os.environ.get("OLLAMA_HOST", "http://127.0.0.1:11434").rstrip("/")

BENIGN_DOMAINS = {
    "google.com", "microsoft.com", "microsoftonline.com", "live.com", "office.com", "outlook.com",
    "aka.ms", "vscode.dev", "googleapis.com", "gstatic.com",
    "cloudflare.com", "apple.com", "amazon.com", "amazonaws.com",
    "thehackernews.com", "bleepingcomputer.com", "kaspersky.com",
    "securelist.com", "checkpoint.com", "sentinelone.com", "thedfirreport.com",
    "cisa.gov", "mitre.org", "cve.org", "nvd.nist.gov", "nist.gov",
    "virustotal.com", "abuseipdb.com", "shodan.io", "twitter.com", "x.com",
    "linkedin.com", "youtube.com", "reddit.com", "wikipedia.org",
    "apache.org", "nodejs.org", "python.org", "npmjs.com", "pypi.org",
    "adobe.com", "oracle.com", "cisco.com", "fortinet.com", "paloaltonetworks.com",
    "ivanti.com", "solarwinds.com", "wordpress.org", "nextcloud.com", "cpanel.net",
    "notepad-plus-plus.org", "openai.com", "chatgpt.com", "claude.ai", "claude.com",
    "anthropic.com", "langchain.com", "dropbox.com", "gmail.com", "yahoo.com", "ukr.net",
}

# Multi-tenant SaaS / code hosting / paste / dead-drop / tunneling / utility platforms:
# NEVER allow their bare root domain as a malicious DOMAIN IOC,
# while allowing attacker subdomains (e.g. foo.workers.dev) or full payload URLs (e.g. github.com/u/r/raw/...).
ROOT_ONLY_PLATFORM_DOMAINS = {
    "github.com", "gist.github.com", "githubusercontent.com", "raw.githubusercontent.com",
    "gitlab.com", "bitbucket.org",
    "workers.dev", "pages.dev", "r2.dev", "trycloudflare.com", "lhr.life", "ngrok.io", "ngrok-free.app",
    "vercel.app", "netlify.app", "herokuapp.com", "fly.dev", "azurewebsites.net", "cloudfront.net",
    "aliyuncs.com", "storage.googleapis.com", "s3.filebase.com", "wasabisys.com", "backblazeb2.com",
    "pastebin.com", "glot.io", "snippet.host", "rlim.com", "paste.ee", "rentry.co", "paste.kealper.com",
    "webhook.site", "requestrepo.com", "api.npoint.io", "npoint.io",
    "temp.sh", "files.fm", "filen.io", "gofile.io", "mega.nz", "mediafire.com", "anonfiles.com",
    "proton.me", "protonmail.com", "firstmail.ltd", "rambler.ru", "mail.ru",
    "ipapi.co", "ipapi.is", "ipinfo.io", "ifconfig.me", "api.ipify.org", "ip-api.com",
    "1rpc.io", "arweave.net", "dwservice.net", "gotoresolve.com", "anydesk.com", "teamviewer.com",
    "steamcommunity.com", "steampowered.com", "discord.com", "discordapp.com", "t.me", "telegram.org",
    "tronscanapi.com", "etherscan.io", "bscscan.com", "blockchain.info",
    "example.com", "example.org", "example.net", "test.com", "localhost.localdomain",
    "xxx.com", "de.com", "resi.to", "maper.info",
}

# Passive GeoIP/IP-lookup or developer/auth utility domains whose URLs are not malware payload hosts
NON_PAYLOAD_API_DOMAINS = {
    "ipapi.co", "ipapi.is", "ipinfo.io", "ifconfig.me", "api.ipify.org", "ip-api.com",
    "1rpc.io", "tronscanapi.com", "etherscan.io", "bscscan.com", "webhook.site", "requestrepo.com",
    "dwservice.net", "gotoresolve.com", "xxx.com", "de.com", "example.com", "example.org", "example.net",
}

NON_ROUTABLE_TLDS = {
    "local", "internal", "lan", "home", "corp", "intranet", "invalid", "test", "example", "localhost", "hankook",
}

BENIGN_IPS = {
    "8.8.8.8", "8.8.4.4", "1.1.1.1", "1.0.0.1", "9.9.9.9",
    "0.0.0.0", "127.0.0.1", "255.255.255.255"
}

# Public Anycast CDN proxy ranges (Cloudflare published IPv4 ranges) - fail-closed safety: never block shared CDN IPs
CLOUDFLARE_SHARED_CDN_CIDRS = tuple(
    ipaddress.ip_network(cidr) for cidr in (
        "173.245.48.0/20", "103.21.244.0/22", "103.22.200.0/22", "103.31.4.0/22",
        "141.101.64.0/18", "108.162.192.0/18", "190.93.240.0/20", "188.114.96.0/20",
        "197.234.240.0/22", "198.41.128.0/17", "162.158.0.0/15", "104.16.0.0/13",
        "104.24.0.0/14", "172.64.0.0/13", "131.0.72.0/22",
    )
)

FILE_EXT_SUFFIXES = (
    ".exe", ".dll", ".sys", ".bat", ".ps1", ".vbs", ".js", ".py", ".php",
    ".html", ".htm", ".css", ".png", ".jpg", ".jpeg", ".gif", ".svg",
    ".pdf", ".doc", ".docx", ".xls", ".xlsx", ".zip", ".rar", ".7z",
    ".tar", ".gz", ".json", ".xml", ".yml", ".yaml", ".txt", ".log",
    ".sh", ".elf", ".bin", ".apk", ".ipa", ".msi", ".iso", ".lnk", ".jsp", ".asp", ".aspx"
)

RE_IP = re.compile(r"\b(?:\d{1,3}(?:\[\.\]|\(\.\)|\.)){3}\d{1,3}\b")
RE_CVE = re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.I)
RE_SHA256 = re.compile(r"\b[a-fA-F0-9]{64}\b")
RE_MD5 = re.compile(r"\b[a-fA-F0-9]{32}\b")
RE_URL = re.compile(r"(?:hxxps?|https?)(?:\[:\]|:)//(?:[^\s\"'<>()\[\],;\u201c\u201d\u2018\u2019]|\[(?:\.|:)\]|\(\.\))+", re.I)
RE_DEFANG_DOM = re.compile(r"\b(?:[a-z0-9-]+(?:\[\.\]|\(\.\)|\.))*[a-z0-9-]+(?:\[\.\]|\(\.\))[a-z]{2,12}\b", re.I)


def refang(val: str) -> str:
    s = (val or "").strip().strip("\u201c\u201d\u2018\u2019")
    s = s.replace("[.]", ".").replace("(.)", ".").replace("[:]", ":")
    s = re.sub(r"^hxxps://", "https://", s, flags=re.I)
    s = re.sub(r"^hxxp://", "http://", s, flags=re.I)
    return s.rstrip(".,;:\"')]>}\u201d\u2019")


def _all_occurrences_are_software_version(ip_val: str, article_text: str) -> bool:
    if not article_text:
        return False
    clean_ip = refang(ip_val)
    ref_text = article_text.replace("[.]", ".").replace("(.)", ".")
    matches = list(re.finditer(r"(?<![\d.])" + re.escape(clean_ip) + r"(?![\d.])", ref_text))
    if not matches:
        return False
    ver_pat = re.compile(r"(?:\bversion\b|\bver\.?|\bv\.|\bbuild\b|\brelease\b|\bios\b|\bandroid\b|\bchrome\b|\bfirefox\b|\bcpanel\b|\bwhm\b|\bfileversion\b)\s*$", re.I)
    for m in matches:
        prefix = ref_text[max(0, m.start() - 28):m.start()]
        if not ver_pat.search(prefix):
            return False
    return True


def is_valid_malicious_ip(raw_ip: str) -> bool:
    clean = refang(raw_ip)
    try:
        ip_obj = ipaddress.ip_address(clean)
    except ValueError:
        return False
    if (
        clean in BENIGN_IPS
        or ip_obj.is_private
        or ip_obj.is_loopback
        or ip_obj.is_link_local
        or ip_obj.is_unspecified
        or ip_obj.is_multicast
        or ip_obj.is_reserved
        or any(ip_obj in net for net in CLOUDFLARE_SHARED_CDN_CIDRS)
    ):
        return False
    parts = clean.split(".")
    if len(parts) == 4 and int(parts[0]) == 0:
        return False
    return True


def is_valid_malicious_domain(raw_dom: str) -> bool:
    clean = refang(raw_dom).lower()
    if not clean or "." not in clean or " " in clean or "/" in clean:
        return False
    if re.fullmatch(r"(?:\d{1,3}\.){3}\d{1,3}", clean):
        return False
    if any(clean.endswith(ext) for ext in FILE_EXT_SUFFIXES):
        return False
    if not re.fullmatch(r"(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,15}", clean):
        return False
    tld = clean.rsplit(".", 1)[-1]
    if tld in NON_ROUTABLE_TLDS:
        return False
    for b in BENIGN_DOMAINS:
        if clean == b or clean.endswith("." + b):
            return False
    bare = clean[4:] if clean.startswith("www.") else clean
    if clean in ROOT_ONLY_PLATFORM_DOMAINS or bare in ROOT_ONLY_PLATFORM_DOMAINS:
        return False
    return True


def is_valid_malicious_url(raw_url: str) -> bool:
    clean = refang(raw_url)
    if not clean.lower().startswith(("http://", "https://")):
        return False
    if "{" in clean or "}" in clean or "<" in clean or ">" in clean:
        return False
    try:
        parsed = urlparse(clean)
        host = (parsed.hostname or "").lower()
    except Exception:
        return False
    if not host or "." not in host:
        return False
    if any(host == d or host.endswith("." + d) for d in NON_PAYLOAD_API_DOMAINS):
        return False
    # Handle host IP URLs safely
    try:
        ipaddress.ip_address(host)
        return is_valid_malicious_ip(host)
    except ValueError:
        pass
    path_clean = (parsed.path or "").strip("/")
    bare = host[4:] if host.startswith("www.") else host
    # Code/paste/file-share platforms (e.g. github.com, gist.github.com, pastebin.com, steamcommunity.com)
    if host in ("github.com", "gist.github.com", "githubusercontent.com", "raw.githubusercontent.com") or host.endswith(".github.com"):
        if not path_clean or len(path_clean) < 6:
            return False
        p_low = "/" + path_clean.lower()
        if any(seg in p_low for seg in ("/raw", "/releases/", "/download/", "/blob/", ".zip", ".exe", ".py", ".sh", ".ps1", ".dll", ".bat", ".elf")) or host in ("gist.github.com", "raw.githubusercontent.com"):
            return True
        return False
    for b in BENIGN_DOMAINS:
        if host == b or host.endswith("." + b):
            return False
    if host in ROOT_ONLY_PLATFORM_DOMAINS or bare in ROOT_ONLY_PLATFORM_DOMAINS:
        return len(path_clean) >= 3
    return True


def ensure_ollama_running(preferred_model: str = "qwen3:8b") -> Tuple[bool, str]:
    """Kiem tra Ollama dang chay, neu chua thi tu dong khoi dong voi ollama_models cuc bo."""
    def _get_models() -> List[str]:
        try:
            r = requests.get(f"{OLLAMA_HOST}/api/tags", timeout=3)
            if r.status_code == 200:
                return [m.get("name", "") for m in r.json().get("models", [])]
        except Exception:
            pass
        return []

    models = _get_models()
    if not models:
        env = os.environ.copy()
        if OLLAMA_MODELS_DIR.exists():
            env["OLLAMA_MODELS"] = str(OLLAMA_MODELS_DIR)
        try:
            subprocess.Popen(
                ["ollama", "serve"],
                env=env,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                creationflags=subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0,
            )
            for _ in range(15):
                time.sleep(0.8)
                models = _get_models()
                if models:
                    break
        except Exception as e:
            return False, f"Khong the khoi dong Ollama: {e}"

    if not models:
        return False, "Ollama server khong phan hoi tai http://127.0.0.1:11434"

    if preferred_model in models:
        return True, preferred_model
    for m in models:
        if preferred_model.split(":")[0] in m:
            return True, m
    return True, models[0]


def call_ollama_chat(
    model: str,
    system_prompt: str,
    user_prompt: str,
    json_mode: bool = False,
    temperature: float = 0.1,
    timeout: int = 120,
    num_predict: int = 1800,
    num_ctx: int = 8192,
) -> str:
    payload: Dict[str, Any] = {
        "model": model,
        "messages": [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": user_prompt},
        ],
        "stream": False,
        "options": {
            "temperature": temperature,
            "num_ctx": num_ctx,
            "num_predict": num_predict,
        },
    }
    if json_mode:
        payload["format"] = "json"
    if "qwen3" in (model or "").lower():
        payload["think"] = False

    resp = requests.post(f"{OLLAMA_HOST}/api/chat", json=payload, timeout=timeout)
    resp.raise_for_status()
    text = (resp.json().get("message", {}).get("content") or "").strip()
    text = re.sub(r"<think>.*?</think>", "", text, flags=re.S).strip()
    return text


def _prepare_article_window(title: str, content: str, max_chars: int = 15500) -> str:
    text = (content or "").strip()
    if len(text) <= max_chars:
        return f"TITLE: {title}\n\n{text}"
    head = text[:6500]
    tail = text[-(max_chars - 6600):]
    return f"TITLE: {title}\n\n{head}\n\n[...]\n\n{tail}"


def _find_evidence_in_article(ioc_val: str, article_text: str, radius: int = 120) -> Optional[str]:
    """xAI Grounding: Tim dung cau van goc trong bai bao chua IOC (ho tro moi kieu defang 1 phan hoac toan phan)."""
    clean = refang(ioc_val)
    refanged_text = article_text.replace("[.]", ".").replace("(.)", ".").replace("[:]", ":")
    refanged_text = re.sub(r"hxxps://", "https://", refanged_text, flags=re.I)
    refanged_text = re.sub(r"hxxp://", "http://", refanged_text, flags=re.I)

    variants = [ioc_val, clean]
    text_low = refanged_text.lower()
    for v in variants:
        vl = v.lower().strip()
        if not vl:
            continue
        idx = text_low.find(vl)
        if idx != -1:
            start = max(0, idx - radius)
            end = min(len(refanged_text), idx + len(v) + radius)
            snippet = re.sub(r"\s+", " ", refanged_text[start:end]).strip()
            return snippet
    return None


def _snap_hash_to_article(candidate_hash: str, article_hashes: List[str]) -> Optional[str]:
    ch = candidate_hash.lower().strip()
    if ch in article_hashes:
        return ch
    best = difflib.get_close_matches(ch, article_hashes, n=1, cutoff=0.88)
    return best[0] if best else None


def _extract_clean_hashes(content: str) -> Tuple[List[str], List[str]]:
    """
    Trich xuat SHA256/MD5 sach tu noi dung bai bao:
    - Loai hex nam ben trong URL, query param, subdomain (vd gist ID, pub-<hex>.r2.dev, ?k=<hex>)
    - Loai hex duoc chu thich la key/salt giai ma hoac binary hop phap ("not malicious", "older version of legitimate binary")
    """
    url_spans = [(m.start(), m.end()) for m in RE_URL.finditer(content)]
    dom_spans = [(m.start(), m.end()) for m in RE_DEFANG_DOM.findall_iter(content)] if hasattr(RE_DEFANG_DOM, "findall_iter") else [(m.start(), m.end()) for m in RE_DEFANG_DOM.finditer(content)]
    non_hash_ctx = re.compile(
        r"(?:md5 hash of the string|concatenation of|and a salt|initialization vector|as the aes key|"
        r"older version of legitimate binary|not malicious|non-malicious)",
        re.I,
    )

    def _is_clean_hex_match(m: re.Match) -> bool:
        s, e = m.start(), m.end()
        if any(a <= s and e <= b for a, b in url_spans):
            return False
        if any(a <= s and e <= b for a, b in dom_spans):
            return False
        prev_ch = content[s - 1] if s > 0 else " "
        next_ch = content[e] if e < len(content) else " "
        if prev_ch in "/=?&-_." or next_ch in "/.-_&":
            return False
        ctx_window = content[max(0, s - 120):min(len(content), e + 120)]
        if non_hash_ctx.search(ctx_window):
            return False
        return True

    sha256_list = list(dict.fromkeys(
        m.group().lower() for m in RE_SHA256.finditer(content) if _is_clean_hex_match(m)
    ))
    md5_list = list(dict.fromkeys(
        m.group().lower()
        for m in RE_MD5.finditer(content)
        if _is_clean_hex_match(m) and not any(m.group().lower() in s for s in sha256_list)
    ))
    return sha256_list, md5_list


def _extract_ioc_section_text(content: str) -> str:
    ms = list(re.finditer(r"(?im)^\s*(?:Indicators of Compromise|IOCs)\b", content or ""))
    if not ms:
        return ""
    sec = content[ms[-1].start():]
    if len(sec) < 80:
        return ""
    return sec


def _extract_standalone_defanged_domains(text: str) -> List[str]:
    """Trich xuat domain defang dung doc lap hoac la root URL (khong trich host tu path URL dai kieu pastebin/raw)."""
    url_spans_with_path = []
    bare_root_domains = []
    for m in RE_URL.finditer(text):
        u_raw = m.group()
        u_clean = refang(u_raw)
        try:
            p = urlparse(u_clean)
            host = (p.hostname or "").lower()
            path = (p.path or "").strip("/")
            if not path and not p.query and is_valid_malicious_domain(host):
                bare_root_domains.append(host)
            elif path or p.query:
                url_spans_with_path.append((m.start(), m.end()))
        except Exception:
            url_spans_with_path.append((m.start(), m.end()))

    out = []
    for m in RE_DEFANG_DOM.finditer(text):
        s, e = m.start(), m.end()
        if any(a <= s and e <= b for a, b in url_spans_with_path):
            continue
        dom = refang(m.group()).lower()
        if is_valid_malicious_domain(dom):
            out.append(dom)
    out.extend(bare_root_domains)
    return list(dict.fromkeys(out))


def _audit_extracted_iocs_with_llm(
    title: str,
    full_text: str,
    context_notes: List[str],
    ips: List[str],
    domains: List[str],
    urls: List[str],
    model: str,
) -> Tuple[List[str], List[str], List[str], List[Tuple[str, str, str]]]:
    """
    Buoc 1B (Context-Audit Verification Gate):
    Doi chieu tung IP/Domain/URL voi doan van goc quanh no va context_notes.
    Tu dong loai bo False Positive la API hop phap (vd tronscanapi.com, ipapi.co),
    victim/impersonated site (vd cpuid.com, hydro.gov.ua), hoac CDN proxy duoc bao cao chi ro.
    """
    audit_items: List[Dict[str, str]] = []
    for ip in ips:
        q = _find_evidence_in_article(ip, full_text, radius=130) or ""
        audit_items.append({"id": f"IP:{ip}", "kind": "IP", "value": ip, "quote": q})
    for dom in domains:
        q = _find_evidence_in_article(dom, full_text, radius=130) or ""
        audit_items.append({"id": f"DOMAIN:{dom}", "kind": "DOMAIN", "value": dom, "quote": q})

    # Audit suspect/non-IOC-section or diverse host URLs (cap cleanly so latency stays ~2-3s)
    seen_url_hosts = set()
    for u in urls:
        host = (urlparse(u).hostname or "").lower()
        if host in seen_url_hosts and len(audit_items) >= 35:
            continue
        seen_url_hosts.add(host)
        q = _find_evidence_in_article(u, full_text, radius=110) or _find_evidence_in_article(host, full_text, radius=110) or ""
        audit_items.append({"id": f"URL:{u}", "kind": "URL", "value": u, "quote": q})
        if len(audit_items) >= 50:
            break

    if not audit_items:
        return ips, domains, urls, []

    audit_sys = (
        "You are a strict CTI False-Positive Auditor.\n"
        "Review the campaign title, analyst context_notes, and verbatim quote for each candidate IOC.\n"
        "REJECT an item ONLY when the quote/context clearly shows it is NOT a malicious IOC:\n"
        "  1. A legitimate public third-party API, AI/SaaS service, blockchain explorer/RPC, or benign email/cloud service queried/abused via normal HTTPS (e.g. tronscanapi.com, 1rpc.io, chatgpt.com, ipapi.co).\n"
        "  2. An unaffected victim organization, targeted website, impersonated brand, or researcher blog mentioned as target/reference (e.g. cpuid.com, mjla.gov.om, hydro.gov.ua, notepad-plus-plus.org).\n"
        "  3. A shared CDN/Cloudflare proxy IP explicitly described as a Cloudflare/proxy IP rather than real attacker C2.\n"
        "  4. A software version tuple, documentation example/placeholder, or benign dependency.\n"
        "DO NOT reject real attacker C2 servers, phishing domains, malware staging hosts, compromised sites actively serving malware payloads, or items listed under an Indicators of Compromise table.\n"
        "Return STRICT JSON ONLY:\n"
        '{"reject": [{"id": "DOMAIN:...", "reason": "short reason"}]}'
    )
    audit_user = json.dumps({
        "title": title,
        "context_notes": context_notes,
        "candidates": audit_items,
    }, ensure_ascii=False)

    rejected_records: List[Tuple[str, str, str]] = []
    reject_ids: set[str] = set()
    try:
        raw_audit = call_ollama_chat(
            model=model,
            system_prompt=audit_sys,
            user_prompt=audit_user,
            json_mode=True,
            temperature=0.0,
            timeout=60,
            num_predict=600,
            num_ctx=8192,
        )
        audit_parsed = json.loads(raw_audit)
        for rec in audit_parsed.get("reject", []) if isinstance(audit_parsed, dict) else []:
            if isinstance(rec, dict) and rec.get("id"):
                rid = str(rec["id"]).strip()
                reason = str(rec.get("reason", "context_audit")).strip()
                reject_ids.add(rid)
                rejected_records.append((rid, reason, "step1b_audit"))
    except Exception:
        return ips, domains, urls, []

    if not reject_ids:
        return ips, domains, urls, []

    rejected_url_hosts = {
        (urlparse(rid[4:]).hostname or "").lower()
        for rid in reject_ids if rid.startswith("URL:")
    }
    kept_ips = [ip for ip in ips if f"IP:{ip}" not in reject_ids]
    kept_doms = [d for d in domains if f"DOMAIN:{d}" not in reject_ids]
    kept_urls = [
        u for u in urls
        if f"URL:{u}" not in reject_ids and (urlparse(u).hostname or "").lower() not in rejected_url_hosts
    ]
    return kept_ips, kept_doms, kept_urls, rejected_records


def extract_iocs_with_local_llm(
    title: str,
    content: str,
    model: str = "qwen3:8b",
    progress_callback: Optional[Any] = None,
) -> Dict[str, Any]:
    """
    Buoc 1 Pipeline: Agent doc ban tin CTI bang Local LLM (Ollama),
    trich xuat IOCs + hanh vi tan cong + Context Audit Verification + xAI Grounding.
    """
    full_text = f"{title}\n{content}"
    cand_ips = list(dict.fromkeys(
        refang(m.group()) for m in RE_IP.finditer(content)
        if is_valid_malicious_ip(m.group()) and not _all_occurrences_are_software_version(m.group(), content)
    ))
    cand_cves = list(dict.fromkeys(m.upper() for m in RE_CVE.findall(full_text)))
    cand_sha256, cand_md5 = _extract_clean_hashes(content)
    cand_urls = list(dict.fromkeys(
        refang(u) for u in RE_URL.findall(content)
        if ("hxxp" in u.lower() or "[.]" in u or "[:]" in u) and is_valid_malicious_url(u)
    ))
    cand_doms = _extract_standalone_defanged_domains(content)

    system_prompt = (
        "You are a senior Cyber Threat Intelligence (CTI) Analyst Agent.\n"
        "Read the CTI report and extract ONLY genuine malicious Indicators of Compromise (IOCs) and attack behaviors.\n"
        "CRITICAL PRECISION & CONTEXT RULES:\n"
        "1. Convert defanged indicators (1.2.3[.]4 -> 1.2.3.4, hxxps://evil[.]com -> https://evil.com).\n"
        "2. SEPARATE non-malicious infrastructure into `excluded_non_malicious`! NEVER put these into `ips` or `domains`:\n"
        "   - Legitimate public APIs, AI assistants, email providers, blockchain RPC/explorers, or cloud services abused by malware (e.g. tronscanapi.com, ipapi.co, chatgpt.com, claude.ai, proton.me, filen.io, 1rpc.io, webhook.site, glot.io, vscode.dev, steamcommunity.com).\n"
        "   - Victim/targeted sites, impersonated legitimate brands, or security/news vendors (e.g. cpuid.com, mjla.gov.om, hydro.gov.ua, notepad-plus-plus.org, kaspersky.com).\n"
        "   - Shared CDN/Cloudflare proxy IPs explicitly identified as proxy/Cloudflare rather than real attacker C2.\n"
        "   - Metadata/link-local IPs (169.254.x.x), private/DNS IPs, version numbers (14.2.1.0), or placeholders (xxx.com, {payload_id}).\n"
        "3. `domains` vs `urls`: Put dedicated malicious/C2/phishing/compromised domains in `domains`. Do NOT split bare hosting/paste platform domains (github.com, pastebin.com, snippet.host, rlim.com, api.npoint.io, s3.filebase.com) into `domains` — keep only their full attacker-specific path URLs in `urls`.\n"
        "4. Return STRICT JSON ONLY matching this exact schema:\n"
        "{\n"
        '  "ips": ["..."],\n'
        '  "domains": ["..."],\n'
        '  "urls": ["..."],\n'
        '  "md5": ["..."],\n'
        '  "sha256": ["..."],\n'
        '  "cves": ["CVE-..."],\n'
        '  "excluded_non_malicious": [{"indicator": "...", "role": "legitimate_api|victim_site|vendor_infra|cdn_proxy|placeholder", "reason": "..."}],\n'
        '  "mitre_techniques": ["T1190", "T1059.001"],\n'
        '  "attack_behaviors": ["short observable strings like process names, command lines, file paths, registry keys, URI paths"],\n'
        '  "context_notes": ["2-3 concise Vietnamese analyst notes: explain campaign context, distinguish true C2 vs abused legitimate services/victim sites, and key telemetry to detect"],\n'
        '  "summary": "1-2 sentence technical summary"\n'
        "}"
    )

    hints_block = json.dumps({
        "regex_candidates_to_verify": {
            "ips": cand_ips[:40],
            "defanged_domains": cand_doms[:40],
            "defanged_urls": cand_urls[:35],
            "md5": cand_md5[:20],
            "sha256": cand_sha256[:20],
            "cves": cand_cves[:25],
        }
    }, ensure_ascii=False)

    user_prompt = (
        f"Analyze the following CTI report and extract ONLY genuine malicious IOCs.\n"
        f"Regex pre-scan hints (verify carefully against context; exclude benign/victim/legitimate APIs into excluded_non_malicious, and keep all true malicious IOCs from the report & Indicators of Compromise table):\n"
        f"{hints_block}\n\n"
        f"--- ARTICLE TEXT ---\n"
        f"{_prepare_article_window(title, content)}"
    )

    t0 = time.time()
    llm_raw = ""
    parsed: Dict[str, Any] = {}
    llm_used = True
    try:
        llm_raw = call_ollama_chat(
            model=model,
            system_prompt=system_prompt,
            user_prompt=user_prompt,
            json_mode=True,
            temperature=0.05,
            timeout=120,
            num_predict=1800,
            num_ctx=8192,
        )
        parsed = json.loads(llm_raw)
    except Exception as e:
        llm_used = False
        parsed = {
            "ips": cand_ips,
            "domains": cand_doms,
            "urls": cand_urls,
            "md5": cand_md5,
            "sha256": cand_sha256,
            "cves": cand_cves,
            "excluded_non_malicious": [],
            "mitre_techniques": [],
            "attack_behaviors": [],
            "summary": f"Fallback deterministic extraction ({e})",
        }

    evidences: List[Dict[str, str]] = []
    hallucinated_rejected: List[str] = []

    llm_excluded_set: set[str] = set()
    raw_excl = parsed.get("excluded_non_malicious", [])
    if isinstance(raw_excl, list):
        for ex in raw_excl:
            if isinstance(ex, dict):
                ind = refang(str(ex.get("indicator", ""))).lower().rstrip("/")
                role = str(ex.get("role", "non_malicious")).strip()
                if role.lower() in ("malicious", "c2", "attacker", "compromised", "malware", "phishing"):
                    continue
                if ind:
                    llm_excluded_set.add(ind)
                    hallucinated_rejected.append(f"LLM_EXCLUDED({role}):{ind}")
            elif isinstance(ex, str) and ex.strip():
                ind = refang(ex).lower().rstrip("/")
                llm_excluded_set.add(ind)
                hallucinated_rejected.append(f"LLM_EXCLUDED:{ind}")

    def _is_excluded(val: str) -> bool:
        norm = refang(val).lower().rstrip("/")
        return norm in llm_excluded_set

    def _verify_list(raw_list: Any, kind: str) -> List[str]:
        if not isinstance(raw_list, list):
            return []
        verified = []
        seen = set()
        for item in raw_list:
            val = refang(str(item))
            if not val or _is_excluded(val):
                continue
            if kind == "IP":
                if not is_valid_malicious_ip(val) or _all_occurrences_are_software_version(val, content):
                    continue
                ev = _find_evidence_in_article(val, full_text)
                if not ev:
                    hallucinated_rejected.append(f"IP:{val}")
                    continue
            elif kind == "DOMAIN":
                val = val.lower()
                if not is_valid_malicious_domain(val):
                    continue
                ev = _find_evidence_in_article(val, full_text)
                if not ev:
                    hallucinated_rejected.append(f"DOMAIN:{val}")
                    continue
            elif kind == "URL":
                if not is_valid_malicious_url(val):
                    continue
                ev = _find_evidence_in_article(val, full_text)
                if not ev:
                    ev = _find_evidence_in_article(urlparse(val).netloc, full_text)
                if not ev:
                    hallucinated_rejected.append(f"URL:{val}")
                    continue
            elif kind == "MD5":
                val = val.lower()
                snapped = _snap_hash_to_article(val, cand_md5)
                if snapped:
                    val = snapped
                elif not re.fullmatch(r"[a-f0-9]{32}", val):
                    continue
                if cand_md5 and val not in cand_md5:
                    continue
                ev = _find_evidence_in_article(val, full_text)
                if not ev:
                    hallucinated_rejected.append(f"MD5:{val}")
                    continue
            elif kind == "SHA256":
                val = val.lower()
                snapped = _snap_hash_to_article(val, cand_sha256)
                if snapped:
                    val = snapped
                elif not re.fullmatch(r"[a-f0-9]{64}", val):
                    continue
                if cand_sha256 and val not in cand_sha256:
                    continue
                ev = _find_evidence_in_article(val, full_text)
                if not ev:
                    hallucinated_rejected.append(f"SHA256:{val}")
                    continue
            elif kind == "CVE":
                val = val.upper()
                if not re.fullmatch(r"CVE-\d{4}-\d{4,7}", val):
                    continue
                ev = _find_evidence_in_article(val, full_text)
                if not ev:
                    hallucinated_rejected.append(f"CVE:{val}")
                    continue
            else:
                ev = None

            if val not in seen:
                seen.add(val)
                verified.append(val)
                if ev:
                    evidences.append({"type": kind, "value": val, "evidence_quote": ev})
        return verified

    final_ips = _verify_list(parsed.get("ips", []), "IP")
    final_doms = _verify_list(parsed.get("domains", []), "DOMAIN")
    final_urls = _verify_list(parsed.get("urls", []), "URL")
    final_md5 = _verify_list(parsed.get("md5", []), "MD5")
    final_sha256 = _verify_list(parsed.get("sha256", []), "SHA256")
    final_cves = _verify_list(parsed.get("cves", []), "CVE")

    # Safe deterministic recall completion for verified file hashes & CVEs (avoids 8B output truncation on 40-80+ hash tables)
    for h in cand_md5:
        if h not in final_md5 and not _is_excluded(h):
            ev = _find_evidence_in_article(h, full_text)
            if ev:
                final_md5.append(h)
                evidences.append({"type": "MD5", "value": h, "evidence_quote": ev})

    for h in cand_sha256:
        if h not in final_sha256 and not _is_excluded(h):
            ev = _find_evidence_in_article(h, full_text)
            if ev:
                final_sha256.append(h)
                evidences.append({"type": "SHA256", "value": h, "evidence_quote": ev})

    for cve in cand_cves:
        if cve not in final_cves and not _is_excluded(cve):
            ev = _find_evidence_in_article(cve, full_text)
            if ev:
                final_cves.append(cve)
                evidences.append({"type": "CVE", "value": cve, "evidence_quote": ev})

    # Explicit IOC Section Tail Recovery: catches long IOC tables (>15 IPs/domains/URLs) without blind prose injection
    ioc_section = _extract_ioc_section_text(content)
    if ioc_section:
        sec_ips = [
            refang(m.group()) for m in RE_IP.finditer(ioc_section)
            if ("[" in m.group() or len(re.findall(r"(?m)^\s*" + re.escape(m.group()), ioc_section)) > 0)
            and is_valid_malicious_ip(m.group())
            and not _all_occurrences_are_software_version(m.group(), content)
        ]
        for ip in dict.fromkeys(sec_ips):
            if ip not in final_ips and not _is_excluded(ip):
                ev = _find_evidence_in_article(ip, full_text)
                if ev:
                    final_ips.append(ip)
                    evidences.append({"type": "IP", "value": ip, "evidence_quote": ev})

        sec_urls = [
            refang(u) for u in RE_URL.findall(ioc_section)
            if ("hxxp" in u.lower() or "[.]" in u or "[:]" in u) and is_valid_malicious_url(u)
        ]
        seen_urls_norm = {u.rstrip("/") for u in final_urls}
        for u in dict.fromkeys(sec_urls):
            u_norm = u.rstrip("/")
            if u_norm not in seen_urls_norm and not _is_excluded(u_norm):
                ev = _find_evidence_in_article(u, full_text) or _find_evidence_in_article(urlparse(u).netloc, full_text)
                if ev:
                    seen_urls_norm.add(u_norm)
                    final_urls.append(u)
                    evidences.append({"type": "URL", "value": u, "evidence_quote": ev})

        sec_doms = _extract_standalone_defanged_domains(ioc_section)
        for dom in sec_doms:
            if dom not in final_doms and not _is_excluded(dom):
                ev = _find_evidence_in_article(dom, full_text)
                if ev:
                    final_doms.append(dom)
                    evidences.append({"type": "DOMAIN", "value": dom, "evidence_quote": ev})

    notes_raw = parsed.get("context_notes", [])
    notes_clean = [str(n).strip() for n in notes_raw if len(str(n).strip()) >= 8][:5] if isinstance(notes_raw, list) else []

    # Fast Fail-Closed Self-Consistency Guard:
    # Neu context_notes chinh AI viet tu khang dinh 1 domain la API/dich vu hop phap hoac nan nhan bi mao danh, tu loai bo de tranh mau thuan.
    if notes_clean and final_doms:
        benign_note_pat = re.compile(
            r"(?:legitimate\s+(?:public\s+)?api|legitimate\s+service|abused\s+legitimate|impersonated\s+(?:brand|site)|"
            r"unaffected\s+victim|dịch vụ\s+(?:api\s+)?hợp pháp|trang\s+(?:web\s+)?hợp pháp|nạn nhân\s+bị\s+mạo\s+danh)",
            re.I,
        )
        contradicted_doms: set[str] = set()
        for note in notes_clean:
            if benign_note_pat.search(note):
                for dom in final_doms:
                    if dom.lower() in note.lower():
                        contradicted_doms.add(dom)
        if contradicted_doms:
            final_doms = [d for d in final_doms if d not in contradicted_doms]
            evidences = [ev for ev in evidences if not (ev["type"] == "DOMAIN" and ev["value"] in contradicted_doms)]
            for d in sorted(contradicted_doms):
                hallucinated_rejected.append(f"CTX_SELF_AUDIT_EXCLUDED:DOMAIN:{d}")

    mitre_raw = parsed.get("mitre_techniques", [])
    mitre_clean = [str(m).upper().strip() for m in mitre_raw if re.match(r"^T\d{4}(?:\.\d{3})?$", str(m).upper().strip())] if isinstance(mitre_raw, list) else []
    behaviors_raw = parsed.get("attack_behaviors", [])
    behaviors_clean = [
        str(b).strip() for b in behaviors_raw
        if len(str(b).strip()) >= 4 and not re.fullmatch(r"[A-Za-z]:\\{1,2}", str(b).strip())
    ][:12] if isinstance(behaviors_raw, list) else []

    elapsed = round(time.time() - t0, 2)
    return {
        "model": model,
        "llm_used": llm_used,
        "latency_sec": elapsed,
        "iocs": {
            "ips": final_ips,
            "domains": final_doms,
            "urls": final_urls,
            "md5": final_md5,
            "sha256": final_sha256,
            "cves": final_cves,
        },
        "mitre_techniques": mitre_clean or ["T1059"],
        "attack_behaviors": behaviors_clean,
        "context_notes": notes_clean,
        "summary": str(parsed.get("summary", "")).strip(),
        "xai_evidences": evidences,
        "hallucinated_rejected": hallucinated_rejected,
    }


# ---------------------------------------------------------------------------
# Skill Validators (Table 2: SKILL.md, manifest.json, scripts/verify_threat.py, references/)
# ---------------------------------------------------------------------------
def validate_skill_markdown(skill_md: str) -> Tuple[bool, str]:
    if not skill_md or not skill_md.strip():
        return False, "Empty SKILL.md"
    s = skill_md.strip()
    m = re.match(r"^---\s*\n(.*?)\n---\s*\n(.*)$", s, re.S)
    if not m:
        return False, "SKILL.md missing YAML frontmatter (--- ... ---)"
    try:
        fm = yaml.safe_load(m.group(1))
    except Exception as e:
        return False, f"SKILL.md frontmatter YAML error: {e}"
    if not isinstance(fm, dict):
        return False, "SKILL.md frontmatter is not a mapping"
    if not fm.get("name") or not fm.get("description"):
        return False, "SKILL.md frontmatter missing 'name' or 'description'"
    body = m.group(2).strip()
    if len(body) < 80 or "#" not in body:
        return False, "SKILL.md SOP body too short or missing markdown headings"
    return True, "Valid SKILL.md (YAML frontmatter + SOP)"


def validate_manifest_json(manifest_text: str) -> Tuple[bool, str]:
    if not manifest_text or not manifest_text.strip():
        return False, "Empty manifest.json"
    try:
        data = json.loads(manifest_text)
    except Exception as e:
        return False, f"manifest.json parse error: {e}"
    if not isinstance(data, dict):
        return False, "manifest.json root must be a JSON object"
    for req in ("name", "version", "tools", "references"):
        if req not in data or not data[req]:
            return False, f"manifest.json missing required field '{req}'"
    if not isinstance(data["tools"], list) or not isinstance(data["references"], list):
        return False, "manifest.json 'tools' and 'references' must be lists"
    scripts_declared = [str(t.get("script", "")) for t in data["tools"] if isinstance(t, dict)]
    if not any("verify_threat.py" in s for s in scripts_declared):
        return False, "manifest.json tools must reference 'scripts/verify_threat.py'"
    return True, "Valid manifest.json schema"


def validate_skill_script(py_text: str, sample_ioc: str = "") -> Tuple[bool, str]:
    if not py_text or not py_text.strip():
        return False, "Empty scripts/verify_threat.py"
    try:
        tree = ast.parse(py_text)
        code_obj = compile(py_text, "<verify_threat.py>", "exec")
    except SyntaxError as e:
        return False, f"Python syntax error line {e.lineno}: {e.msg}"
    except Exception as e:
        return False, f"Python compile error: {e}"
    func_names = {n.name for n in ast.walk(tree) if isinstance(n, ast.FunctionDef)}
    if "scan_artifact" not in func_names:
        return False, "Missing required entry function 'scan_artifact'"
    # Functional contract check: supports log_event & payload_bytes without flagging benign DNS
    try:
        ns: Dict[str, Any] = {"__name__": "skill_contract_check"}
        exec(code_obj, ns)
        fn = ns["scan_artifact"]
        benign_res = fn(log_event={"DestinationIp": "8.8.8.8", "QueryName": "google.com"})
        if isinstance(benign_res, dict) and benign_res.get("detected"):
            return False, "Script flagged benign DNS/domain (8.8.8.8 / google.com)"
        if sample_ioc:
            r_log = fn(log_event={"DestinationIp": sample_ioc, "QueryName": sample_ioc, "CommandLine": sample_ioc})
            r_buf = fn(payload_bytes=sample_ioc.encode("utf-8"))
            if not (isinstance(r_log, dict) and r_log.get("detected")):
                return False, "Script failed to detect sample IOC in log_event"
            if not (isinstance(r_buf, dict) and r_buf.get("detected")):
                return False, "Script failed to detect sample IOC in payload_bytes"
    except Exception as e:
        return False, f"Script runtime contract error: {e}"
    return True, "Valid Python AST & scan_artifact functional contract"


def validate_indicators_reference(entries: List[str]) -> Tuple[bool, str, Dict[str, int]]:
    clean_entries = [x.strip() for x in entries if x.strip() and not x.strip().startswith("#")]
    if not clean_entries:
        return True, "No network IOCs (clean empty indicator list)", {"total": 0, "valid": 0}
    valid_cnt = 0
    invalid = []
    for entry in clean_entries:
        token = entry.split()[0]
        if "[.]" in token or "hxxp" in token.lower():
            invalid.append(token)
            continue
        if is_valid_malicious_ip(token) or is_valid_malicious_domain(token) or is_valid_malicious_url(token):
            valid_cnt += 1
        else:
            invalid.append(token)
    if invalid:
        return False, f"Unsafe/Invalid indicator entries: {invalid[:3]}", {"total": len(clean_entries), "valid": valid_cnt}
    return True, f"All {valid_cnt} reference indicators valid & safe", {"total": len(clean_entries), "valid": valid_cnt}


def _strip_code_fences(text: str) -> str:
    s = (text or "").strip()
    m = re.search(r"```(?:markdown|md|json|python|py|yaml|yml)?\s*\n(.*?)```", s, re.S | re.I)
    if m:
        return m.group(1).strip()
    return s


def _make_skill_slug(article_id: str, title: str) -> str:
    slug = re.sub(r"[^a-z0-9]+", "-", title.lower()).strip("-")[:36].strip("-")
    aid_clean = re.sub(r"[^a-z0-9-]+", "-", article_id.lower()).strip("-")
    return f"cti-{aid_clean}-{slug or 'defense-skill'}"


def _build_deterministic_skill_md(
    skill_name: str,
    article_id: str,
    title: str,
    extraction_result: Dict[str, Any],
) -> str:
    iocs = extraction_result["iocs"]
    mitre = extraction_result.get("mitre_techniques", ["T1059"])
    behaviors = extraction_result.get("attack_behaviors", [])
    summary = extraction_result.get("summary", "") or f"CTI defense skill synthesized from {title}."
    evidences = extraction_result.get("xai_evidences", [])

    fm = {
        "name": skill_name,
        "description": summary[:220],
        "article_id": article_id,
        "mitre_techniques": mitre,
        "generated_by": "CTI Local AI Agent (Ollama)",
        "generated_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
    }
    fm_yaml = yaml.safe_dump(fm, sort_keys=False, allow_unicode=True).strip()

    lines = [
        "---",
        fm_yaml,
        "---",
        "",
        f"# {title}",
        "",
        "## Threat Overview",
        summary,
        "",
        "## Verified Indicators of Compromise (xAI Grounded)",
        f"- **IPs**: {', '.join(iocs.get('ips', [])) or 'None'}",
        f"- **Domains**: {', '.join(iocs.get('domains', [])) or 'None'}",
        f"- **URLs**: {', '.join(iocs.get('urls', [])) or 'None'}",
        f"- **SHA256**: {', '.join(iocs.get('sha256', [])) or 'None'}",
        f"- **MD5**: {', '.join(iocs.get('md5', [])) or 'None'}",
        f"- **CVEs**: {', '.join(iocs.get('cves', [])) or 'None'}",
        f"- **MITRE ATT&CK**: {', '.join(mitre)}",
        f"- **Observable Behaviors**: {', '.join(behaviors) or 'None'}",
        "",
        "## Agent Standard Operating Procedure (SOP)",
        "1. Review `references/xai_audit_trail.json` and `references/cti_verbatim_report.txt` for verbatim evidence.",
        "2. Apply network isolation using verified clean indicators in `references/c2_ip_indicators.txt` (Fail-Closed Whitelist enforced).",
        "3. Execute `python scripts/verify_threat.py` against telemetry logs, binary buffers, or network events to detect matching threat activity.",
        "",
        "## Analyst Context Notes",
        *([f"- {n}" for n in extraction_result.get("context_notes", [])] or [f"- {summary}"]),
        "",
        "## xAI Evidence Sample",
    ]
    for ev in evidences[:5]:
        lines.append(f"- `{ev['type']}` `{ev['value']}` -> \"{ev['evidence_quote']}\"")
    return "\n".join(lines) + "\n"


def _build_deterministic_manifest(
    skill_name: str,
    article_id: str,
    title: str,
    extraction_result: Dict[str, Any],
) -> str:
    iocs = extraction_result["iocs"]
    manifest = {
        "name": skill_name,
        "version": "1.0.0",
        "title": title,
        "article_id": article_id,
        "mitre_techniques": extraction_result.get("mitre_techniques", ["T1059"]),
        "ioc_summary": {k: len(v) for k, v in iocs.items()},
        "tools": [
            {
                "name": "verify_threat",
                "script": "scripts/verify_threat.py",
                "entrypoint": "scan_artifact",
                "description": "Scan telemetry JSON events, byte buffers, or network indicators against verified CTI IOCs.",
            }
        ],
        "references": [
            "references/c2_ip_indicators.txt",
            "references/cti_verbatim_report.txt",
            "references/xai_audit_trail.json",
        ],
    }
    return json.dumps(manifest, indent=2, ensure_ascii=False)


def _build_deterministic_verify_script(
    skill_name: str,
    extraction_result: Dict[str, Any],
) -> str:
    iocs = extraction_result["iocs"]
    behaviors = extraction_result.get("attack_behaviors", [])
    payload = {
        "ips": iocs.get("ips", []),
        "domains": [d.lower() for d in iocs.get("domains", [])],
        "urls": iocs.get("urls", []),
        "hashes": [h.lower() for h in (iocs.get("sha256", []) + iocs.get("md5", []))],
        "cves": [c.upper() for c in iocs.get("cves", [])],
        "behaviors": [b for b in behaviors if len(b) >= 4],
    }
    iocs_json = json.dumps(payload, ensure_ascii=False, indent=4)
    return f'''#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Executable Verification Probe for Agentic Skill: {skill_name}"""

import argparse
import json
from typing import Any, Dict, List, Optional

SKILL_NAME = {json.dumps(skill_name)}
BENIGN_ALLOWLIST = {{
    "8.8.8.8", "8.8.4.4", "1.1.1.1", "1.0.0.1", "127.0.0.1", "0.0.0.0",
    "google.com", "microsoft.com", "github.com", "cloudflare.com", "cisa.gov",
    "time.windows.com", "pypi.org",
}}

THREAT_INDICATORS = {iocs_json}


def _contains_token(haystack: str, needle: str) -> bool:
    return bool(needle) and needle.lower() in haystack.lower()


def scan_artifact(
    log_event: Optional[Dict[str, Any]] = None,
    payload_bytes: Optional[bytes] = None,
    indicator: Optional[str] = None,
) -> Dict[str, Any]:
    matches: List[str] = []

    if indicator:
        ind_clean = indicator.strip().lower()
        if ind_clean in BENIGN_ALLOWLIST:
            return {{"skill_name": SKILL_NAME, "detected": False, "matched_indicators": [], "allowlisted": True}}
        for grp in ("ips", "domains", "urls", "hashes", "cves"):
            for tok in THREAT_INDICATORS.get(grp, []):
                if ind_clean == tok.lower() or ind_clean in tok.lower():
                    matches.append(f"{{grp}}:{{tok}}")

    if log_event is not None:
        flat_vals = " ".join(str(v) for v in log_event.values() if v is not None)
        if not any(b == flat_vals.strip().lower() for b in BENIGN_ALLOWLIST):
            for grp in ("ips", "domains", "urls", "hashes", "cves", "behaviors"):
                for tok in THREAT_INDICATORS.get(grp, []):
                    if _contains_token(flat_vals, tok):
                        matches.append(f"{{grp}}:{{tok}}")

    if payload_bytes is not None:
        text_buf = payload_bytes.decode("utf-8", errors="ignore")
        for grp in ("ips", "domains", "urls", "hashes", "cves", "behaviors"):
            for tok in THREAT_INDICATORS.get(grp, []):
                if _contains_token(text_buf, tok):
                    matches.append(f"{{grp}}:{{tok}}")

    unique_matches = list(dict.fromkeys(matches))
    return {{
        "skill_name": SKILL_NAME,
        "detected": len(unique_matches) > 0,
        "matched_indicators": unique_matches,
    }}


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=f"Run Skill probe {{SKILL_NAME}}")
    parser.add_argument("--indicator", type=str, default=None)
    parser.add_argument("--json-log", type=str, default=None)
    parser.add_argument("--payload-file", type=str, default=None)
    args = parser.parse_args()

    ev = json.loads(args.json_log) if args.json_log else None
    buf = open(args.payload_file, "rb").read() if args.payload_file else None
    print(json.dumps(scan_artifact(log_event=ev, payload_bytes=buf, indicator=args.indicator), ensure_ascii=False, indent=2))
'''


def generate_skill_with_local_llm(
    article_id: str,
    title: str,
    content: str,
    extraction_result: Dict[str, Any],
    model: str = "qwen3:8b",
    output_root: Optional[Path] = None,
) -> Dict[str, Any]:
    """
    Buoc 2 Pipeline: Dung Local LLM (Ollama) dong goi Agentic Defense Skill hoan chinh:
      1. SKILL.md (YAML frontmatter + Threat SOP)
      2. manifest.json (Agent loader schema)
      3. scripts/verify_threat.py (Python probe/detector thuc thi duoc)
      4. references/ (c2_ip_indicators.txt, cti_verbatim_report.txt, xai_audit_trail.json)
    """
    iocs = extraction_result["iocs"]
    mitre = extraction_result.get("mitre_techniques", ["T1059"])
    behaviors = extraction_result.get("attack_behaviors", [])
    summary = extraction_result.get("summary", "")
    skill_name = _make_skill_slug(article_id, title)

    skill_context = json.dumps({
        "skill_name": skill_name,
        "article_id": article_id,
        "title": title,
        "summary": summary,
        "iocs": {k: v[:12] for k, v in iocs.items()},
        "mitre_techniques": mitre,
        "attack_behaviors": behaviors[:10],
        "context_notes": extraction_result.get("context_notes", [])[:5],
    }, ensure_ascii=False, indent=2)

    skill_sys = (
        "You are an AI Security Engineer creating a concise Agentic Defense Skill Package from verified CTI IOCs.\n"
        "Start your reply immediately with ===SKILL_MD_START=== and output THREE exact delimited blocks:\n"
        "===SKILL_MD_START===\n"
        "---\n"
        "name: <skill_name>\n"
        "description: <1-sentence summary>\n"
        "---\n"
        "# <Title>\n"
        "## Threat Overview\n"
        "<2 concise sentences>\n"
        "## Verified IOCs\n"
        "- IPs/Domains/Hashes/CVEs\n"
        "## Analyst Context Notes\n"
        "- Context notes explaining true C2 vs abused benign infrastructure & telemetry focus\n"
        "## Agent SOP\n"
        "1. Verify `references/xai_audit_trail.json`\n"
        "2. Run `python scripts/verify_threat.py`\n"
        "===SKILL_MD_END===\n"
        "===MANIFEST_JSON_START===\n"
        "{\"name\": \"<skill_name>\", \"version\": \"1.0.0\", \"article_id\": \"<id>\", \"tools\": [{\"name\": \"verify_threat\", \"script\": \"scripts/verify_threat.py\"}], \"references\": [\"references/c2_ip_indicators.txt\", \"references/xai_audit_trail.json\"]}\n"
        "===MANIFEST_JSON_END===\n"
        "===SCRIPT_PY_START===\n"
        "ALLOWLIST = {\"8.8.8.8\", \"8.8.4.4\", \"1.1.1.1\", \"google.com\", \"microsoft.com\"}\n"
        "INDICATORS = [<exact verified IOC strings lowercase>]\n"
        "def scan_artifact(log_event=None, payload_bytes=None, indicator=None):\n"
        "    hay = \"\"\n"
        "    if indicator and indicator.strip().lower() not in ALLOWLIST: hay += \" \" + indicator\n"
        "    if log_event: hay += \" \" + \" \".join(str(v) for v in log_event.values())\n"
        "    if payload_bytes: hay += \" \" + payload_bytes.decode(\"utf-8\", \"ignore\")\n"
        "    hay_low = hay.lower()\n"
        "    matched = [i for i in INDICATORS if i and i not in ALLOWLIST and i in hay_low]\n"
        "    return {\"detected\": len(matched) > 0, \"matched_indicators\": matched}\n"
        "===SCRIPT_PY_END===\n"
    )

    raw_skill_md = ""
    raw_manifest = ""
    raw_script_py = ""
    try:
        llm_skill_raw = call_ollama_chat(
            model=model,
            system_prompt=skill_sys,
            user_prompt=f"Synthesize concise SKILL.md, manifest.json, and scripts/verify_threat.py for this CTI:\n{skill_context}",
            json_mode=False,
            temperature=0.05,
            timeout=90,
            num_predict=1100,
        )
        m_md = re.search(r"===SKILL_MD_START===\s*(.*?)\s*===SKILL_MD_END===", llm_skill_raw, re.S)
        if not m_md:
            m_md = re.search(r"^(---\s*\n.*?)(?====SKILL_MD_END===|===MANIFEST_JSON_START===)", llm_skill_raw.strip(), re.S)
        m_mn = re.search(r"===MANIFEST_JSON_START===\s*(.*?)\s*===MANIFEST_JSON_END===", llm_skill_raw, re.S)
        m_py = re.search(r"===SCRIPT_PY_START===\s*(.*?)\s*===SCRIPT_PY_END===", llm_skill_raw, re.S)
        if m_md:
            raw_skill_md = _strip_code_fences(m_md.group(1))
        if m_mn:
            raw_manifest = _strip_code_fences(m_mn.group(1))
        if m_py:
            raw_script_py = _strip_code_fences(m_py.group(1))
    except Exception:
        pass

    sample_ioc = next(
        (x for grp in ("ips", "domains", "urls", "sha256", "md5", "cves") for x in iocs.get(grp, [])),
        "",
    )
    raw_md_ok, raw_md_msg = validate_skill_markdown(raw_skill_md)
    raw_manifest_ok, raw_manifest_msg = validate_manifest_json(raw_manifest)
    raw_script_ok, raw_script_msg = validate_skill_script(raw_script_py, sample_ioc=sample_ioc)

    final_skill_md = raw_skill_md
    final_md_ok, final_md_msg = raw_md_ok, raw_md_msg
    if not raw_md_ok:
        final_skill_md = _build_deterministic_skill_md(skill_name, article_id, title, extraction_result)
        final_md_ok, final_md_msg = validate_skill_markdown(final_skill_md)

    final_manifest = raw_manifest
    final_manifest_ok, final_manifest_msg = raw_manifest_ok, raw_manifest_msg
    if not raw_manifest_ok:
        final_manifest = _build_deterministic_manifest(skill_name, article_id, title, extraction_result)
        final_manifest_ok, final_manifest_msg = validate_manifest_json(final_manifest)

    final_script_py = raw_script_py
    final_script_ok, final_script_msg = raw_script_ok, raw_script_msg
    if not raw_script_ok:
        final_script_py = _build_deterministic_verify_script(skill_name, extraction_result)
        final_script_ok, final_script_msg = validate_skill_script(final_script_py, sample_ioc=sample_ioc)

    ref_indicators: List[str] = []
    for ip in iocs.get("ips", []):
        if is_valid_malicious_ip(ip):
            ref_indicators.append(ip)
    for dom in iocs.get("domains", []):
        if is_valid_malicious_domain(dom):
            ref_indicators.append(dom)
    for u in iocs.get("urls", []):
        if is_valid_malicious_url(u):
            ref_indicators.append(u)
    ref_indicators = list(dict.fromkeys(ref_indicators))
    ref_ok, ref_msg, ref_stats = validate_indicators_reference(ref_indicators)

    xai_audit = {
        "article_id": article_id,
        "title": title,
        "skill_name": skill_name,
        "model": model,
        "context_notes": extraction_result.get("context_notes", []),
        "evidences": extraction_result.get("xai_evidences", []),
        "hallucinated_rejected": extraction_result.get("hallucinated_rejected", []),
    }

    written_path = None
    if output_root is not None:
        bundle_dir = Path(output_root) / skill_name
        (bundle_dir / "scripts").mkdir(parents=True, exist_ok=True)
        (bundle_dir / "references").mkdir(parents=True, exist_ok=True)
        (bundle_dir / "SKILL.md").write_text(final_skill_md, encoding="utf-8")
        (bundle_dir / "manifest.json").write_text(final_manifest, encoding="utf-8")
        (bundle_dir / "scripts" / "verify_threat.py").write_text(final_script_py, encoding="utf-8")
        (bundle_dir / "references" / "c2_ip_indicators.txt").write_text("\n".join(ref_indicators), encoding="utf-8")
        (bundle_dir / "references" / "cti_verbatim_report.txt").write_text(content or "", encoding="utf-8")
        (bundle_dir / "references" / "xai_audit_trail.json").write_text(json.dumps(xai_audit, indent=2, ensure_ascii=False), encoding="utf-8")
        written_path = str(bundle_dir)

    return {
        "skill_name": skill_name,
        "skill_md": final_skill_md,
        "manifest_json": final_manifest,
        "verify_script_py": final_script_py,
        "reference_indicators": ref_indicators,
        "xai_audit_trail": xai_audit,
        "written_path": written_path,
        "syntax_checks": {
            "raw_llm_skill_md_valid": raw_md_ok,
            "raw_llm_skill_md_msg": raw_md_msg,
            "final_skill_md_valid": final_md_ok,
            "final_skill_md_msg": final_md_msg,
            "raw_llm_manifest_valid": raw_manifest_ok,
            "raw_llm_manifest_msg": raw_manifest_msg,
            "final_manifest_valid": final_manifest_ok,
            "final_manifest_msg": final_manifest_msg,
            "raw_llm_script_valid": raw_script_ok,
            "raw_llm_script_msg": raw_script_msg,
            "final_script_valid": final_script_ok,
            "final_script_msg": final_script_msg,
            "reference_indicators_valid": ref_ok,
            "reference_indicators_msg": ref_msg,
            "reference_indicators_stats": ref_stats,
        },
    }


def run_single_article_pipeline(
    article_id: str,
    title: str,
    content: str,
    model: str = "qwen3:8b",
    output_root: Optional[Path] = None,
    progress_callback: Optional[Any] = None,
) -> Dict[str, Any]:
    if progress_callback:
        progress_callback("checking_ollama", f"Đang kiểm tra Ollama & model {model}...")
    ok, active_model = ensure_ollama_running(model)
    if not ok:
        raise RuntimeError(active_model)
    if progress_callback:
        progress_callback("extracting_iocs", f"Bước 1/2: AI ({active_model}) đang đọc bài báo & trích xuất IOC + Context Notes...")
    extraction = extract_iocs_with_local_llm(title=title, content=content, model=active_model, progress_callback=progress_callback)
    if progress_callback:
        progress_callback("generating_skill", f"Bước 2/2: AI ({active_model}) đang tổng hợp Agentic Skill (SKILL.md, verify_threat.py)...")
    skill_pkg = generate_skill_with_local_llm(
        article_id=article_id,
        title=title,
        content=content,
        extraction_result=extraction,
        model=active_model,
        output_root=output_root,
    )
    return {
        "article_id": article_id,
        "title": title,
        "model": active_model,
        "extraction": extraction,
        "skill_package": skill_pkg,
    }
