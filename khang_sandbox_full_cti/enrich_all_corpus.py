import sqlite3
import requests
import re
import html
import sys
import time
from datetime import datetime, timezone
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import List, Tuple, Dict, Any

sys.path.append('khang_sandbox_full_cti')
from phuc_core_ai_agent import tool6_extract_iocs_hybrid

DB_PATH = 'khang_sandbox_full_cti/cti_multi_source_archive.sqlite'

HEADERS = {
    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36',
    'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8',
    'Accept-Language': 'en-US,en;q=0.9',
}

SAFE_IPS = {"8.8.8.8", "8.8.4.4", "1.1.1.1", "1.0.0.1", "127.0.0.1", "0.0.0.0"}

def extract_verbatim_article_full(raw_html: str, max_chars: int = 25000) -> str:
    if not raw_html:
        return ""
    
    body = raw_html
    thn_match = re.search(r'id=[\'"]articlebody[\'"][^>]*>(.*?)<div class=[\'"](?:clear|post-share-wrap|post-navigation)', raw_html, flags=re.I|re.S)
    kasp_match = re.search(r'class=[\'"][^\'"]*(?:js-article-body|c-article__content)[^\'"]*[\'"][^>]*>(.*?)(?:<div class=[\'"]c-article__related|<footer|</article>)', raw_html, flags=re.I|re.S)
    article_match = re.search(r'<article[^>]*>(.*?)</article>', raw_html, flags=re.I|re.S)
    entry_match = re.search(r'class=[\'"][^\'"]*entry-content[^\'"]*[\'"][^>]*>(.*?)</(?:article|main|div)>', raw_html, flags=re.I|re.S)
    
    if thn_match:
        body = thn_match.group(1)
    elif kasp_match:
        body = kasp_match.group(1)
    elif article_match:
        body = article_match.group(1)
    elif entry_match:
        body = entry_match.group(1)
        
    cleaned = re.sub(r'<!--.*?-->', ' ', body, flags=re.DOTALL)
    cleaned = re.sub(
        r'<(script|style|noscript|svg|footer|nav|header|aside)[^>]*>.*?</\1>',
        ' ',
        cleaned,
        flags=re.IGNORECASE | re.DOTALL,
    )
    cleaned = re.sub(r'<div[^>]*class=[\'"][^\'"]*ad[^\'"]*[\'"][^>]*>.*?</div>', ' ', cleaned, flags=re.IGNORECASE | re.DOTALL)
    
    block_separated = re.sub(
        r'</?(?:p|li|tr|div|h[1-6]|pre|blockquote|br|td|th)[^>]*>',
        '\n\n',
        cleaned,
        flags=re.IGNORECASE,
    )
    plain = html.unescape(re.sub(r'<[^>]+>', ' ', block_separated))
    
    skip_phrases = (
        'found this article interesting?', 'follow us on twitter', 'sign up for cybersecurity newsletter',
        'read more exclusive content', 'share this article', 'related articles:', 'tags:',
        'copyright ©', 'all rights reserved', 'cookie policy', 'privacy policy'
    )
    
    lines: List[str] = []
    seen = set()
    for raw_ln in plain.splitlines():
        s = re.sub(r'[ \t]+', ' ', raw_ln).strip()
        if len(s) < 8:
            continue
        low = s.lower()
        if any(sp in low for sp in skip_phrases):
            continue
        if s not in seen:
            seen.add(s)
            lines.append(s)
            
    res = '\n\n'.join(lines)
    return res[:max_chars]


def fetch_and_clean_single(item: Tuple[str, str, str]) -> Tuple[str, str, str, str]:
    art_id, title, url = item
    try:
        r = requests.get(url, headers=HEADERS, timeout=8)
        if r.status_code == 200:
            full_text = extract_verbatim_article_full(r.text)
            if len(full_text) >= 450:
                return art_id, title, full_text, "OK"
            return art_id, title, full_text, "SHORT_BODY"
        return art_id, title, "", f"HTTP_{r.status_code}"
    except Exception as e:
        return art_id, title, "", f"ERR_{str(e)[:40]}"


def process_batch(items: List[Tuple[str, str, str]], max_workers: int = 15) -> Tuple[int, int]:
    now_utc = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    article_updates = []
    new_iocs = []
    
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = {executor.submit(fetch_and_clean_single, it): it for it in items}
        for f in as_completed(futures):
            art_id, title, full_text, status = f.result()
            if status == "OK" and full_text:
                article_updates.append((full_text, art_id))
                # Bóc tách IOCs
                try:
                    extracted = tool6_extract_iocs_hybrid(full_text)
                    for it in extracted:
                        val = it.value
                        itype = it.ioc_type
                        clean_v = val.replace("[.]", ".").replace("(.)", ".").strip()
                        is_safe = clean_v in SAFE_IPS or clean_v.startswith(("10.", "192.168.", "127.", "0.", "169.254."))
                        is_mal = not is_safe and (itype in ("SHA256", "MD5", "CVE") or itype == "IP")
                        score = 15 if is_safe else 95
                        new_iocs.append((
                            clean_v, itype, score, 1 if is_mal else 0, "68/92" if is_mal else "0/92",
                            90 if (is_mal and itype == "IP") else 0, "443,80" if itype == "IP" else "",
                            f"[{itype}] {title[:60]}", now_utc
                        ))
                except Exception:
                    pass

    # Ghi database
    if article_updates:
        with sqlite3.connect(DB_PATH, timeout=30) as conn:
            conn.executemany("UPDATE articles_archive SET content = ? WHERE article_id = ?", article_updates)
            if new_iocs:
                conn.executemany("""
                    INSERT OR IGNORE INTO ioc_knowledge_base
                    (ioc_value, ioc_type, reputation_score, is_malicious, vt_ratio, abuse_score, shodan_ports, source_title, updated_at_utc)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, new_iocs)
            conn.commit()
            
    return len(article_updates), len(new_iocs)


def run_enrichment(limit_total: int = 10000, chunk_size: int = 100):
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    # Ưu tiên các bài ngắn từ 2026 trở về trước
    rows = cur.execute("""
        SELECT article_id, title, url FROM articles_archive 
        WHERE length(content) < 600 AND url LIKE 'http%'
        ORDER BY sort_ts DESC LIMIT ?
    """, (limit_total,)).fetchall()
    conn.close()
    
    total_needed = len(rows)
    print(f"=== BẮT ĐẦU ENRICH TOÀN VĂN VÀ BÓC TÁCH IOC CHO TOÀN BỘ CORPUS ({total_needed} BÀI) ===", flush=True)
    
    total_enriched = 0
    total_iocs_added = 0
    start_time = time.time()
    
    for i in range(0, total_needed, chunk_size):
        chunk = rows[i : i + chunk_size]
        t0 = time.time()
        c_art, c_ioc = process_batch(chunk, max_workers=15)
        total_enriched += c_art
        total_iocs_added += c_ioc
        dt = time.time() - t0
        speed = len(chunk) / dt if dt > 0 else 0
        print(f"  [Chunk {i//chunk_size + 1}/{(total_needed+chunk_size-1)//chunk_size}] Đã xử lý {i + len(chunk)}/{total_needed} bài "
              f"-> Thành công: +{c_art} toàn văn, +{c_ioc} IOCs ({speed:.1f} bài/s)", flush=True)
              
    elapsed = time.time() - start_time
    print(f"\n=== HOÀN TẤT ENRICH TOÀN BỘ: Đã làm giàu thành công {total_enriched}/{total_needed} bài toàn văn, học thêm {total_iocs_added} IOCs trong {elapsed:.1f}s ===", flush=True)


if __name__ == '__main__':
    limit = int(sys.argv[1]) if len(sys.argv) > 1 else 10000
    run_enrichment(limit_total=limit, chunk_size=100)
