import argparse
import sqlite3
import re
import json
import html as html_lib
import ipaddress
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from html.parser import HTMLParser
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple
import requests

DB_FULL = Path("cti_core/cti_multi_source_archive_full_corpus.sqlite")
DB_MAIN = Path("cti_core/cti_multi_source_archive.sqlite")
OUT_DIR = Path("cti_core/benchmark")
OUT_DIR.mkdir(parents=True, exist_ok=True)

RE_IP = re.compile(r"\b(?:\d{1,3}(?:\[\.\]|\.)){3}\d{1,3}\b")
RE_CVE = re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.I)
RE_SHA256 = re.compile(r"\b[a-fA-F0-9]{64}\b")
RE_MD5 = re.compile(r"\b[a-fA-F0-9]{32}\b")
RE_URL = re.compile(r"(?:hxxps?|https?)://[^\s\"'<>)\]]+", re.I)
RE_DEFANG_DOM = re.compile(r"\b(?:[a-z0-9-]+(?:\[\.\]|\(\.\)|\.))*[a-z0-9-]+(?:\[\.\]|\(\.\))[a-z]{2,12}\b", re.I)

EXCLUDE_TITLE_KEYWORDS = [
    "weekly recap", "threatsday", "roundup", "digest", "month in", "year in review",
    "top vulnerabilities", "patch tuesday", "microsoft patches", "apple patches"
]

VERSION_CONTEXT_KW = (
    "version", "versions", "v.", "release", "build", "chrome", "firefox", "edge",
    "safari", "ios", "android", "windows", "macos", "prior to", "before", "through",
    "fixed in", "patched in", "update to", "upgrade to", "firmware", "sdk", "node",
    "python", "php", "openssl", "fortios", "fortisiem", "pan-os", "cpanel", "ios xe"
)

def is_likely_real_ip(raw_ip: str, content: str, span: tuple) -> bool:
    clean = raw_ip.replace("[.]", ".").replace("(.)", ".")
    try:
        ip_obj = ipaddress.ip_address(clean)
    except ValueError:
        return False
    # If defanged [.], almost certainly a real IOC
    if "[.]" in raw_ip or "(.)" in raw_ip:
        return True
    if ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_multicast:
        return False
    if clean in {"8.8.8.8", "8.8.4.4", "1.1.1.1", "1.0.0.1", "0.0.0.0", "255.255.255.255"}:
        return False
    start, end = span
    ctx = content[max(0, start - 65):min(len(content), end + 45)].lower()
    if any(k in ctx for k in VERSION_CONTEXT_KW):
        return False
    # Version numbers often start with 0.x or small build octets in software versions like 14.2.1.0
    parts = [int(p) for p in clean.split(".")]
    if parts[0] == 0:
        return False
    return True

def build_50_articles_dataset():
    db_path = DB_FULL if DB_FULL.exists() else DB_MAIN
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    rows = conn.execute(
        """
        SELECT article_id, source_name, title, url, published_date, sort_ts, content
        FROM articles_archive
        WHERE sort_ts >= '2026-01-01' AND sort_ts <= '2026-06-30'
          AND length(content) BETWEEN 1200 AND 18000
        ORDER BY sort_ts ASC
        """
    ).fetchall()

    candidates = []
    seen_titles = set()
    seen_urls = set()

    for r in rows:
        title = (r["title"] or "").strip()
        tl = title.lower()
        if any(k in tl for k in EXCLUDE_TITLE_KEYWORDS):
            continue
        url = (r["url"] or "").strip()
        if any(bad_u in url for bad_u in ("/2025/", "/2024/", "/2023/", "/tr/", "/es/", "/pt/", "/ru/")):
            continue
        norm_t = re.sub(r"[^a-z0-9]", "", tl)[:35]
        if not norm_t or norm_t in seen_titles or (url and url in seen_urls):
            continue

        content = (r["content"] or "").strip()
        ips = []
        for m in RE_IP.finditer(content):
            if is_likely_real_ip(m.group(), content, m.span()):
                ips.append(m.group())
        ips = list(dict.fromkeys(ips))
        cves = list(dict.fromkeys(m.upper() for m in RE_CVE.findall(content)))
        shas = list(dict.fromkeys(m.lower() for m in RE_SHA256.findall(content)))
        md5s = list(dict.fromkeys(m.lower() for m in RE_MD5.findall(content)))
        urls = list(dict.fromkeys(u for u in RE_URL.findall(content) if "hxxp" in u.lower() or "[.]" in u))
        doms = list(dict.fromkeys(RE_DEFANG_DOM.findall(content)))

        type_count = (1 if ips else 0) + (1 if cves else 0) + (1 if shas else 0) + (1 if md5s else 0) + (1 if doms else 0) + (1 if urls else 0)
        if type_count < 2:
            continue

        total_hints = len(ips) + len(cves) + len(shas) + len(md5s) + len(doms) + len(urls)
        if total_hints < 2 or total_hints > 80:
            continue

        richness = type_count * 12 + min(total_hints, 20)
        # Bonus if has hashes or defanged C2 IPs/domains
        if shas or md5s:
            richness += 8
        if doms or urls:
            richness += 6

        seen_titles.add(norm_t)
        if url:
            seen_urls.add(url)

        candidates.append({
            "richness": richness,
            "article_id": r["article_id"],
            "source_name": r["source_name"],
            "title": title,
            "url": url,
            "published_date": r["published_date"] or str(r["sort_ts"])[:10],
            "sort_ts": str(r["sort_ts"])[:10],
            "content": content,
            "candidate_hints": {
                "ips": ips,
                "domains": doms,
                "urls": urls,
                "md5s": md5s,
                "sha256s": shas,
                "cves": cves,
            }
        })

    candidates.sort(key=lambda x: (x["richness"], x["sort_ts"]), reverse=True)
    selected = candidates[:68]
    selected.sort(key=lambda x: x["sort_ts"])

    # Hydrate live HTML first so we verify exact live published_date >= 2026-01-01 and true H1/images
    hydrated_pool: List[Dict[str, Any]] = []
    with ThreadPoolExecutor(max_workers=8) as ex:
        fut_map = {ex.submit(_parse_live_article, {
            "index": i + 1,
            "article_id": item["article_id"],
            "source_name": item["source_name"],
            "published_date": item["sort_ts"],
            "title": item["title"],
            "url": item["url"],
            "content": item["content"],
            "candidate_hints": item["candidate_hints"],
        }): item for i, item in enumerate(selected)}
        for fut in as_completed(fut_map):
            upd, status = fut.result()
            pub = str(upd.get("published_date") or "")[:10]
            if upd.get("content_html") and "2026-01-01" <= pub <= "2026-06-30":
                hydrated_pool.append(upd)

    hydrated_pool.sort(key=lambda x: (x["published_date"], x["article_id"]))
    final_50 = hydrated_pool[:50]

    articles_out = []
    gt_template_out = []

    for idx, item in enumerate(final_50, 1):
        articles_out.append({
            **item,
            "index": idx,
        })
        gt_template_out.append({
            "index": idx,
            "article_id": item["article_id"],
            "title": item["title"],
            "source_name": item["source_name"],
            "published_date": item["published_date"],
            "annotation_status": "pending",
            "ground_truth": {
                "ips": [],
                "domains": [],
                "urls": [],
                "md5": [],
                "sha256": [],
                "cves": [],
                "attack_behaviors": []
            },
            "annotator_notes": ""
        })

    articles_file = OUT_DIR / "articles_50_2026.json"
    gt_template_file = OUT_DIR / "ground_truth_50_template.json"
    articles_file.write_text(json.dumps(articles_out, indent=2, ensure_ascii=False), encoding="utf-8")
    gt_template_file.write_text(json.dumps(gt_template_out, indent=2, ensure_ascii=False), encoding="utf-8")

    # Preserve existing manual work if any article already marked 'done'
    gt_live_file = OUT_DIR / "ground_truth_50.json"
    has_done = False
    if gt_live_file.exists():
        old_gt = json.loads(gt_live_file.read_text(encoding="utf-8"))
        has_done = any(x.get("annotation_status") == "done" for x in old_gt)
    if not gt_live_file.exists() or not has_done:
        gt_live_file.write_text(json.dumps(gt_template_out, indent=2, ensure_ascii=False), encoding="utf-8")

    print(f"[+] Saved 50 distinct early-2026 CTI articles to: {articles_file}")
    print(f"[+] Saved annotation template to: {gt_template_file}")
    print(f"[+] Ground Truth working file: {gt_live_file}")
    src_dist = {}
    for a in articles_out:
        src_dist[a["source_name"]] = src_dist.get(a["source_name"], 0) + 1
    print("[*] Source breakdown:", src_dist)


LIVE_HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    "Accept-Language": "en-US,en;q=0.9",
}


def _extract_element_by_marker(raw_html: str, tag_name: str, attr_name: str, attr_substr: str) -> str:
    pat = re.compile(
        rf"<{tag_name}\b[^>]*\b{attr_name}\s*=\s*['\"][^'\"]*{re.escape(attr_substr)}[^'\"]*['\"][^>]*>",
        re.I,
    )
    m = pat.search(raw_html)
    if not m:
        return ""
    start = m.end()
    depth = 1
    tok_pat = re.compile(rf"<(/?){tag_name}\b[^>]*>", re.I)
    pos = start
    while depth > 0:
        tm = tok_pat.search(raw_html, pos)
        if not tm:
            return raw_html[start:]
        if tm.group(1) == "/":
            depth -= 1
            if depth == 0:
                return raw_html[start:tm.start()]
        else:
            if not tm.group(0).rstrip().endswith("/>"):
                depth += 1
        pos = tm.end()
    return ""


class _CleanArticleSanitizer(HTMLParser):
    ALLOWED = {
        "p", "br", "h1", "h2", "h3", "h4", "ul", "ol", "li", "pre", "code",
        "blockquote", "strong", "b", "em", "i", "table", "thead", "tbody",
        "tr", "th", "td", "figure", "figcaption", "img",
    }
    SKIP_TAGS = {"script", "style", "noscript", "svg", "iframe", "form", "button", "nav", "footer", "aside"}
    SKIP_CLASS_KW = (
        "share", "related", "newsletter", "subscribe", "ad-", "ads", "banner",
        "dog_two", "note-b", "stophere", "post-tags", "comment", "social",
        "toc", "table-of-contents",
    )

    def __init__(self, base_url: str = ""):
        super().__init__(convert_charrefs=False)
        self.base_url = base_url
        self.out: List[str] = []
        self.skip_stack: List[str] = []
        self.img_urls: List[str] = []

    def handle_starttag(self, tag: str, attrs: List[Tuple[str, Optional[str]]]):
        t = tag.lower()
        d = {k.lower(): (v or "") for k, v in attrs}
        cls = (d.get("class", "") + " " + d.get("id", "")).lower()
        if self.skip_stack:
            if t not in ("br", "img", "hr"):
                self.skip_stack.append(t)
            return
        if t in self.SKIP_TAGS or any(kw in cls for kw in self.SKIP_CLASS_KW):
            if t not in ("br", "img", "hr"):
                self.skip_stack.append(t)
            return
        if t == "img":
            src = d.get("data-src") or d.get("data-lazy-src") or d.get("data-original") or d.get("src") or ""
            if src.startswith("//"):
                src = "https:" + src
            elif src.startswith("/") and self.base_url:
                src = "/".join(self.base_url.split("/")[:3]) + src
            bad_img = ("doubleclick", "1x1", "pixel", "avatar", "gravatar", "icon-", "logo-", "spacer", "data:image")
            if src.startswith("http") and not any(b in src.lower() for b in bad_img):
                alt = html_lib.escape(d.get("alt", ""), quote=True)
                self.img_urls.append(src)
                self.out.append(f'<img src="{html_lib.escape(src, quote=True)}" alt="{alt}" loading="lazy" />')
            return
        if t in self.ALLOWED:
            if t == "br":
                self.out.append("<br/>")
            else:
                self.out.append(f"<{t}>")

    def handle_endtag(self, tag: str):
        t = tag.lower()
        if self.skip_stack:
            if self.skip_stack[-1] == t:
                self.skip_stack.pop()
            elif t in self.skip_stack:
                while self.skip_stack and self.skip_stack[-1] != t:
                    self.skip_stack.pop()
                if self.skip_stack:
                    self.skip_stack.pop()
            return
        if t in self.ALLOWED and t not in ("br", "img"):
            self.out.append(f"</{t}>")

    def handle_data(self, data: str):
        if not self.skip_stack:
            self.out.append(html_lib.escape(data))

    def handle_entityref(self, name: str):
        if not self.skip_stack:
            self.out.append(f"&{name};")

    def handle_charref(self, name: str):
        if not self.skip_stack:
            self.out.append(f"&#{name};")


def _parse_live_article(art: Dict[str, Any]) -> Tuple[Dict[str, Any], str]:
    url = art.get("url", "")
    try:
        r = requests.get(url, headers=LIVE_HEADERS, timeout=18)
        if r.status_code != 200:
            return art, f"HTTP {r.status_code}"
        raw = r.text
    except Exception as e:
        return art, f"ERR {e}"

    src = art.get("source_name", "")
    author = ""
    tags = ""
    live_date = art.get("published_date", "")

    if "thehackernews.com" in url:
        chunk = _extract_element_by_marker(raw, "div", "id", "articlebody")
        h1_m = (
            re.search(r"<h1[^>]*class=['\"][^'\"]*story-title[^'\"]*['\"][^>]*>(.*?)</h1>", raw, re.I | re.S)
            or re.search(r"<h1[^>]*>(.*?)</h1>", raw, re.I | re.S)
        )
        cal_m = re.search(r"icon-calendar[^>]*>.*?</i>\s*<span[^>]*class=['\"]author['\"][^>]*>(.*?)</span>", raw, re.I | re.S)
        if cal_m:
            raw_d = html_lib.unescape(re.sub(r"<[^>]+>", "", cal_m.group(1))).strip()
            try:
                live_date = datetime.strptime(raw_d, "%b %d, %Y").strftime("%Y-%m-%d")
            except Exception:
                pass
        auth_m = re.search(r"icon-user[^>]*>.*?</i>\s*<span[^>]*class=['\"]author['\"][^>]*>(.*?)</span>", raw, re.I | re.S)
        if auth_m:
            author = html_lib.unescape(re.sub(r"<[^>]+>", "", auth_m.group(1))).strip()
        tag_m = re.search(r"<span[^>]*class=['\"]p-tags['\"][^>]*>(.*?)</span>", raw, re.I | re.S)
        if tag_m:
            tags = html_lib.unescape(re.sub(r"<[^>]+>", "", tag_m.group(1))).strip()
    elif "securelist.com" in url:
        chunk = (
            _extract_element_by_marker(raw, "div", "class", "c-wysiwyg")
            or _extract_element_by_marker(raw, "div", "class", "js-article-body")
            or _extract_element_by_marker(raw, "div", "class", "c-article__content")
        )
        h1_m = re.search(r"<h1[^>]*>(.*?)</h1>", raw, re.I | re.S)
        tm_m = re.search(r"<time[^>]+datetime=['\"]([^'\"]+)['\"]", raw, re.I) or re.search(r"\"datePublished\"\s*:\s*\"([^\"]+)\"", raw, re.I)
        if tm_m:
            live_date = tm_m.group(1)[:10]
    else:
        chunk = _extract_element_by_marker(raw, "div", "class", "entry-content")
        h1_m = re.search(r"<h1[^>]*>(.*?)</h1>", raw, re.I | re.S)
        meta_m = (
            re.search(r"article:published_time['\"]?\s*content=['\"]([^'\"]+)['\"]", raw, re.I)
            or re.search(r"\"datePublished\"\s*:\s*\"([^\"]+)\"", raw, re.I)
        )
        if meta_m:
            live_date = meta_m.group(1)[:10]

    if not chunk:
        return art, f"NO_BODY ({src})"

    sanitizer = _CleanArticleSanitizer(url)
    sanitizer.feed(chunk)
    clean_html = "".join(sanitizer.out).strip()
    clean_html = re.sub(r"<p>\s*Found this article interesting\?.*?</p>", "", clean_html, flags=re.I | re.S)
    clean_html = re.sub(r"<p>\s*</p>", "", clean_html)

    plain = html_lib.unescape(re.sub(r"</(?:p|h[1-4]|li|tr|div|pre|blockquote|figcaption)>|<br\s*/?>", "\n", clean_html))
    plain = re.sub(r"<[^>]+>", " ", plain)
    plain = re.sub(r"[ \t]+\n", "\n", plain)
    plain = re.sub(r"\n{3,}", "\n\n", plain).strip()

    live_title = html_lib.unescape(re.sub(r"<[^>]+>", "", h1_m.group(1))).strip() if h1_m else art["title"]
    if len(plain) < 400:
        return art, f"TOO_SHORT ({len(plain)})"

    ips = []
    for m in RE_IP.finditer(plain):
        if is_likely_real_ip(m.group(), plain, m.span()):
            ips.append(m.group())
    updated = {
        **art,
        "title": live_title or art["title"],
        "published_date": live_date or art["published_date"],
        "author": author,
        "tags": tags,
        "content": plain,
        "content_html": clean_html,
        "image_count": len(sanitizer.img_urls),
        "candidate_hints": {
            "ips": list(dict.fromkeys(ips)),
            "domains": list(dict.fromkeys(RE_DEFANG_DOM.findall(plain))),
            "urls": list(dict.fromkeys(u for u in RE_URL.findall(plain) if "hxxp" in u.lower() or "[.]" in u)),
            "md5s": list(dict.fromkeys(m.lower() for m in RE_MD5.findall(plain))),
            "sha256s": list(dict.fromkeys(m.lower() for m in RE_SHA256.findall(plain))),
            "cves": list(dict.fromkeys(m.upper() for m in RE_CVE.findall(plain))),
        },
    }
    return updated, f"OK len {len(art['content'])}->{len(plain)}, imgs={len(sanitizer.img_urls)}"


def hydrate_50_articles_live():
    articles_file = OUT_DIR / "articles_50_2026.json"
    if not articles_file.exists():
        print("[!] Chua co articles_50_2026.json.")
        return
    arts = json.loads(articles_file.read_text(encoding="utf-8"))
    results: Dict[str, Dict[str, Any]] = {}
    print(f"[*] Dang dong bo noi dung goc + hinh anh + tieu de thuc cho {len(arts)} bai bao...")

    with ThreadPoolExecutor(max_workers=8) as ex:
        fut_map = {ex.submit(_parse_live_article, a): a for a in arts}
        for fut in as_completed(fut_map):
            orig = fut_map[fut]
            upd, status = fut.result()
            results[orig["article_id"]] = upd
            print(f"  #{orig['index']:02d} [{orig['source_name']}] -> {status}")

    hydrated = [results[a["article_id"]] for a in arts]
    articles_file.write_text(json.dumps(hydrated, indent=2, ensure_ascii=False), encoding="utf-8")

    # Sync title & published_date in ground_truth_50.json & template without losing any manual annotations
    for gt_name in ("ground_truth_50_template.json", "ground_truth_50.json"):
        p = OUT_DIR / gt_name
        if p.exists():
            gt_list = json.loads(p.read_text(encoding="utf-8"))
            h_map = {x["article_id"]: x for x in hydrated}
            for g in gt_list:
                h = h_map.get(g["article_id"])
                if h:
                    g["title"] = h["title"]
                    g["published_date"] = h["published_date"]
            p.write_text(json.dumps(gt_list, indent=2, ensure_ascii=False), encoding="utf-8")

    ok_html = sum(1 for a in hydrated if a.get("content_html"))
    tot_imgs = sum(a.get("image_count", 0) for a in hydrated)
    print(f"[+] Hoan tat dong bo: {ok_html}/{len(hydrated)} bai co full HTML + {tot_imgs} hinh anh goc.")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Prepare and hydrate 50 early-2026 CTI articles.")
    parser.add_argument("--rebuild-from-db", action="store_true", help="Rebuild 50-article selection from SQLite archive")
    parser.add_argument("--hydrate-live", action="store_true", help="Fetch full verbatim HTML, images, true H1 titles, and dates from live URLs")
    args = parser.parse_args()
    if args.rebuild_from_db or not (OUT_DIR / "articles_50_2026.json").exists():
        build_50_articles_dataset()
    if args.hydrate_live or not args.rebuild_from_db:
        hydrate_50_articles_live()
