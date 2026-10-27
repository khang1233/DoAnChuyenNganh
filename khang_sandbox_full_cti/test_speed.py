import urllib.request
import time
import concurrent.futures
import re

urls = [
    "https://thehackernews.com/2026/10/connectwise-suspends-cloud-backup-after.html",
    "https://thehackernews.com/2026/10/malfex-npm-package-imgdecode-hides.html",
    "https://thehackernews.com/2026/10/hackers-use-compromised-connectwise.html",
    "https://thehackernews.com/2026/10/researchers-demonstrate-openbsd-root.html",
    "https://thehackernews.com/2026/10/attackers-tampered-with-aomei.html",
    "https://thehackernews.com/2026/10/uat-11985-uses-fake-event-invites-to.html",
    "https://thehackernews.com/2026/10/openai-research-model-spent-3rd-party.html",
    "https://thehackernews.com/2026/10/critical-cisco-asa-ftd-vulnerability.html",
    "https://thehackernews.com/2026/10/north-korean-hackers-target-crypto.html",
    "https://thehackernews.com/2026/10/critical-ivanti-endpoint-manager-flaws.html"
]

def fetch_one(url):
    req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"})
    try:
        with urllib.request.urlopen(req, timeout=5) as resp:
            html = resp.read().decode("utf-8", errors="ignore")
            m_title = re.search(r'<title>(.*?)</title>', html, re.I)
            title = m_title.group(1).split('|')[0].strip() if m_title else ""
            m_body = re.search(r'id=[\'"]articlebody[\'"][^>]*>(.*?)<div class=[\'"]clear', html, re.S | re.I)
            body = m_body.group(1) if m_body else ""
            clean_body = re.sub(r'<[^>]+>', ' ', body).strip()
            clean_body = re.sub(r'\s+', ' ', clean_body)
            return {"url": url, "title": title, "len": len(clean_body), "content": clean_body[:500]}
    except Exception as e:
        return {"url": url, "error": str(e)}

t0 = time.time()
with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
    results = list(executor.map(fetch_one, urls))
elapsed = time.time() - t0
print(f"Fetched {len(results)} articles in {elapsed:.2f} seconds!")
for r in results[:3]:
    print(" -", r.get("title", ""), f"({r.get('len', 0)} chars)")
