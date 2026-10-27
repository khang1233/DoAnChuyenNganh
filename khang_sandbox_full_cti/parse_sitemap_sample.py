import urllib.request
import re
import xml.etree.ElementTree as ET
from datetime import datetime

def parse_thn_sitemap():
    articles = []
    ns = {'ns': 'http://www.sitemaps.org/schemas/sitemap/0.9'}
    for p in range(1, 8):
        url = f"https://thehackernews.com/sitemap.xml?page={p}"
        req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)'})
        try:
            with urllib.request.urlopen(req, timeout=10) as r:
                txt = r.read().decode('utf-8')
                root = ET.fromstring(txt)
                for u in root.findall('ns:url', ns):
                    loc = u.findtext('ns:loc', '', ns)
                    lastmod = u.findtext('ns:lastmod', '', ns)
                    # Check if 2024, 2025, 2026
                    m = re.search(r'/(202[456])/(\d{2})/(.*?)\.html', loc)
                    if m:
                        year = m.group(1)
                        month = m.group(2)
                        slug = m.group(3)
                        # Generate clean title from slug
                        title = slug.replace('-', ' ').title()
                        articles.append({
                            'url': loc,
                            'published_date': lastmod[:10] if lastmod else f"{year}-{month}-01",
                            'year': year,
                            'title': title,
                            'slug': slug
                        })
        except Exception as e:
            print(f"Error page {p}: {e}")
            break
    return articles

if __name__ == '__main__':
    arts = parse_thn_sitemap()
    print(f"Total parsed: {len(arts)}")
    by_year = {}
    for a in arts:
        by_year[a['year']] = by_year.get(a['year'], 0) + 1
    print("Breakdown by year:", by_year)
