import sqlite3
from pathlib import Path

db_path = Path(__file__).resolve().parent / "cti_multi_source_archive.sqlite"
conn = sqlite3.connect(db_path)
rows = conn.execute("SELECT article_id, source_name, title, sort_ts, processing_time_sec, last_analyzed_at FROM articles_archive WHERE status = 'completed' ORDER BY last_analyzed_at DESC").fetchall()
print(f"Total completed: {len(rows)}")
for r in rows:
    print(f"[{r[5]}] (pub: {r[3]}) ({r[4]}s) {r[1]}: {r[2][:45]}")
conn.close()
