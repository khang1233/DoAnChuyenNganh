import sqlite3
from pathlib import Path

db_path = Path(__file__).resolve().parent / "cti_multi_source_archive.sqlite"
conn = sqlite3.connect(db_path)
rows = conn.execute("SELECT article_id, title, status, processing_time_sec, is_historical, fetched_at_utc, last_analyzed_at FROM articles_archive WHERE status = 'processing'").fetchall()
print(f"Total processing in DB: {len(rows)}")
for r in rows:
    print(r[0], r[1][:40], r[2], r[3], r[4], r[5], r[6])

all_rows = conn.execute("SELECT status, count(*) FROM articles_archive GROUP BY status").fetchall()
print("All statuses:", all_rows)
conn.close()
