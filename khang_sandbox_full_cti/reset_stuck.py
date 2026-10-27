import sqlite3
from pathlib import Path

db_path = Path(__file__).resolve().parent / "cti_multi_source_archive.sqlite"
conn = sqlite3.connect(db_path)
conn.execute("UPDATE articles_archive SET status = 'pending' WHERE status = 'processing'")
conn.commit()
counts = conn.execute("SELECT status, count(*) FROM articles_archive GROUP BY status").fetchall()
print("New Status counts:", counts)
conn.close()
