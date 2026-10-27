import sqlite3
from collections import defaultdict

conn = sqlite3.connect('cti_multi_source_archive.sqlite')
conn.row_factory = sqlite3.Row

print("=== 1. TỔNG SỐ BÀI THEO TỪNG NGUỒN ===")
rows = conn.execute("SELECT source_name, count(*) as cnt FROM articles_archive GROUP BY source_name ORDER BY cnt DESC").fetchall()
for r in rows:
    print(f"- {r['source_name']}: {r['cnt']} bài")

print("\n=== 2. THỐNG KÊ SỐ BÀI TRUNG BÌNH THEO NGÀY TRONG NĂM 2026 ===")
days = conn.execute("""
    SELECT substr(sort_ts, 1, 10) as day_str, count(*) as cnt 
    FROM articles_archive 
    WHERE sort_ts >= '2026-01-01' AND sort_ts <= '2026-12-31'
    GROUP BY day_str 
    ORDER BY day_str DESC
""").fetchall()

print(f"Tổng số ngày có bài phát hành trong 2026: {len(days)} ngày")
total_arts_2026 = sum(d['cnt'] for d in days)
print(f"Tổng số bài năm 2026: {total_arts_2026} bài")
if days:
    avg = total_arts_2026 / len(days)
    print(f"Trung bình các ngày có bài: {avg:.2f} bài/ngày")

print("\n20 ngày gần nhất:")
for d in days[:20]:
    print(f"  + {d['day_str']}: {d['cnt']} bài")

print("\n=== 3. THỐNG KÊ CHI TIẾT TỪNG NGUỒN THEO NGÀY (THỰC TẾ TRÊN TOÀN CẦU) ===")
# Kiểm tra số ngày hoạt động và trung bình của từng nguồn
for r in rows:
    src = r['source_name']
    src_days = conn.execute("""
        SELECT substr(sort_ts, 1, 10) as day_str, count(*) as cnt
        FROM articles_archive
        WHERE source_name = ? AND sort_ts >= '2026-01-01'
        GROUP BY day_str
    """, (src,)).fetchall()
    cnt_2026 = sum(d['cnt'] for d in src_days)
    if src_days:
        print(f"* {src}: {cnt_2026} bài trong {len(src_days)} ngày xuất bản (Trung bình: {cnt_2026/len(src_days):.2f} bài/ngày có xuất bản)")
    else:
        print(f"* {src}: Không có bài trong 2026 (thuộc dữ liệu lịch sử 2024-2025)")
