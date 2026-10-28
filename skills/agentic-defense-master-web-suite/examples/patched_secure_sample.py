# [HARDENED] Python Backend — Whitelist enum, subprocess.run(shell=False), Parameterized SQL
import subprocess
import sqlite3
from flask import Flask, request, jsonify

app = Flask(__name__)
ALLOWED_SERVICES = {"nginx", "gunicorn", "redis", "celery", "node_app"}

# Khắc phục RCE: Whitelist kiểm tra giá trị + subprocess.run với shell=False
@app.route('/api/system/service_action')
def service_action():
    svc = request.args.get('service', '').strip()
    if svc not in ALLOWED_SERVICES:
        return jsonify({"error": "Dịch vụ không nằm trong Whitelist được phép"}), 400
        
    # An toàn tuyệt đối: shell=False, mảng đối số tường minh
    res = subprocess.run(["systemctl", "restart", svc], capture_output=True, text=True, timeout=5, check=False)
    return jsonify({"status": "success", "service": svc, "code": res.returncode})

# Khắc phục SQLi: Sử dụng Parameterized Queries
@app.route('/api/articles')
def get_articles():
    keyword = request.args.get('q', '').strip()
    with sqlite3.connect("database.db") as conn:
        cur = conn.execute("SELECT id, title FROM articles WHERE title LIKE ? ESCAPE '\\'", (f"%{keyword}%",))
        return jsonify(cur.fetchall())
