# [VULNERABLE] Python Backend — Cho phép RCE qua os.system() và SQLi qua f-string
import os
import sqlite3
from flask import Flask, request, jsonify

app = Flask(__name__)

# Lỗ hổng 1: Command Injection (RCE)
@app.route('/api/system/service_action')
def service_action():
    svc = request.args.get('service', '')
    # Nguy hiểm: os.system chạy shell trực tiếp, cho phép chèn lệnh qua ; | &&
    os.system(f"systemctl restart {svc}")
    return jsonify({"status": "executed"})

# Lỗ hổng 2: SQL Injection
@app.route('/api/articles')
def get_articles():
    keyword = request.args.get('q', '')
    conn = sqlite3.connect("database.db")
    cur = conn.execute(f"SELECT id, title FROM articles WHERE title LIKE '%{keyword}%'")
    return jsonify(cur.fetchall())
