# HARDENED & SECURE SAMPLE (Python Backend — Sau khi AI Agent sửa)
import subprocess
from flask import Flask, request, jsonify

app = Flask(__name__)
ALLOWED_SERVICES = {"nginx", "mysql", "redis", "node_app"}

@app.route('/api/system_status')
def system_status():
    service = request.args.get('service', '')
    if service not in ALLOWED_SERVICES:
        return jsonify({"error": "Dịch vụ không nằm trong Whitelist cho phép"}), 400
        
    # An toàn tuyệt đối: shell=False và mảng đối số tường minh
    res = subprocess.run(["systemctl", "status", service], capture_output=True, text=True, check=False)
    return jsonify({"service": service, "output": res.stdout[:500]})
