# VULNERABLE SAMPLE (Python Backend — Trước khi sửa)
import os
from flask import Flask, request

app = Flask(__name__)

@app.route('/api/system_status')
def system_status():
    service = request.args.get('service', 'nginx')
    # Lỗ hổng RCE: os.system thực thi shell trực tiếp
    os.system(f"systemctl status {service}")
    return {"status": "checked"}
