// [HARDENED] Node.js Express — Whitelist Regex, execFile không dùng shell, Parameterized Query
const express = require('express');
const { execFile } = require('child_process');
const helmet = require('helmet');
const app = express();

app.use(helmet()); // Bổ sung Security Headers chuẩn OWASP

// Khắc phục RCE: Whitelist kiểm tra định dạng IP/Domain + execFile mảng cố định
const IP_REGEX = /^([0-9]{1,3}\.){3}[0-9]{1,3}$/;
app.get('/api/ping', (req, res) => {
    const host = req.query.host;
    if (!host || !IP_REGEX.test(host)) {
        return res.status(400).json({ error: "Tham số IP không hợp lệ theo Whitelist." });
    }
    // Thực thi trực tiếp binary không qua shell trung gian (/bin/sh)
    execFile('ping', ['-c', '1', host], { timeout: 3000 }, (err, stdout) => {
        if (err) return res.status(500).json({ error: "Lỗi thực thi kiểm tra mạng" });
        res.type('text/plain').send(stdout);
    });
});

// Khắc phục SQLi: Prepared Statement với tham số hóa (?)
app.get('/api/user', async (req, res) => {
    const id = parseInt(req.query.id, 10);
    if (isNaN(id) || id <= 0) {
        return res.status(400).json({ error: "ID người dùng không hợp lệ." });
    }
    const [rows] = await db.execute('SELECT id, username, email FROM users WHERE id = ?', [id]);
    res.json(rows);
});
