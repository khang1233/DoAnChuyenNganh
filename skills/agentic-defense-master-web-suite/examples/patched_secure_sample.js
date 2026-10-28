// HARDENED & SECURE SAMPLE (Node.js / Express — Sau khi AI Agent sửa)
const express = require('express');
const { execFile } = require('child_process');
const helmet = require('helmet');
const app = express();

app.use(helmet()); // Bổ sung các Security Headers chuẩn OWASP

// Khắc phục 1: Dùng execFile với mảng tham số cố định và Whitelist regex
app.get('/api/ping', (req, res) => {
    const host = req.query.host;
    const IP_REGEX = /^([0-9]{1,3}\.){3}[0-9]{1,3}$/;
    
    if (!host || !IP_REGEX.test(host)) {
        return res.status(400).json({ error: "Tham số IP không hợp lệ theo Whitelist." });
    }
    // Thực thi an toàn tuyệt đối, không kích hoạt shell trung gian
    execFile('ping', ['-c', '1', host], (err, stdout) => {
        if (err) return res.status(500).json({ error: "Lỗi thực thi lệnh" });
        res.type('text/plain').send(stdout);
    });
});

// Khắc phục 2: Sử dụng Parameterized Query (Prepared Statement)
app.get('/api/user', async (req, res) => {
    const userId = parseInt(req.query.id, 10);
    if (isNaN(userId)) {
        return res.status(400).json({ error: "ID người dùng bắt buộc là số nguyên." });
    }
    // An toàn tuyệt đối trước mọi kỹ thuật SQL Injection
    const result = await db.query('SELECT id, username, email FROM users WHERE id = ?', [userId]);
    res.json(result);
});
