// [VULNERABLE] Node.js Express — Cho phép RCE qua exec() và SQLi qua nối chuỗi
const express = require('express');
const { exec } = require('child_process');
const mysql = require('mysql2/promise');
const app = express();

// Lỗ hổng 1: Command Injection (RCE)
app.get('/api/ping', (req, res) => {
    const host = req.query.host; // Kẻ tấn công chèn: 127.0.0.1; cat /etc/passwd
    exec(`ping -c 1 ${host}`, (err, stdout) => {
        res.send(stdout);
    });
});

// Lỗ hổng 2: SQL Injection (SQLi)
app.get('/api/user', async (req, res) => {
    const id = req.query.id; // Kẻ tấn công chèn: 1' OR 1=1 --
    const [rows] = await db.query(`SELECT id, username, email FROM users WHERE id = '${id}'`);
    res.json(rows);
});
