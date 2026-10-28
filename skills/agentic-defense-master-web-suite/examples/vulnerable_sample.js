// VULNERABLE SAMPLE (Node.js / Express — Trước khi sửa)
const express = require('express');
const { exec } = require('child_process');
const app = express();

// Lỗ hổng 1: Command Injection qua query string
app.get('/api/ping', (req, res) => {
    const host = req.query.host;
    // Nguy hiểm: Ghép chuỗi trực tiếp cho phép attacker chèn toán tử ; | &&
    exec(`ping -c 1 ${host}`, (err, stdout) => {
        res.send(stdout);
    });
});

// Lỗ hổng 2: SQL Injection qua chuỗi thô
app.get('/api/user', async (req, res) => {
    const userId = req.query.id;
    const query = `SELECT * FROM users WHERE id = '${userId}'`; // Dễ bị ' OR 1=1 --
    const result = await db.raw(query);
    res.json(result);
});
