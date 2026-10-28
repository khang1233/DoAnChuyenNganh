# -*- coding: utf-8 -*-
"""
MULTI-LANGUAGE DEFENSE REMEDIATION SUITE
Chuẩn hóa mẫu mã nguồn an toàn (Before/After) cho 6 ngôn ngữ lập trình chủ đạo:
1. JavaScript / TypeScript (Node.js & Express)
2. Python (FastAPI / Django / Flask)
3. Java (Spring Boot / JPA / Hibernate)
4. PHP (Modern PHP / Laravel)
5. Go (Golang / Gin / database/sql)
6. C# / .NET (ASP.NET Core / Entity Framework)
"""

from pathlib import Path
from typing import Dict, Any

MULTI_LANG_CODE_SAMPLES: Dict[str, Dict[str, Any]] = {
    "javascript": {
        "title": "JavaScript / TypeScript (Node.js & Express)",
        "lang_tag": "javascript",
        "file_vuln": "vulnerable_sample.js",
        "file_secure": "patched_secure_sample.js",
        "vuln_code": """// [VULNERABLE] Node.js Express — Cho phép RCE qua exec() và SQLi qua nối chuỗi
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
""",
        "secure_code": """// [HARDENED] Node.js Express — Whitelist Regex, execFile không dùng shell, Parameterized Query
const express = require('express');
const { execFile } = require('child_process');
const helmet = require('helmet');
const app = express();

app.use(helmet()); // Bổ sung Security Headers chuẩn OWASP

// Khắc phục RCE: Whitelist kiểm tra định dạng IP/Domain + execFile mảng cố định
const IP_REGEX = /^([0-9]{1,3}\\.){3}[0-9]{1,3}$/;
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
"""
    },
    "python": {
        "title": "Python (FastAPI / Flask / Django)",
        "lang_tag": "python",
        "file_vuln": "vulnerable_sample.py",
        "file_secure": "patched_secure_sample.py",
        "vuln_code": """# [VULNERABLE] Python Backend — Cho phép RCE qua os.system() và SQLi qua f-string
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
""",
        "secure_code": """# [HARDENED] Python Backend — Whitelist enum, subprocess.run(shell=False), Parameterized SQL
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
        cur = conn.execute("SELECT id, title FROM articles WHERE title LIKE ? ESCAPE '\\\\'", (f"%{keyword}%",))
        return jsonify(cur.fetchall())
"""
    },
    "java": {
        "title": "Java (Spring Boot / JPA / Hibernate)",
        "lang_tag": "java",
        "file_vuln": "VulnerableSample.java",
        "file_secure": "PatchedSecureSample.java",
        "vuln_code": """// [VULNERABLE] Java Spring Boot — RCE qua Runtime.exec() và SQLi qua nối chuỗi
package com.security.example;

import org.springframework.web.bind.annotation.*;
import java.io.*;
import java.sql.*;

@RestController
@RequestMapping("/api")
public class VulnerableSample {

    // Lỗ hổng RCE
    @GetMapping("/diagnostics/traceroute")
    public String trace(@RequestParam String target) throws Exception {
        Process p = Runtime.getRuntime().exec("traceroute " + target);
        BufferedReader reader = new BufferedReader(new InputStreamReader(p.getInputStream()));
        return reader.readLine();
    }

    // Lỗ hổng SQL Injection
    @GetMapping("/account")
    public String getAccount(@RequestParam String user, Connection conn) throws Exception {
        Statement stmt = conn.createStatement();
        ResultSet rs = stmt.executeQuery("SELECT balance FROM accounts WHERE username = '" + user + "'");
        return rs.next() ? rs.getString("balance") : "Not found";
    }
}
""",
        "secure_code": """// [HARDENED] Java Spring Boot — ProcessBuilder mảng tham số cố định, PreparedStatement
package com.security.example;

import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import java.io.*;
import java.sql.*;
import java.util.regex.Pattern;

@RestController
@RequestMapping("/api")
public class PatchedSecureSample {

    private static final Pattern HOST_PATTERN = Pattern.compile("^[a-zA-Z0-9.-]{1,64}$");

    // Khắc phục RCE: Regex validation + ProcessBuilder với danh sách đối số
    @GetMapping("/diagnostics/traceroute")
    public ResponseEntity<String> trace(@RequestParam String target) throws Exception {
        if (!HOST_PATTERN.matcher(target).matches()) {
            return ResponseEntity.badRequest().body("Tham số target không hợp lệ.");
        }
        ProcessBuilder pb = new ProcessBuilder("traceroute", "-m", "15", target);
        pb.redirectErrorStream(true);
        Process p = pb.start();
        BufferedReader reader = new BufferedReader(new InputStreamReader(p.getInputStream()));
        return ResponseEntity.ok(reader.readLine());
    }

    // Khắc phục SQLi: PreparedStatement chuẩn bảo vệ 100%
    @GetMapping("/account")
    public ResponseEntity<String> getAccount(@RequestParam String user, Connection conn) throws Exception {
        String sql = "SELECT balance FROM accounts WHERE username = ?";
        try (PreparedStatement ps = conn.prepareStatement(sql)) {
            ps.setString(1, user);
            try (ResultSet rs = ps.executeQuery()) {
                return rs.next() ? ResponseEntity.ok(rs.getString("balance")) : ResponseEntity.notFound().build();
            }
        }
    }
}
"""
    },
    "php": {
        "title": "PHP (Modern PHP & Laravel)",
        "lang_tag": "php",
        "file_vuln": "vulnerable_sample.php",
        "file_secure": "patched_secure_sample.php",
        "vuln_code": """<?php
// [VULNERABLE] PHP — Thực thi hệ thống với system() và ghép chuỗi SQL
if (isset($_GET['cmd'])) {
    $command = $_GET['cmd'];
    // Lỗ hổng RCE nghiêm trọng
    system("backup_utility.sh " . $command);
}

if (isset($_GET['user_id'])) {
    $id = $_GET['user_id'];
    $conn = new mysqli("localhost", "root", "secret", "app_db");
    // Lỗ hổng SQL Injection
    $result = $conn->query("SELECT * FROM users WHERE id = " . $id);
    echo json_encode($result->fetch_assoc());
}
?>""",
        "secure_code": """<?php
// [HARDENED] PHP — Whitelist kiểm tra tham số, escapeshellcmd, PDO Prepared Statements
header('Content-Type: application/json; charset=UTF-8');

$allowed_commands = ['daily', 'weekly', 'monthly'];
if (isset($_GET['action'])) {
    $action = $_GET['action'];
    if (!in_array($action, $allowed_commands, true)) {
        http_response_code(400);
        die(json_encode(["error" => "Action không hợp lệ theo Whitelist."]));
    }
    // Thực thi an toàn với escapeshellarg
    $output = shell_exec("/usr/local/bin/backup_utility.sh " . escapeshellarg($action));
    echo json_encode(["status" => "success", "result" => $output]);
}

if (isset($_GET['user_id'])) {
    $id = filter_var($_GET['user_id'], FILTER_VALIDATE_INT);
    if ($id === false || $id <= 0) {
        http_response_code(400);
        die(json_encode(["error" => "ID người dùng không hợp lệ."]));
    }
    $pdo = new PDO("mysql:host=localhost;dbname=app_db;charset=utf8mb4", "app_user", "password", [
        PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
        PDO::ATTR_EMULATE_PREPARES => false,
    ]);
    $stmt = $pdo->prepare("SELECT id, username, email FROM users WHERE id = :id");
    $stmt->execute(['id' => $id]);
    echo json_encode($stmt->fetch(PDO::FETCH_ASSOC));
}
?>"""
    },
    "golang": {
        "title": "Go (Golang & Gin)",
        "lang_tag": "go",
        "file_vuln": "vulnerable_sample.go",
        "file_secure": "patched_secure_sample.go",
        "vuln_code": """// [VULNERABLE] Golang — RCE qua sh -c và SQLi qua fmt.Sprintf
package main

import (
    "database/sql"
    "fmt"
    "net/http"
    "os/exec"
)

func vulnHandler(w http.ResponseWriter, r *http.Request, db *sql.DB) {
    ip := r.URL.Query().Get("ip")
    // Lỗ hổng RCE: Nối chuỗi vào shell sh -c
    out, _ := exec.Command("sh", "-c", "ping -c 1 " + ip).CombinedOutput()
    w.Write(out)

    category := r.URL.Query().Get("cat")
    // Lỗ hổng SQLi qua fmt.Sprintf
    q := fmt.Sprintf("SELECT id, name FROM products WHERE category = '%s'", category)
    rows, _ := db.Query(q)
    _ = rows
}
""",
        "secure_code": """// [HARDENED] Golang — net.ParseIP validation, exec.Command đối số trực tiếp, Parameterized SQL
package main

import (
    "database/sql"
    "net"
    "net/http"
    "os/exec"
)

func safeHandler(w http.ResponseWriter, r *http.Request, db *sql.DB) {
    rawIP := r.URL.Query().Get("ip")
    parsedIP := net.ParseIP(rawIP)
    if parsedIP == nil {
        http.Error(w, "Địa chỉ IP không hợp lệ theo Whitelist", http.StatusBadRequest)
        return
    }
    // Thực thi trực tiếp binary không qua shell trung gian
    cmd := exec.Command("ping", "-c", "1", parsedIP.String())
    out, err := cmd.CombinedOutput()
    if err != nil {
        http.Error(w, "Lỗi kiểm tra mạng", http.StatusInternalServerError)
        return
    }
    w.Write(out)

    category := r.URL.Query().Get("cat")
    // Chuẩn Parameterized Query trong Go database/sql
    rows, err := db.Query("SELECT id, name FROM products WHERE category = ?", category)
    if err != nil {
        http.Error(w, "Lỗi truy vấn cơ sở dữ liệu", http.StatusInternalServerError)
        return
    }
    defer rows.Close()
}
"""
    },
    "csharp": {
        "title": "C# / .NET (ASP.NET Core & Entity Framework)",
        "lang_tag": "csharp",
        "file_vuln": "VulnerableSample.cs",
        "file_secure": "PatchedSecureSample.cs",
        "vuln_code": """// [VULNERABLE] C# ASP.NET Core — RCE qua cmd.exe /c và SQLi qua String Concat
using Microsoft.AspNetCore.Mvc;
using System.Diagnostics;
using Microsoft.Data.SqlClient;

[ApiController]
[Route("api/[controller]")]
public class VulnerableController : ControllerBase
{
    [HttpGet("lookup")]
    public IActionResult Lookup([FromQuery] string domain)
    {
        // Lỗ hổng RCE: cmd.exe /c nối chuỗi
        var p = Process.Start("cmd.exe", "/c nslookup " + domain);
        return Ok("Executing lookup");
    }

    [HttpGet("user")]
    public IActionResult GetUser([FromQuery] string username)
    {
        using var conn = new SqlConnection("Server=localhost;Database=AppDb;");
        conn.Open();
        // Lỗ hổng SQL Injection
        var cmd = new SqlCommand("SELECT Id, Role FROM Users WHERE Username = '" + username + "'", conn);
        using var reader = cmd.ExecuteReader();
        return Ok(reader.HasRows);
    }
}
""",
        "secure_code": """// [HARDENED] C# ASP.NET Core — ProcessStartInfo ArgumentList, SqlCommand Parameterized
using Microsoft.AspNetCore.Mvc;
using System.Diagnostics;
using System.Text.RegularExpressions;
using Microsoft.Data.SqlClient;

[ApiController]
[Route("api/[controller]")]
public class PatchedSecureController : ControllerBase
{
    private static readonly Regex DomainRegex = new Regex(@"^[a-zA-Z0-9.-]{1,128}$", RegexOptions.Compiled);

    [HttpGet("lookup")]
    public IActionResult Lookup([FromQuery] string domain)
    {
        if (string.IsNullOrWhiteSpace(domain) || !DomainRegex.IsMatch(domain))
        {
            return BadRequest(new { error = "Tên miền không hợp lệ theo Whitelist." });
        }

        // An toàn: Dùng ArgumentList không qua shell command interpreter
        var psi = new ProcessStartInfo("nslookup")
        {
            RedirectStandardOutput = true,
            UseShellExecute = false,
            CreateNoWindow = true
        };
        psi.ArgumentList.Add(domain);

        using var process = Process.Start(psi);
        string output = process?.StandardOutput.ReadToEnd() ?? string.Empty;
        return Content(output, "text/plain");
    }

    [HttpGet("user")]
    public IActionResult GetUser([FromQuery] string username)
    {
        using var conn = new SqlConnection("Server=localhost;Database=AppDb;");
        conn.Open();
        // Chuẩn Parameterized Query trong .NET
        using var cmd = new SqlCommand("SELECT Id, Role FROM Users WHERE Username = @Username", conn);
        cmd.Parameters.AddWithValue("@Username", username);
        using var reader = cmd.ExecuteReader();
        return Ok(reader.HasRows);
    }
}
"""
    }
}


def write_all_language_fixtures(examples_dir: Path):
    """
    Ghi đầy đủ cả 6 cặp mã nguồn kiểm thử (Before / After) vào thư mục examples/.
    """
    examples_dir.mkdir(parents=True, exist_ok=True)
    for lang_key, data in MULTI_LANG_CODE_SAMPLES.items():
        (examples_dir / data["file_vuln"]).write_text(data["vuln_code"], encoding="utf-8")
        (examples_dir / data["file_secure"]).write_text(data["secure_code"], encoding="utf-8")


def generate_multi_lang_markdown_sop() -> str:
    """
    Tạo nội dung Markdown chuẩn mực cho PHẦN 5 trong SKILL.md bao gồm cả 6 ngôn ngữ lớn.
    """
    lines = [
        "## PHẦN 5: QUY CHUẨN KHẮC PHỤC TẬN GỐC CHO 6 NGÔN NGỮ LỚN (MULTI-LANGUAGE REMEDIATION SOP)",
        "",
        "> [!IMPORTANT]",
        "> Tác tử AI Coding Agent (Cursor, Claude Code, Antigravity, Devin) khi nạp kỹ năng này bắt buộc phải đối chiếu",
        "> công nghệ của dự án mục tiêu với các mẫu chuẩn dưới đây để refactor mã nguồn đạt tiêu chí Zero-Vulnerability.",
        ""
    ]

    for idx, (lang_key, data) in enumerate(MULTI_LANG_CODE_SAMPLES.items(), 1):
        lines.extend([
            f"### {idx}. {data['title']}",
            f"- **File mẫu dính lỗi (Before):** `examples/{data['file_vuln']}`",
            f"- **File mẫu chuẩn an toàn (After):** `examples/{data['file_secure']}`",
            "",
            "#### Mã nguồn trước khi sửa (Vulnerable):",
            f"```{data['lang_tag']}",
            data["vuln_code"].strip(),
            "```",
            "",
            "#### Mã nguồn chuẩn hóa an toàn (Hardened):",
            f"```{data['lang_tag']}",
            data["secure_code"].strip(),
            "```",
            ""
        ])

    return "\n".join(lines)
