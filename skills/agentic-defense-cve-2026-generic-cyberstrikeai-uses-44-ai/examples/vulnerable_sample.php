<?php
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
?>