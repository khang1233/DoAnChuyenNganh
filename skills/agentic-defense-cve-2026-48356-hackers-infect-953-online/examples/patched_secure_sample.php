<?php
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
?>