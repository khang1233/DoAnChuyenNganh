// [HARDENED] Golang — net.ParseIP validation, exec.Command đối số trực tiếp, Parameterized SQL
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
