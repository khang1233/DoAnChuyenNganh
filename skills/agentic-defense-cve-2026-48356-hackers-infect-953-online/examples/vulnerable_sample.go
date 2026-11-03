// [VULNERABLE] Golang — RCE qua sh -c và SQLi qua fmt.Sprintf
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
