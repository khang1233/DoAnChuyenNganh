// [HARDENED] Java Spring Boot — ProcessBuilder mảng tham số cố định, PreparedStatement
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
