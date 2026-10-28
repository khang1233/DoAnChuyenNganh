// [VULNERABLE] Java Spring Boot — RCE qua Runtime.exec() và SQLi qua nối chuỗi
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
