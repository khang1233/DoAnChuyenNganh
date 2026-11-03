// [VULNERABLE] C# ASP.NET Core — RCE qua cmd.exe /c và SQLi qua String Concat
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
