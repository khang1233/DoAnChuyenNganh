// [HARDENED] C# ASP.NET Core — ProcessStartInfo ArgumentList, SqlCommand Parameterized
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
