using Microsoft.AspNetCore.Mvc;
using FansVoice.Auth.Data;
using Microsoft.EntityFrameworkCore;

namespace FansVoice.Auth.Controllers;

[ApiController]
[Route("api/[controller]")]
public class HealthController : ControllerBase
{
    private readonly AuthDbContext _context;
    private readonly ILogger<HealthController> _logger;

    public HealthController(AuthDbContext context, ILogger<HealthController> logger)
    {
        _context = context;
        _logger = logger;
    }

    [HttpGet]
    public async Task<IActionResult> Get()
    {
        try
        {
            // Veritabanı bağlantısını kontrol et
            await _context.Database.CanConnectAsync();

            var healthStatus = new
            {
                Status = "Healthy",
                Timestamp = DateTime.UtcNow,
                Version = GetType().Assembly.GetName().Version?.ToString() ?? "1.0.0",
                Database = new
                {
                    Status = "Connected",
                    Provider = _context.Database.ProviderName,
                    MigrationsPending = (await _context.Database.GetPendingMigrationsAsync()).Any()
                }
            };

            _logger.LogInformation("Health check completed successfully");
            return Ok(healthStatus);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Health check failed");

            var unhealthyStatus = new
            {
                Status = "Unhealthy",
                Timestamp = DateTime.UtcNow,
                Error = ex.Message
            };

            return StatusCode(500, unhealthyStatus);
        }
    }

    [HttpGet("detailed")]
    public async Task<IActionResult> GetDetailed()
    {
        try
        {
            // Veritabanı istatistikleri
            var userCount = await _context.Users.CountAsync();
            var activeUserCount = await _context.Users.CountAsync(u => u.IsActive);
            var roleCount = await _context.Roles.CountAsync();

            var detailedStatus = new
            {
                Status = "Healthy",
                Timestamp = DateTime.UtcNow,
                Version = GetType().Assembly.GetName().Version?.ToString() ?? "1.0.0",
                Database = new
                {
                    Status = "Connected",
                    Provider = _context.Database.ProviderName,
                    MigrationsPending = (await _context.Database.GetPendingMigrationsAsync()).Any(),
                    Statistics = new
                    {
                        TotalUsers = userCount,
                        ActiveUsers = activeUserCount,
                        TotalRoles = roleCount
                    }
                },
                Runtime = new
                {
                    Framework = System.Runtime.InteropServices.RuntimeInformation.FrameworkDescription,
                    OS = System.Runtime.InteropServices.RuntimeInformation.OSDescription,
                    ProcessorCount = Environment.ProcessorCount,
                    WorkingSet = Environment.WorkingSet / 1024 / 1024, // MB cinsinden
                    ThreadCount = System.Diagnostics.Process.GetCurrentProcess().Threads.Count
                }
            };

            _logger.LogInformation("Detailed health check completed successfully");
            return Ok(detailedStatus);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Detailed health check failed");

            var unhealthyStatus = new
            {
                Status = "Unhealthy",
                Timestamp = DateTime.UtcNow,
                Error = ex.Message
            };

            return StatusCode(500, unhealthyStatus);
        }
    }
}