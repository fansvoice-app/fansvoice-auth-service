using System.Text;
using FansVoice.Auth.Data;
using FansVoice.Auth.Extensions;
using FansVoice.Auth.Interfaces;
using FansVoice.Auth.Services;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
using Microsoft.OpenApi.Models;
using Serilog;
using Serilog.Events;

Log.Logger = new LoggerConfiguration()
    .MinimumLevel.Debug()
    .MinimumLevel.Override("Microsoft", LogEventLevel.Information)
    .MinimumLevel.Override("Microsoft.AspNetCore", LogEventLevel.Warning)
    .Enrich.FromLogContext()
    .Enrich.WithMachineName()
    .Enrich.WithEnvironmentName()
    .WriteTo.Console()
    .WriteTo.File(
        path: "logs/fansvoice-auth-.log",
        rollingInterval: RollingInterval.Day,
        restrictedToMinimumLevel: LogEventLevel.Information)
    .CreateLogger();

try
{
    Log.Information("Starting FansVoice Auth Service");

    var builder = WebApplication.CreateBuilder(args);

    // Add Serilog
    builder.Host.UseSerilog();

    // Add services to the container using extensions
    builder.Services.AddAuthServices(builder.Configuration);

    var app = builder.Build();

    // Configure the HTTP request pipeline using extensions
    app.UseAuthConfiguration(app.Environment);

    // Global exception handling
    var logger = app.Services.GetRequiredService<ILogger<Program>>();
    app.UseGlobalExceptionHandler(logger);

    // Rate limiting
    app.UseRateLimiter();

    // Migrate and seed the database
    await app.MigrateDatabaseAsync();

    app.MapControllers();

    app.Run();
}
catch (Exception ex)
{
    Log.Fatal(ex, "FansVoice Auth Service terminated unexpectedly");
}
finally
{
    Log.CloseAndFlush();
}
