using FansVoice.Auth.Data;
using Microsoft.EntityFrameworkCore;

namespace FansVoice.Auth.Extensions;

public static class ApplicationBuilderExtensions
{
    public static IApplicationBuilder UseAuthConfiguration(this IApplicationBuilder app, IWebHostEnvironment env)
    {
        // Development specific middleware
        if (env.IsDevelopment())
        {
            app.UseSwagger();
            app.UseSwaggerUI(c =>
            {
                c.SwaggerEndpoint("/swagger/v1/swagger.json", "FansVoice Auth API v1");
                c.RoutePrefix = string.Empty; // Swagger UI at root
            });
        }

        // Global middleware
        app.UseHttpsRedirection();
        app.UseCors("AllowAll");
        app.UseAuthentication();
        app.UseAuthorization();

        return app;
    }

    public static async Task<IApplicationBuilder> MigrateDatabaseAsync(this IApplicationBuilder app)
    {
        using var scope = app.ApplicationServices.CreateScope();
        var context = scope.ServiceProvider.GetRequiredService<AuthDbContext>();
        var logger = scope.ServiceProvider.GetRequiredService<ILogger<AuthDbContext>>();

        try
        {
            await context.Database.MigrateAsync();
            logger.LogInformation("Database migration completed successfully");

            // Seed data if needed
            await SeedDataAsync(context, logger);
        }
        catch (Exception ex)
        {
            logger.LogError(ex, "An error occurred while migrating the database");
            throw;
        }

        return app;
    }

    private static async Task SeedDataAsync(AuthDbContext context, ILogger logger)
    {
        try
        {
            // Rolleri kontrol et ve eksik olanları ekle
            if (!await context.Roles.AnyAsync())
            {
                var roles = new[]
                {
                    new Models.Role { Id = Guid.NewGuid(), Name = "Admin", Description = "System Administrator" },
                    new Models.Role { Id = Guid.NewGuid(), Name = "User", Description = "Standard User" },
                    new Models.Role { Id = Guid.NewGuid(), Name = "PremiumUser", Description = "Premium User with additional features" }
                };

                await context.Roles.AddRangeAsync(roles);
                await context.SaveChangesAsync();

                logger.LogInformation("Default roles have been seeded");
            }

            // Admin kullanıcısını kontrol et ve yoksa ekle
            if (!await context.Users.AnyAsync(u => u.Email == "admin@fansvoice.app"))
            {
                var adminRole = await context.Roles.FirstOrDefaultAsync(r => r.Name == "Admin");
                if (adminRole != null)
                {
                    var adminUser = new Models.User
                    {
                        Id = Guid.NewGuid(),
                        Username = "admin",
                        Email = "admin@fansvoice.app",
                        PasswordHash = HashPassword("Admin123!"), // Güvenli bir şekilde değiştirilmeli
                        EmailConfirmed = true,
                        IsActive = true,
                        CreatedAt = DateTime.UtcNow
                    };

                    adminUser.UserRoles.Add(new Models.UserRole
                    {
                        Id = Guid.NewGuid(),
                        Role = adminRole
                    });

                    await context.Users.AddAsync(adminUser);
                    await context.SaveChangesAsync();

                    logger.LogInformation("Admin user has been seeded");
                }
            }
        }
        catch (Exception ex)
        {
            logger.LogError(ex, "An error occurred while seeding the database");
            throw;
        }
    }

    private static string HashPassword(string password)
    {
        using var sha256 = System.Security.Cryptography.SHA256.Create();
        var hashedBytes = sha256.ComputeHash(System.Text.Encoding.UTF8.GetBytes(password));
        return Convert.ToBase64String(hashedBytes);
    }
}