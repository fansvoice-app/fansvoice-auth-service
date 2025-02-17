using System.Security.Cryptography;
using System.Text;
using FansVoice.Auth.Data;
using FansVoice.Auth.DTOs;
using FansVoice.Auth.Interfaces;
using FansVoice.Auth.Models;
using Microsoft.EntityFrameworkCore;

namespace FansVoice.Auth.Services;

public class AuthService : IAuthService
{
    private readonly AuthDbContext _context;
    private readonly ITokenService _tokenService;
    private readonly IConfiguration _configuration;
    // Normalde IEmailService ve ILogger<AuthService> de enjekte edilmeli

    public AuthService(
        AuthDbContext context,
        ITokenService tokenService,
        IConfiguration configuration)
    {
        _context = context;
        _tokenService = tokenService;
        _configuration = configuration;
    }

    public async Task<AuthResponse> LoginAsync(LoginRequest request)
    {
        var user = await _context.Users
            .Include(u => u.UserRoles)
            .ThenInclude(ur => ur.Role)
            .FirstOrDefaultAsync(u => u.Email == request.Email);

        if (user == null)
            throw new Exception("Invalid credentials");

        if (!VerifyPasswordHash(request.Password, user.PasswordHash))
            throw new Exception("Invalid credentials");

        if (!user.EmailConfirmed)
            throw new Exception("Email not confirmed");

        if (!user.IsActive)
            throw new Exception("Account is deactivated");

        var roles = user.UserRoles.Select(ur => ur.Role.Name).ToList();
        var accessToken = _tokenService.GenerateAccessToken(user, roles);
        var refreshToken = _tokenService.GenerateRefreshToken();
        var refreshTokenExpiryTime = DateTime.UtcNow.AddDays(7);

        user.RefreshToken = refreshToken;
        user.RefreshTokenExpiryTime = refreshTokenExpiryTime;
        user.LastLoginAt = DateTime.UtcNow;

        await _context.SaveChangesAsync();

        return new AuthResponse(
            accessToken,
            refreshToken,
            refreshTokenExpiryTime,
            MapToUserDto(user, roles)
        );
    }

    public async Task<AuthResponse> RegisterAsync(RegisterRequest request)
    {
        if (await _context.Users.AnyAsync(u => u.Email == request.Email))
            throw new Exception("Email already registered");

        if (await _context.Users.AnyAsync(u => u.Username == request.Username))
            throw new Exception("Username already taken");

        var user = new User
        {
            Username = request.Username,
            Email = request.Email,
            PasswordHash = HashPassword(request.Password),
            PhoneNumber = request.PhoneNumber,
            CreatedAt = DateTime.UtcNow,
            EmailConfirmed = false // Email doğrulaması gerekiyor
        };

        // Varsayılan "User" rolünü ata
        var defaultRole = await _context.Roles.FirstOrDefaultAsync(r => r.Name == "User")
            ?? throw new Exception("Default role not found");

        user.UserRoles.Add(new UserRole { Role = defaultRole });

        _context.Users.Add(user);
        await _context.SaveChangesAsync();

        // Email doğrulama token'ı oluştur ve gönder
        var verificationToken = _tokenService.GenerateEmailVerificationToken(user.Email);
        // await _emailService.SendVerificationEmailAsync(user.Email, verificationToken);

        var roles = new List<string> { "User" };
        var accessToken = _tokenService.GenerateAccessToken(user, roles);
        var refreshToken = _tokenService.GenerateRefreshToken();
        var refreshTokenExpiryTime = DateTime.UtcNow.AddDays(7);

        user.RefreshToken = refreshToken;
        user.RefreshTokenExpiryTime = refreshTokenExpiryTime;

        await _context.SaveChangesAsync();

        return new AuthResponse(
            accessToken,
            refreshToken,
            refreshTokenExpiryTime,
            MapToUserDto(user, roles)
        );
    }

    public async Task<AuthResponse> RefreshTokenAsync(string refreshToken)
    {
        var user = await _context.Users
            .Include(u => u.UserRoles)
            .ThenInclude(ur => ur.Role)
            .FirstOrDefaultAsync(u => u.RefreshToken == refreshToken);

        if (user == null)
            throw new Exception("Invalid refresh token");

        if (user.RefreshTokenExpiryTime <= DateTime.UtcNow)
            throw new Exception("Refresh token expired");

        var roles = user.UserRoles.Select(ur => ur.Role.Name).ToList();
        var accessToken = _tokenService.GenerateAccessToken(user, roles);
        var newRefreshToken = _tokenService.GenerateRefreshToken();
        var refreshTokenExpiryTime = DateTime.UtcNow.AddDays(7);

        user.RefreshToken = newRefreshToken;
        user.RefreshTokenExpiryTime = refreshTokenExpiryTime;

        await _context.SaveChangesAsync();

        return new AuthResponse(
            accessToken,
            newRefreshToken,
            refreshTokenExpiryTime,
            MapToUserDto(user, roles)
        );
    }

    public async Task<bool> ChangePasswordAsync(Guid userId, ChangePasswordRequest request)
    {
        var user = await _context.Users.FindAsync(userId);
        if (user == null)
            throw new Exception("User not found");

        if (!VerifyPasswordHash(request.CurrentPassword, user.PasswordHash))
            throw new Exception("Current password is incorrect");

        user.PasswordHash = HashPassword(request.NewPassword);
        await _context.SaveChangesAsync();

        return true;
    }

    public async Task<bool> ForgotPasswordAsync(ForgotPasswordRequest request)
    {
        var user = await _context.Users.FirstOrDefaultAsync(u => u.Email == request.Email);
        if (user == null)
            return true; // Don't reveal that email doesn't exist

        var resetToken = _tokenService.GeneratePasswordResetToken(user.Email);
        // await _emailService.SendPasswordResetEmailAsync(user.Email, resetToken);

        return true;
    }

    public async Task<bool> ResetPasswordAsync(ResetPasswordRequest request)
    {
        if (!_tokenService.ValidateToken(request.Token))
            throw new Exception("Invalid or expired token");

        var user = await _context.Users.FirstOrDefaultAsync(u => u.Email == request.Email);
        if (user == null)
            throw new Exception("User not found");

        user.PasswordHash = HashPassword(request.NewPassword);
        await _context.SaveChangesAsync();

        return true;
    }

    public async Task<bool> VerifyEmailAsync(VerifyEmailRequest request)
    {
        if (!_tokenService.ValidateToken(request.Token))
            throw new Exception("Invalid or expired token");

        var user = await _context.Users.FirstOrDefaultAsync(u => u.Email == request.Email);
        if (user == null)
            throw new Exception("User not found");

        user.EmailConfirmed = true;
        await _context.SaveChangesAsync();

        return true;
    }

    public async Task<User?> GetUserByIdAsync(Guid userId)
    {
        return await _context.Users
            .Include(u => u.UserRoles)
            .ThenInclude(ur => ur.Role)
            .FirstOrDefaultAsync(u => u.Id == userId);
    }

    public async Task<bool> RevokeRefreshTokenAsync(Guid userId)
    {
        var user = await _context.Users.FindAsync(userId);
        if (user == null)
            return false;

        user.RefreshToken = null;
        user.RefreshTokenExpiryTime = null;
        await _context.SaveChangesAsync();

        return true;
    }

    private static string HashPassword(string password)
    {
        using var sha256 = SHA256.Create();
        var hashedBytes = sha256.ComputeHash(Encoding.UTF8.GetBytes(password));
        return Convert.ToBase64String(hashedBytes);
    }

    private static bool VerifyPasswordHash(string password, string storedHash)
    {
        var hashOfInput = HashPassword(password);
        return storedHash == hashOfInput;
    }

    private static UserDto MapToUserDto(User user, List<string> roles)
    {
        return new UserDto(
            user.Id,
            user.Username,
            user.Email,
            user.PhoneNumber,
            user.EmailConfirmed,
            user.PhoneNumberConfirmed,
            roles
        );
    }
}