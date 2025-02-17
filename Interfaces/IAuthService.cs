using FansVoice.Auth.DTOs;
using FansVoice.Auth.Models;

namespace FansVoice.Auth.Interfaces;

public interface IAuthService
{
    Task<AuthResponse> LoginAsync(LoginRequest request);
    Task<AuthResponse> RegisterAsync(RegisterRequest request);
    Task<AuthResponse> RefreshTokenAsync(string refreshToken);
    Task<bool> ChangePasswordAsync(Guid userId, ChangePasswordRequest request);
    Task<bool> ForgotPasswordAsync(ForgotPasswordRequest request);
    Task<bool> ResetPasswordAsync(ResetPasswordRequest request);
    Task<bool> VerifyEmailAsync(VerifyEmailRequest request);
    Task<User?> GetUserByIdAsync(Guid userId);
    Task<bool> RevokeRefreshTokenAsync(Guid userId);
}