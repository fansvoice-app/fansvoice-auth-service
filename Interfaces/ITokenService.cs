using FansVoice.Auth.Models;

namespace FansVoice.Auth.Interfaces;

public interface ITokenService
{
    string GenerateAccessToken(User user, IEnumerable<string> roles);
    string GenerateRefreshToken();
    string GenerateEmailVerificationToken(string email);
    string GeneratePasswordResetToken(string email);
    bool ValidateToken(string token);
    Guid? GetUserIdFromToken(string token);
}