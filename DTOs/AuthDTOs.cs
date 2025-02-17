using System.ComponentModel.DataAnnotations;

namespace FansVoice.Auth.DTOs;

public record LoginRequest(
    [Required] string Email,
    [Required] string Password
);

public record RegisterRequest(
    [Required][MaxLength(50)] string Username,
    [Required][EmailAddress] string Email,
    [Required][MinLength(6)] string Password,
    string? PhoneNumber
);

public record AuthResponse(
    string AccessToken,
    string RefreshToken,
    DateTime ExpiresAt,
    UserDto User
);

public record UserDto(
    Guid Id,
    string Username,
    string Email,
    string? PhoneNumber,
    bool EmailConfirmed,
    bool PhoneNumberConfirmed,
    List<string> Roles
);

public record RefreshTokenRequest(
    [Required] string RefreshToken
);

public record ChangePasswordRequest(
    [Required] string CurrentPassword,
    [Required][MinLength(6)] string NewPassword
);

public record ForgotPasswordRequest(
    [Required][EmailAddress] string Email
);

public record ResetPasswordRequest(
    [Required] string Token,
    [Required][EmailAddress] string Email,
    [Required][MinLength(6)] string NewPassword
);

public record VerifyEmailRequest(
    [Required] string Token,
    [Required][EmailAddress] string Email
);