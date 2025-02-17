using System.Security.Claims;

namespace FansVoice.Auth.Extensions;

public static class ClaimsPrincipalExtensions
{
    public static Guid? GetUserId(this ClaimsPrincipal principal)
    {
        var userIdClaim = principal.FindFirst(ClaimTypes.NameIdentifier)?.Value
            ?? principal.FindFirst("sub")?.Value;

        return userIdClaim != null ? Guid.Parse(userIdClaim) : null;
    }

    public static string? GetUsername(this ClaimsPrincipal principal)
    {
        return principal.FindFirst("username")?.Value;
    }

    public static string? GetEmail(this ClaimsPrincipal principal)
    {
        return principal.FindFirst(ClaimTypes.Email)?.Value;
    }

    public static IEnumerable<string> GetRoles(this ClaimsPrincipal principal)
    {
        return principal.Claims
            .Where(c => c.Type == ClaimTypes.Role)
            .Select(c => c.Value);
    }

    public static bool IsInRole(this ClaimsPrincipal principal, params string[] roles)
    {
        var userRoles = principal.GetRoles();
        return roles.Any(role => userRoles.Contains(role));
    }

    public static bool IsAdmin(this ClaimsPrincipal principal)
    {
        return principal.IsInRole("Admin");
    }

    public static bool IsPremiumUser(this ClaimsPrincipal principal)
    {
        return principal.IsInRole("PremiumUser");
    }
}