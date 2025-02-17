namespace FansVoice.Auth.Extensions;

public static class HttpContextExtensions
{
    public static string? GetBearerToken(this HttpContext context)
    {
        var authHeader = context.Request.Headers["Authorization"].ToString();
        if (string.IsNullOrEmpty(authHeader) || !authHeader.StartsWith("Bearer "))
            return null;

        return authHeader.Substring("Bearer ".Length).Trim();
    }

    public static string? GetClientIp(this HttpContext context)
    {
        return context.Connection.RemoteIpAddress?.ToString();
    }

    public static string? GetUserAgent(this HttpContext context)
    {
        return context.Request.Headers["User-Agent"].ToString();
    }

    public static bool IsAuthenticated(this HttpContext context)
    {
        return context.User?.Identity?.IsAuthenticated ?? false;
    }

    public static void AddPaginationHeader(this HttpContext context, int currentPage, int itemsPerPage, int totalItems, int totalPages)
    {
        var paginationHeader = new
        {
            currentPage,
            itemsPerPage,
            totalItems,
            totalPages
        };

        context.Response.Headers.Add("X-Pagination", System.Text.Json.JsonSerializer.Serialize(paginationHeader));
    }

    public static (string? ipAddress, string? userAgent) GetClientInfo(this HttpContext context)
    {
        return (context.GetClientIp(), context.GetUserAgent());
    }

    public static void AddResponseHeader(this HttpContext context, string key, string value)
    {
        if (!context.Response.Headers.ContainsKey(key))
        {
            context.Response.Headers.Add(key, value);
        }
    }

    public static Dictionary<string, string> GetRequestHeaders(this HttpContext context)
    {
        var headers = new Dictionary<string, string>();
        foreach (var header in context.Request.Headers)
        {
            headers.Add(header.Key, header.Value.ToString());
        }
        return headers;
    }
}