using System.Net;
using System.Text.Json;
using Microsoft.AspNetCore.Diagnostics;

namespace FansVoice.Auth.Extensions;

public static class ExceptionMiddlewareExtensions
{
    public static IApplicationBuilder UseGlobalExceptionHandler(this IApplicationBuilder app, ILogger logger)
    {
        app.UseExceptionHandler(appError =>
        {
            appError.Run(async context =>
            {
                context.Response.StatusCode = (int)HttpStatusCode.InternalServerError;
                context.Response.ContentType = "application/json";

                var contextFeature = context.Features.Get<IExceptionHandlerFeature>();
                if (contextFeature != null)
                {
                    var exception = contextFeature.Error;

                    // Log the error
                    logger.LogError(exception, "An unhandled exception has occurred");

                    var response = new
                    {
                        StatusCode = context.Response.StatusCode,
                        Message = "Internal Server Error.",
                        DetailedMessage = exception.Message,
                        ErrorCode = "INTERNAL_ERROR"
                    };

                    // Hata türüne göre özel yanıtlar
                    switch (exception)
                    {
                        case UnauthorizedAccessException:
                            context.Response.StatusCode = (int)HttpStatusCode.Unauthorized;
                            response = new
                            {
                                StatusCode = context.Response.StatusCode,
                                Message = "Unauthorized access",
                                DetailedMessage = "You are not authorized to access this resource",
                                ErrorCode = "UNAUTHORIZED"
                            };
                            break;

                        case ArgumentException:
                            context.Response.StatusCode = (int)HttpStatusCode.BadRequest;
                            response = new
                            {
                                StatusCode = context.Response.StatusCode,
                                Message = "Invalid argument",
                                DetailedMessage = exception.Message,
                                ErrorCode = "INVALID_ARGUMENT"
                            };
                            break;

                        case InvalidOperationException:
                            context.Response.StatusCode = (int)HttpStatusCode.BadRequest;
                            response = new
                            {
                                StatusCode = context.Response.StatusCode,
                                Message = "Invalid operation",
                                DetailedMessage = exception.Message,
                                ErrorCode = "INVALID_OPERATION"
                            };
                            break;
                    }

                    await context.Response.WriteAsync(JsonSerializer.Serialize(response));
                }
            });
        });

        return app;
    }
}