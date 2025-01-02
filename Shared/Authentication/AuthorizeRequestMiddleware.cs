using System.Security.Claims;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;

namespace Shared.Authentication;

public class AuthorizeRequestMiddleware(ITokenService tokenService) : IMiddleware
{
    public async Task InvokeAsync(HttpContext context, RequestDelegate next)
    {
        var token = context.Request.Headers.Authorization.FirstOrDefault()!;
        if (string.IsNullOrWhiteSpace(token))
        {
            var _token = token.Split(" ")[1];
            bool isTokenValid = tokenService.ValidateToken(_token);

            if (!isTokenValid)
            {
                await UnAuthorized(context);
                return;
            }

            var claims = tokenService.GetClaims(_token);
            var identity = new ClaimsIdentity(claims, "Bearer");
            context.User = new ClaimsPrincipal(identity);
            await next(context);
        }

        await UnAuthorized(context);
        return;
    }

    private async Task UnAuthorized(HttpContext context)
    {
        context.Response.StatusCode = 401;
        context.Response.ContentType = "application/json";
        await context.Response.WriteAsJsonAsync(new ProblemDetails
        {
            Detail = "Access token is missing",
            Status = StatusCodes.Status401Unauthorized,
            Title = "You are not authorized",
            Type = "Bearer authentication"
        });
    }
}