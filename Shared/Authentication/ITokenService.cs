using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using Microsoft.Extensions.Configuration;
using Microsoft.IdentityModel.Tokens;

namespace Shared.Authentication;

public interface ITokenService
{
    bool ValidateToken(string token);
    IEnumerable<Claim>? GetClaims(string token);
}

public class TokenService(IConfiguration config) : ITokenService
{
    public bool ValidateToken(string token)
    {
        var handler = new JwtSecurityTokenHandler();

        try
        {
            var validateParameters = new TokenValidationParameters
            {
                ValidateIssuerSigningKey = true,
                IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(config["Jwt:Key"]!)),
                ValidateIssuer = true,
                ValidIssuer = config["Jwt:Issuer"],
                ValidateAudience = true,
                ValidAudience = config[config["Audience"]!], // config["Jwt:Audience"]
                ValidateLifetime = true,
                ClockSkew = TimeSpan.Zero
            };
            handler.ValidateToken(token, validateParameters, out SecurityToken validatedToken);
            return true;
        }
        catch
        {
            return false;
        }
    }

    public IEnumerable<Claim>? GetClaims(string token)
    {
        var handler = new JwtSecurityTokenHandler();
        if (handler.CanReadToken(token))
        {
            var jwtToken = handler.ReadJwtToken(token);
            return jwtToken?.Claims!.ToList();
        }
        return [];
    }
}