using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using IdentityApi.Domain;
using Microsoft.IdentityModel.Tokens;

namespace IdentityApi.Infrastructure.Repository;

public interface IJwtToken
{
    string GenerateToken(IEnumerable<Claim> claims);
}

public class JwtTokenManagement(IConfiguration config) : IJwtToken
{
    public string GenerateToken(IEnumerable<Claim> claims)
    {
        var securityToken = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(config["Jwt:Key"]!));
        var credentials = new SigningCredentials(securityToken, SecurityAlgorithms.HmacSha256);
        var token = new JwtSecurityToken(
            issuer: config["Jwt:Issuer"],
            audience: config["Jwt:Audience"],
            claims: claims,
            expires: DateTime.Now.AddHours(3),
            signingCredentials: credentials
        );

        return new JwtSecurityTokenHandler().WriteToken(token);
    }
}