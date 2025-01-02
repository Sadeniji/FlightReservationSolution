using System.Security.Claims;
using IdentityApi.Domain;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;
using Shared.Authentication;

namespace IdentityApi.Infrastructure.Data;

public class AppDbContext(DbContextOptions<AppDbContext> options) : IdentityDbContext<AppUser>(options)
{
    public DbSet<RefreshToken> RefreshTokens => Set<RefreshToken>();
}

public static class DatabaseSeeder
{
    public static async Task SeedAsync(AppDbContext context, UserManager<AppUser> userManager)
    {
        await context.Database.EnsureCreatedAsync();
        if (!context.Users.Any())
        {
            var admin = new AppUser
            {
                FullName = "Administrator",
                UserName = "admin@admin.com",
                PasswordHash = "Admin@123",
                Email = "admin@admin.com"
            };

            await userManager.CreateAsync(admin, admin.PasswordHash);
            List<Claim> claims = [
                new Claim(ClaimTypes.Role, Roles.Admin),
                new Claim(ClaimTypes.Email, admin.Email),
                new Claim(ClaimTypes.Name, admin.FullName),
                new(Permissions.CanCreate, true.ToString()),
                new(Permissions.CanUpdate, true.ToString()),
                new(Permissions.CanRead, true.ToString()),
                new(Permissions.CanDelete, true.ToString()),
            ];

            var _admin = await userManager.FindByEmailAsync(admin.Email);
            await userManager.AddClaimsAsync(_admin!, claims);
        }
    }
}