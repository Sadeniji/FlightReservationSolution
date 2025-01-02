using Microsoft.AspNetCore.Identity;

namespace IdentityApi.Domain;

public class AppUser : IdentityUser
{
    public string? FullName { get; set; }
}