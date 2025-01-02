using Microsoft.Extensions.DependencyInjection;

namespace Shared.Authentication;

public static class PolicyServiceExtensions
{
    public static IServiceCollection AddPolicyAuthenticationService(this IServiceCollection services)
    {
        services.AddAuthorizationBuilder()
            .AddPolicy(PolicyNames.AdminPolicy, admin =>
            {
                admin.RequireAuthenticatedUser()
                    .RequireRole(Roles.Admin)
                    .RequireClaim(Permissions.CanCreate, true.ToString())
                    .RequireClaim(Permissions.CanRead, true.ToString())
                    .RequireClaim(Permissions.CanDelete, true.ToString())
                    .RequireClaim(Permissions.CanUpdate, true.ToString());
            })
            .AddPolicy(PolicyNames.ManagerPolicy, manager =>
            {
                manager.RequireAuthenticatedUser()
                    .RequireRole(Roles.Manager)
                    .RequireClaim(Permissions.CanCreate, true.ToString())
                    .RequireClaim(Permissions.CanRead, true.ToString())
                    .RequireClaim(Permissions.CanDelete, false.ToString())
                    .RequireClaim(Permissions.CanUpdate, true.ToString());
            })
            .AddPolicy(PolicyNames.UserPolicy, user =>
            {
                user.RequireAuthenticatedUser()
                    .RequireRole(Roles.User)
                    .RequireClaim(Permissions.CanCreate, false.ToString())
                    .RequireClaim(Permissions.CanRead, false.ToString())
                    .RequireClaim(Permissions.CanDelete, false.ToString())
                    .RequireClaim(Permissions.CanUpdate, false.ToString());
            })
            .AddPolicy(PolicyNames.AdminManagerPolicy, adminManager =>
            {
                adminManager.RequireAuthenticatedUser()
                    .RequireRole(Roles.Admin, Roles.User)
                    .RequireClaim(Permissions.CanCreate, true.ToString())
                    .RequireClaim(Permissions.CanRead, true.ToString())
                    .RequireClaim(Permissions.CanUpdate, true.ToString());
            })
            .AddPolicy(PolicyNames.AdminUserPolicy, adminUser =>
            {
                adminUser.RequireAuthenticatedUser()
                    .RequireRole(Roles.Admin, Roles.User);
            });

        return services;
    }
}