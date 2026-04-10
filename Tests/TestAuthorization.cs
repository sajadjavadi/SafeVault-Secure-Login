using System.Security.Claims;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Authorization.Infrastructure;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using NUnit.Framework;
using SafeVault;

[TestFixture]
public class TestAuthorization
{
    private ServiceProvider BuildServiceProvider(string databaseName)
    {
        var services = new ServiceCollection();
        services.AddLogging();
        services.AddSingleton(typeof(ILogger<>), typeof(Logger<>));
        services.AddSingleton<ILoggerFactory, LoggerFactory>();
        services.AddOptions();

        services.AddDbContext<ApplicationDbContext>(options =>
            options.UseInMemoryDatabase(databaseName));

        services.AddIdentity<ApplicationUser, IdentityRole>(options =>
        {
            options.Password.RequireDigit = false;
            options.Password.RequireLowercase = false;
            options.Password.RequireNonAlphanumeric = false;
            options.Password.RequireUppercase = false;
            options.Password.RequiredLength = 6;
        })
        .AddEntityFrameworkStores<ApplicationDbContext>()
        .AddDefaultTokenProviders();

        services.AddAuthorization();

        return services.BuildServiceProvider();
    }

    [Test]
    public async Task AdminUser_IsAuthorizedForAdminRole()
    {
        using var provider = BuildServiceProvider(nameof(AdminUser_IsAuthorizedForAdminRole));
        var roleManager = provider.GetRequiredService<RoleManager<IdentityRole>>();
        var userManager = provider.GetRequiredService<UserManager<ApplicationUser>>();
        var authorizationService = provider.GetRequiredService<IAuthorizationService>();

        await roleManager.CreateAsync(new IdentityRole("Admin"));

        var user = new ApplicationUser
        {
            UserName = "adminuser@example.com",
            Email = "adminuser@example.com",
            Name = "Admin User"
        };

        var createResult = await userManager.CreateAsync(user, "Password123!");
        Assert.That(createResult.Succeeded, Is.True);

        var addRoleResult = await userManager.AddToRoleAsync(user, "Admin");
        Assert.That(addRoleResult.Succeeded, Is.True);

        var principal = new ClaimsPrincipal(new ClaimsIdentity(new[]
        {
            new Claim(ClaimTypes.Name, user.Email),
            new Claim(ClaimTypes.Role, "Admin")
        }, "Test"));

        var authorizeResult = await authorizationService.AuthorizeAsync(principal, null, new RolesAuthorizationRequirement(new[] { "Admin" }));
        Assert.That(authorizeResult.Succeeded, Is.True);
    }

    [Test]
    public async Task NonAdminUser_IsNotAuthorizedForAdminRole()
    {
        using var provider = BuildServiceProvider(nameof(NonAdminUser_IsNotAuthorizedForAdminRole));
        var authorizationService = provider.GetRequiredService<IAuthorizationService>();

        var principal = new ClaimsPrincipal(new ClaimsIdentity(new[]
        {
            new Claim(ClaimTypes.Name, "user@example.com")
        }, "Test"));

        var authorizeResult = await authorizationService.AuthorizeAsync(principal, null, new RolesAuthorizationRequirement(new[] { "Admin" }));
        Assert.That(authorizeResult.Succeeded, Is.False);
    }
}
