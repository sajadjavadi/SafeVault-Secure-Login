using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using NUnit.Framework;
using SafeVault;

[TestFixture]
public class TestAuthentication
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

        return services.BuildServiceProvider();
    }

    [Test]
    public async Task RegisterUser_HashesPasswordAndValidatesLogin()
    {
        using var provider = BuildServiceProvider(nameof(RegisterUser_HashesPasswordAndValidatesLogin));
        var userManager = provider.GetRequiredService<UserManager<ApplicationUser>>();

        var user = new ApplicationUser
        {
            UserName = "loginuser@example.com",
            Email = "loginuser@example.com",
            Name = "Login User"
        };

        var createResult = await userManager.CreateAsync(user, "Password123!");
        Assert.That(createResult.Succeeded, Is.True);
        Assert.That(user.PasswordHash, Is.Not.Null.And.Not.Empty);

        var passwordValid = await userManager.CheckPasswordAsync(user, "Password123!");
        Assert.That(passwordValid, Is.True);
    }

    [Test]
    public async Task Login_FailsWithIncorrectPassword()
    {
        using var provider = BuildServiceProvider(nameof(Login_FailsWithIncorrectPassword));
        var userManager = provider.GetRequiredService<UserManager<ApplicationUser>>();

        var user = new ApplicationUser
        {
            UserName = "loginuser2@example.com",
            Email = "loginuser2@example.com",
            Name = "Login User 2"
        };

        var createResult = await userManager.CreateAsync(user, "Password123!");
        Assert.That(createResult.Succeeded, Is.True);

        var passwordValid = await userManager.CheckPasswordAsync(user, "WrongPassword!");
        Assert.That(passwordValid, Is.False);
    }
}
