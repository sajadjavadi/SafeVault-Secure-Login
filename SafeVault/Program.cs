using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using SafeVault;
using System.Net;
using System.Net.Http.Json;
using System.Text.Json;

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddCors(options =>
{
    options.AddDefaultPolicy(policy =>
    {
        policy.AllowAnyOrigin().AllowAnyMethod().AllowAnyHeader();
    });
});

builder.Services.AddDbContext<ApplicationDbContext>(options =>
{
    options.UseInMemoryDatabase("SafeVaultDb");
});

builder.Services.AddIdentity<ApplicationUser, IdentityRole>(options =>
{
    options.Password.RequireDigit = false;
    options.Password.RequireLowercase = false;
    options.Password.RequireNonAlphanumeric = false;
    options.Password.RequireUppercase = false;
    options.Password.RequiredLength = 6;

    options.Lockout.DefaultLockoutTimeSpan = TimeSpan.FromMinutes(15);
    options.Lockout.MaxFailedAccessAttempts = 5;
    options.Lockout.AllowedForNewUsers = true;
})
    .AddEntityFrameworkStores<ApplicationDbContext>()
    .AddDefaultTokenProviders();

builder.Services.ConfigureApplicationCookie(options =>
{
    options.LoginPath = "/login";
    options.AccessDeniedPath = "/login";
});

builder.Services.AddAuthorization(options =>
{
    options.AddPolicy("AdminOnly", policy => policy.RequireRole("Admin"));
});

var app = builder.Build();

app.UseCors();
app.UseAuthentication();
app.UseAuthorization();

using (var scope = app.Services.CreateScope())
{
    await SeedData.EnsureSeedDataAsync(scope.ServiceProvider);
}

app.MapGet("/", async (HttpContext httpContext, UserManager<ApplicationUser> userManager) =>
{
    var userName = await GetCurrentUserDisplayName(httpContext, userManager);
    return Results.Text(GetLandingPage(userName), "text/html");
});

app.MapGet("/safe", async (HttpContext httpContext, UserManager<ApplicationUser> userManager) =>
{
    var userName = await GetCurrentUserDisplayName(httpContext, userManager);
    return Results.Text(GetSafeFormPage(userName), "text/html");
});

app.MapGet("/register", async (HttpContext httpContext, UserManager<ApplicationUser> userManager) =>
{
    var userName = await GetCurrentUserDisplayName(httpContext, userManager);
    return Results.Text(GetRegisterPage(null, userName), "text/html");
});

app.MapPost("/register", async (HttpRequest request, HttpContext httpContext, UserManager<ApplicationUser> userManager, SignInManager<ApplicationUser> signInManager) =>
{
    var currentUserName = await GetCurrentUserDisplayName(httpContext, userManager);
    RegisterModel model;
    if (request.HasFormContentType)
    {
        var form = await request.ReadFormAsync();
        model = new RegisterModel
        {
            Name = form["Name"],
            Email = form["Email"],
            Password = form["Password"]
        };
    }
    else
    {
        model = await request.ReadFromJsonAsync<RegisterModel>() ?? new RegisterModel();
    }

    if (string.IsNullOrWhiteSpace(model.Name) || string.IsNullOrWhiteSpace(model.Email) || string.IsNullOrWhiteSpace(model.Password))
    {
        return Results.Text(GetRegisterPage("Name, email and password are required.", currentUserName), "text/html");
    }

    if (!InputValidator.IsXssSafe(model.Name) || !InputValidator.IsXssSafe(model.Email))
    {
        return Results.Text(GetRegisterPage("Invalid characters in name or email.", currentUserName), "text/html");
    }

    if (!InputValidator.IsSqlSafe(model.Name) || !InputValidator.IsSqlSafe(model.Email))
    {
        return Results.Text(GetRegisterPage("Invalid characters in name or email.", currentUserName), "text/html");
    }

    var sanitizedName = InputValidator.SanitizeUsername(model.Name);
    var sanitizedEmail = InputValidator.SanitizeEmail(model.Email);

    if (string.IsNullOrWhiteSpace(sanitizedName) || string.IsNullOrWhiteSpace(sanitizedEmail))
    {
        return Results.Text(GetRegisterPage("Name or email is invalid.", currentUserName), "text/html");
    }

    var newUser = new ApplicationUser
    {
        UserName = sanitizedEmail,
        Email = sanitizedEmail,
        Name = sanitizedName
    };

    var createResult = await userManager.CreateAsync(newUser, model.Password);
    if (!createResult.Succeeded)
    {
        var errors = string.Join("<br>", createResult.Errors.Select(e => WebUtility.HtmlEncode(e.Description)));
        return Results.Text(GetRegisterPage(errors, currentUserName), "text/html");
    }

    if (!await userManager.IsInRoleAsync(newUser, "User"))
    {
        await userManager.AddToRoleAsync(newUser, "User");
    }

    await signInManager.SignInAsync(newUser, isPersistent: false);
    return Results.Redirect("/");
});

app.MapGet("/login", async (HttpContext httpContext, UserManager<ApplicationUser> userManager) =>
{
    var userName = await GetCurrentUserDisplayName(httpContext, userManager);
    return Results.Text(GetLoginPage(null, userName), "text/html");
});

app.MapPost("/login", async (HttpRequest request, HttpContext httpContext, UserManager<ApplicationUser> userManager, SignInManager<ApplicationUser> signInManager) =>
{
    var currentUserName = await GetCurrentUserDisplayName(httpContext, userManager);
    LoginModel model;
    if (request.HasFormContentType)
    {
        var form = await request.ReadFormAsync();
        model = new LoginModel
        {
            Email = form["Email"],
            Password = form["Password"]
        };
    }
    else
    {
        model = await request.ReadFromJsonAsync<LoginModel>() ?? new LoginModel();
    }

    if (string.IsNullOrWhiteSpace(model.Email) || string.IsNullOrWhiteSpace(model.Password))
    {
        return Results.Text(GetLoginPage("Email and password are required.", currentUserName), "text/html");
    }

    if (!InputValidator.IsXssSafe(model.Email) || !InputValidator.IsXssSafe(model.Password))
    {
        return Results.Text(GetLoginPage("Invalid login attempt.", currentUserName), "text/html");
    }

    if (!InputValidator.IsSqlSafe(model.Email) || !InputValidator.IsSqlSafe(model.Password))
    {
        return Results.Text(GetLoginPage("Invalid login attempt.", currentUserName), "text/html");
    }

    var sanitizedEmail = InputValidator.SanitizeEmail(model.Email);
    if (string.IsNullOrWhiteSpace(sanitizedEmail))
    {
        return Results.Text(GetLoginPage("Email is invalid.", currentUserName), "text/html");
    }

    var result = await signInManager.PasswordSignInAsync(sanitizedEmail, model.Password, isPersistent: false, lockoutOnFailure: true);
    if (result.IsLockedOut)
    {
        return Results.Text(GetLoginPage("Your account has been locked due to multiple failed login attempts. Please try again later.", currentUserName), "text/html");
    }

    if (!result.Succeeded)
    {
        return Results.Text(GetLoginPage("Invalid login attempt.", currentUserName), "text/html");
    }

    return Results.Redirect("/");
});

app.MapGet("/logout", [Authorize] async (SignInManager<ApplicationUser> signInManager) =>
{
    await signInManager.SignOutAsync();
    return Results.Redirect("/login");
});

app.MapGet("/admin", [Authorize(Roles = "Admin")] async (HttpContext httpContext, UserManager<ApplicationUser> userManager) =>
{
    var userName = await GetCurrentUserDisplayName(httpContext, userManager);
    return Results.Text(GetAdminPage(userName), "text/html");
});

app.MapPost("/submit", async (HttpRequest request) =>
{
    try
    {
        using var reader = new StreamReader(request.Body);
        var body = await reader.ReadToEndAsync();

        if (string.IsNullOrWhiteSpace(body))
        {
            return Results.BadRequest(new { error = "Request body is empty" });
        }

        var jsonDoc = JsonDocument.Parse(body);
        var root = jsonDoc.RootElement;

        if (!root.TryGetProperty("username", out var usernameProp) ||
            !root.TryGetProperty("email", out var emailProp))
        {
            return Results.BadRequest(new { error = "Username and email are required" });
        }

        string username = usernameProp.GetString() ?? string.Empty;
        string email = emailProp.GetString() ?? string.Empty;

        if (string.IsNullOrWhiteSpace(username) || string.IsNullOrWhiteSpace(email))
        {
            return Results.BadRequest(new { error = "Username and email are required" });
        }

        if (!InputValidator.IsXssSafe(username) || !InputValidator.IsXssSafe(email) ||
            !InputValidator.IsSqlSafe(username) || !InputValidator.IsSqlSafe(email))
        {
            return Results.BadRequest(new { error = "Input contains invalid patterns" });
        }

        string sanitizedUsername = InputValidator.SanitizeUsername(username);
        string sanitizedEmail = InputValidator.SanitizeEmail(email);

        if (string.IsNullOrEmpty(sanitizedUsername) || string.IsNullOrEmpty(sanitizedEmail))
        {
            return Results.BadRequest(new { error = "Invalid input after sanitization" });
        }

        string encodedUsername = InputValidator.HtmlEncode(sanitizedUsername);
        string encodedEmail = InputValidator.HtmlEncode(sanitizedEmail);

        Console.WriteLine($"Received safe input - Username: {encodedUsername}, Email: {encodedEmail}");

        return Results.Ok(new
        {
            message = "Form processed successfully",
            username = encodedUsername,
            email = encodedEmail
        });
    }
    catch (JsonException ex)
    {
        Console.WriteLine($"JSON parsing error: {ex.Message}");
        return Results.BadRequest(new { error = "Invalid JSON format" });
    }
    catch (Exception ex)
    {
        Console.WriteLine($"Error processing form: {ex.Message}");
        return Results.BadRequest(new { error = "Error processing form" });
    }
});

app.Run();

static async Task<string?> GetCurrentUserDisplayName(HttpContext httpContext, UserManager<ApplicationUser> userManager)
{
    if (httpContext.User?.Identity?.IsAuthenticated != true)
    {
        return null;
    }

    var user = await userManager.GetUserAsync(httpContext.User);
    if (user == null)
    {
        return null;
    }

    return string.IsNullOrWhiteSpace(user.Name) ? user.Email : user.Name;
}

static string GetPageHeader(string? userName)
{
    if (string.IsNullOrWhiteSpace(userName))
    {
        return string.Empty;
    }

    return "<div style=\"display:flex; justify-content:space-between; align-items:center; margin-bottom:20px;\">" +
           "<div></div>" +
           "<div style=\"font-family:Arial,sans-serif; font-size:14px;\">" +
           $"<span style=\"margin-right:14px; color:#333;\">{InputValidator.HtmlEncode(userName)}</span>" +
           "<a href=\"/logout\" style=\"padding:8px 14px; background:#007bff; color:white; text-decoration:none; border-radius:4px;\">Logout</a>" +
           "</div>" +
           "</div>";
}

static string GetSafeFormPage(string? userName = null)
{
    return "<!DOCTYPE html>\n" +
           "<html>\n" +
           "<head>\n" +
           "    <title>SafeVault Form</title>\n" +
           "    <style>\n" +
           "        body { font-family: Arial, sans-serif; margin: 20px; }\n" +
           "        form { max-width: 400px; }\n" +
           "        input { display: block; margin: 10px 0; padding: 8px; width: 100%; }\n" +
           "        button { padding: 10px 20px; background-color: #007bff; color: white; border: none; cursor: pointer; }\n" +
           "        .error { color: red; font-size: 12px; }\n" +
           "        .success { color: green; margin: 10px 0; }\n" +
           "    </style>\n" +
           "</head>\n" +
           "<body>\n" +
           GetPageHeader(userName) +
           "    <h1>SafeVault - Secure Form</h1>\n" +
           "    <form id='safeForm'>\n" +
           "        <div>\n" +
           "            <label for='username'>Username:</label>\n" +
           "            <input type='text' id='username' name='username' pattern='[a-zA-Z0-9_-]{3,50}' required>\n" +
           "            <small class='error' id='usernameError'></small>\n" +
           "        </div>\n" +
           "        <div>\n" +
           "            <label for='email'>Email:</label>\n" +
           "            <input type='email' id='email' name='email' required>\n" +
           "            <small class='error' id='emailError'></small>\n" +
           "        </div>\n" +
           "        <button type='submit'>Submit</button>\n" +
           "        <div id='message'></div>\n" +
           "    </form>\n" +
           "\n" +
           "    <script>\n" +
           "        document.getElementById('safeForm').addEventListener('submit', async (e) => {\n" +
           "            e.preventDefault();\n" +
           "            const username = document.getElementById('username').value;\n" +
           "            const email = document.getElementById('email').value;\n" +
           "\n" +
           "            try {\n" +
           "                const response = await fetch('/submit', {\n" +
           "                    method: 'POST',\n" +
           "                    headers: { 'Content-Type': 'application/json' },\n" +
           "                    body: JSON.stringify({ username, email })\n" +
           "                });\n" +
           "\n" +
           "                const result = await response.json();\n" +
           "                const messageDiv = document.getElementById('message');\n" +
           "\n" +
           "                if (response.ok) {\n" +
           "                    messageDiv.innerHTML = '<div class=\"success\">Form submitted successfully!</div>';\n" +
           "                    document.getElementById('safeForm').reset();\n" +
           "                } else {\n" +
           "                    messageDiv.innerHTML = '<div class=\"error\">' + result.error + '</div>';\n" +
           "                }\n" +
           "            } catch (error) {\n" +
           "                document.getElementById('message').innerHTML = '<div class=\"error\">Error submitting form</div>';\n" +
           "            }\n" +
           "        });\n" +
           "    </script>\n" +
           "</body>\n" +
           "</html>";
}

static string GetLandingPage(string? userName = null)
{
    return "<!DOCTYPE html>\n" +
           "<html>\n" +
           "<head>\n" +
           "    <title>SafeVault Home</title>\n" +
           "    <style>\n" +
           "        body { font-family: Arial, sans-serif; margin: 20px; }\n" +
           "        a { display: inline-block; margin-right: 12px; }\n" +
           "    </style>\n" +
           "</head>\n" +
           "<body>\n" +
           GetPageHeader(userName) +
           "    <h1>SafeVault</h1>\n" +
           "    <p>Welcome to SafeVault. Use the links below to register, log in, or access the admin dashboard.</p>\n" +
           "    <a href=\"/register\">Register</a>\n" +
           "    <a href=\"/login\">Login</a>\n" +
           "    <a href=\"/admin\">Admin Dashboard</a>\n" +
           "    <a href=\"/safe\">Safe Form</a>\n" +
           "</body>\n" +
           "</html>";
}

static string GetRegisterPage(string? message = null, string? userName = null)
{
    var feedback = string.IsNullOrEmpty(message)
        ? string.Empty
        : $"<div style='color: red; margin-bottom: 16px;'>" + WebUtility.HtmlEncode(message) + "</div>";

    return "<!DOCTYPE html>\n" +
           "<html>\n" +
           "<head>\n" +
           "    <title>Register</title>\n" +
           "    <style>\n" +
           "        body { font-family: Arial, sans-serif; margin: 20px; }\n" +
           "        form { max-width: 400px; }\n" +
           "        input { display: block; margin: 10px 0; padding: 8px; width: 100%; }\n" +
           "        button { padding: 10px 20px; background-color: #007bff; color: white; border: none; cursor: pointer; }\n" +
           "    </style>\n" +
           "</head>\n" +
           "<body>\n" +
           GetPageHeader(userName) +
           "    <h1>Register</h1>\n" +
           feedback +
           "    <form method=\"post\" action=\"/register\">\n" +
           "        <label>Name</label>\n" +
           "        <input type=\"text\" name=\"Name\" required />\n" +
           "        <label>Email</label>\n" +
           "        <input type=\"email\" name=\"Email\" required />\n" +
           "        <label>Password</label>\n" +
           "        <input type=\"password\" name=\"Password\" required minlength=\"6\" />\n" +
           "        <button type=\"submit\">Register</button>\n" +
           "    </form>\n" +
           "    <p><a href=\"/login\">Already have an account? Login</a></p>\n" +
           "    <p><a href=\"/\" style=\"display:inline-block; margin-top:12px; padding:10px 18px; background:#6c757d; color:white; text-decoration:none; border-radius:4px;\">Home</a></p>\n" +
           "</body>\n" +
           "</html>";
}

static string GetLoginPage(string? message = null, string? userName = null)
{
    var feedback = string.IsNullOrEmpty(message)
        ? string.Empty
        : $"<div style='color: red; margin-bottom: 16px;'>" + WebUtility.HtmlEncode(message) + "</div>";

    return "<!DOCTYPE html>\n" +
           "<html>\n" +
           "<head>\n" +
           "    <title>Login</title>\n" +
           "    <style>\n" +
           "        body { font-family: Arial, sans-serif; margin: 20px; }\n" +
           "        form { max-width: 400px; }\n" +
           "        input { display: block; margin: 10px 0; padding: 8px; width: 100%; }\n" +
           "        button { padding: 10px 20px; background-color: #007bff; color: white; border: none; cursor: pointer; }\n" +
           "    </style>\n" +
           "</head>\n" +
           "<body>\n" +
           GetPageHeader(userName) +
           "    <h1>Login</h1>\n" +
           feedback +
           "    <form method=\"post\" action=\"/login\">\n" +
           "        <label>Email</label>\n" +
           "        <input type=\"email\" name=\"Email\" required />\n" +
           "        <label>Password</label>\n" +
           "        <input type=\"password\" name=\"Password\" required />\n" +
           "        <button type=\"submit\">Login</button>\n" +
           "    </form>\n" +
           "    <p><a href=\"/register\">Register a new account</a></p>\n" +
           "    <p><a href=\"/\" style=\"display:inline-block; margin-top:12px; padding:10px 18px; background:#6c757d; color:white; text-decoration:none; border-radius:4px;\">Home</a></p>\n" +
           "</body>\n" +
           "</html>";
}

static string GetAdminPage(string? userName = null)
{
    return "<!DOCTYPE html>\n" +
           "<html>\n" +
           "<head>\n" +
           "    <title>Admin Dashboard</title>\n" +
           "    <style>\n" +
           "        body { font-family: Arial, sans-serif; margin: 20px; }\n" +
           "    </style>\n" +
           "</head>\n" +
           "<body>\n" +
           GetPageHeader(userName) +
           "    <h1>Admin Dashboard</h1>\n" +
           "    <p>This is the admin dashboard.</p>\n" +
           "    <p><a href=\"/\" style=\"display:inline-block; margin-top:12px; padding:10px 18px; background:#6c757d; color:white; text-decoration:none; border-radius:4px;\">Home</a></p>\n" +
           "</body>\n" +
           "</html>";
}

public class RegisterModel
{
    public string? Name { get; set; }
    public string? Email { get; set; }
    public string? Password { get; set; }
}

public class LoginModel
{
    public string? Email { get; set; }
    public string? Password { get; set; }
}
