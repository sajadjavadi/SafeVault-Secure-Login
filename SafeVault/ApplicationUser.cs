using Microsoft.AspNetCore.Identity;

namespace SafeVault;

public class ApplicationUser : IdentityUser
{
    public string? Name { get; set; }
}
