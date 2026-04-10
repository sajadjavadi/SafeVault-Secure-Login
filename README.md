# CourseProject - SafeVault

## Overview
SafeVault is a sample ASP.NET Core application demonstrating secure authentication and authorization using ASP.NET Core Identity with an in-memory Entity Framework Core store. The project includes user registration, login, role-based access control, session-aware UI, and input validation to reduce common web security risks.

## Project Structure
- `CourseProject.slnx` - Solution file for the SafeVault application and test project.
- `SafeVault/` - Main ASP.NET Core application.
  - `Program.cs` - Minimal API configuration, route definitions, authentication/authorization setup, UI rendering, and form handling.
  - `ApplicationUser.cs` - Custom Identity user model with a `Name` property.
  - `ApplicationDbContext.cs` - Identity `DbContext` configured for an in-memory database.
  - `SeedData.cs` - Initial role and admin user seeding logic.
  - `InputValidator.cs` - Input sanitization and validation helpers for username, email, SQL injection, and XSS patterns.
  - `webform.html` - Static sample form (if present) for manual UI testing.
- `Tests/` - NUnit test project for validation and security checks.
  - `TestInputValidation.cs` - Unit tests for input sanitization and validation utilities.
  - `TestAuthentication.cs` - Tests for authentication and password hashing behavior.
  - `TestAuthorization.cs` - Tests for role-based authorization and policy enforcement.

## Key Functionalities
- User registration with password hashing through ASP.NET Core Identity.
- Login with session management and redirect behavior.
- Role-based admin dashboard protected by the `Admin` role.
- Seeded admin account for initial role management.
- Account lockout after repeated failed login attempts.
- Input sanitization for usernames and emails.
- Validation checks for basic SQL injection and XSS attack patterns.
- Logout support and authenticated user display in the UI.

## Security Considerations
- Uses an in-memory database for demonstration and testing only.
- Authentication and authorization are powered by ASP.NET Core Identity.
- Account lockout is enabled to reduce brute-force login attempts.
- CORS and cookie security should be tightened before production deployment.

## Running the Project
1. Open the solution in Visual Studio or VS Code.
2. Restore NuGet packages.
3. Run the `SafeVault` project.
4. Access the app in the browser and use the registration or login pages.

## Testing
Run the NUnit test project from the solution or use the command line:

```bash
dotnet test Tests\Tests.csproj
```
