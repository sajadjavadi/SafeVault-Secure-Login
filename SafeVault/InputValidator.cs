using System.Text.RegularExpressions;
using System.Text;

namespace SafeVault;

/// <summary>
/// Utility class for sanitizing and validating user inputs to prevent security vulnerabilities.
/// </summary>
public static class InputValidator
{
    /// <summary>
    /// Sanitizes a username by removing potentially dangerous characters.
    /// Allows only alphanumeric characters, underscores, and hyphens.
    /// </summary>
    /// <param name="input">The username to sanitize</param>
    /// <returns>Sanitized username</returns>
    public static string SanitizeUsername(string input)
    {
        if (string.IsNullOrWhiteSpace(input))
            return string.Empty;

        // Remove leading/trailing whitespace
        input = input.Trim();

        // Allow only alphanumeric, underscore, and hyphen
        input = Regex.Replace(input, @"[^a-zA-Z0-9_-]", string.Empty);

        // Limit length to prevent abuse
        return input.Length > 50 ? input.Substring(0, 50) : input;
    }

    /// <summary>
    /// Sanitizes an email address by validating format and removing dangerous characters.
    /// </summary>
    /// <param name="input">The email to sanitize</param>
    /// <returns>Sanitized email if valid, empty string otherwise</returns>
    public static string SanitizeEmail(string input)
    {
        if (string.IsNullOrWhiteSpace(input))
            return string.Empty;

        // Remove leading/trailing whitespace
        input = input.Trim();

        // Basic email validation using regex
        string emailPattern = @"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$";

        if (!Regex.IsMatch(input, emailPattern))
            return string.Empty;

        // Limit length to prevent abuse
        return input.Length > 254 ? input.Substring(0, 254) : input;
    }

    /// <summary>
    /// Performs HTML encoding to prevent XSS (Cross-Site Scripting) attacks.
    /// Converts dangerous HTML characters to their safe equivalents.
    /// </summary>
    /// <param name="input">The input to HTML encode</param>
    /// <returns>HTML-encoded string</returns>
    public static string HtmlEncode(string input)
    {
        if (string.IsNullOrEmpty(input))
            return input;

        var sb = new StringBuilder();
        foreach (char c in input)
        {
            switch (c)
            {
                case '<':
                    sb.Append("&lt;");
                    break;
                case '>':
                    sb.Append("&gt;");
                    break;
                case '"':
                    sb.Append("&quot;");
                    break;
                case '\'':
                    sb.Append("&#39;");
                    break;
                case '&':
                    sb.Append("&amp;");
                    break;
                default:
                    sb.Append(c);
                    break;
            }
        }

        return sb.ToString();
    }

    /// <summary>
    /// Validates that input doesn't contain SQL injection patterns.
    /// </summary>
    /// <param name="input">The input to validate</param>
    /// <returns>True if input appears safe, false otherwise</returns>
    public static bool IsSqlSafe(string input)
    {
        if (string.IsNullOrEmpty(input))
            return true;

        // Pattern to detect common SQL injection attempts
        string[] sqlInjectionPatterns = new[]
        {
            @"(\b(UNION|SELECT|INSERT|UPDATE|DELETE|DROP|CREATE|ALTER|EXEC|EXECUTE)\b)",
            @"(--|#|;|\*)",
            @"('|"")\s*(OR|AND)\s*('|"")",
            @"(\bOR\b\s*1\s*=\s*1)",
            @"(\x27)|(--)|(/\*.*?\*/)"
        };

        foreach (var pattern in sqlInjectionPatterns)
        {
            if (Regex.IsMatch(input, pattern, RegexOptions.IgnoreCase))
                return false;
        }

        return true;
    }

    /// <summary>
    /// Validates that input doesn't contain XSS attack patterns.
    /// </summary>
    /// <param name="input">The input to validate</param>
    /// <returns>True if input appears safe, false otherwise</returns>
    public static bool IsXssSafe(string input)
    {
        if (string.IsNullOrEmpty(input))
            return true;

        // Pattern to detect common XSS attempts
        string[] xssPatterns = new[]
        {
            @"<script[^>]*>.*?</script>",
            @"javascript:",
            @"on\w+\s*=",
            @"<iframe",
            @"<object",
            @"<embed",
            @"<img[^>]*onerror"
        };

        foreach (var pattern in xssPatterns)
        {
            if (Regex.IsMatch(input, pattern, RegexOptions.IgnoreCase))
                return false;
        }

        return true;
    }
}