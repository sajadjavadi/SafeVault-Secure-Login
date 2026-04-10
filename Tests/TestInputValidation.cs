using NUnit.Framework;
using SafeVault;

[TestFixture]
public class TestInputValidation
{
    #region Username Sanitization Tests

    [Test]
    public void TestSanitizeUsername_ValidInput()
    {
        string input = "john_doe-123";
        string result = InputValidator.SanitizeUsername(input);
        Assert.That(result, Is.EqualTo("john_doe-123"));
    }

    [Test]
    public void TestSanitizeUsername_RemovesSpecialCharacters()
    {
        string input = "john@doe#123!";
        string result = InputValidator.SanitizeUsername(input);
        Assert.That(result, Is.EqualTo("johndoe123"));
    }

    [Test]
    public void TestSanitizeUsername_RemovesSpaces()
    {
        string input = "john doe 123";
        string result = InputValidator.SanitizeUsername(input);
        Assert.That(result, Is.EqualTo("johndoe123"));
    }

    [Test]
    public void TestSanitizeUsername_EmptyInput()
    {
        string result = InputValidator.SanitizeUsername("");
        Assert.That(result, Is.EqualTo(string.Empty));
    }

    [Test]
    public void TestSanitizeUsername_NullInput()
    {
        string result = InputValidator.SanitizeUsername(null!);
        Assert.That(result, Is.EqualTo(string.Empty));
    }

    [Test]
    public void TestSanitizeUsername_ExceedsMaxLength()
    {
        string input = new string('a', 100);
        string result = InputValidator.SanitizeUsername(input);
        Assert.That(result.Length, Is.EqualTo(50));
    }

    [Test]
    public void TestSanitizeUsername_WithWhitespace()
    {
        string input = "  john_doe  ";
        string result = InputValidator.SanitizeUsername(input);
        Assert.That(result, Is.EqualTo("john_doe"));
    }

    #endregion

    #region Email Sanitization Tests

    [Test]
    public void TestSanitizeEmail_ValidInput()
    {
        string input = "test@example.com";
        string result = InputValidator.SanitizeEmail(input);
        Assert.That(result, Is.EqualTo("test@example.com"));
    }

    [Test]
    public void TestSanitizeEmail_InvalidFormat_NoAtSign()
    {
        string input = "testexample.com";
        string result = InputValidator.SanitizeEmail(input);
        Assert.That(result, Is.EqualTo(string.Empty));
    }

    [Test]
    public void TestSanitizeEmail_InvalidFormat_NoDomain()
    {
        string input = "test@";
        string result = InputValidator.SanitizeEmail(input);
        Assert.That(result, Is.EqualTo(string.Empty));
    }

    [Test]
    public void TestSanitizeEmail_InvalidFormat_NoTLD()
    {
        string input = "test@example";
        string result = InputValidator.SanitizeEmail(input);
        Assert.That(result, Is.EqualTo(string.Empty));
    }

    [Test]
    public void TestSanitizeEmail_WithWhitespace()
    {
        string input = "  test@example.com  ";
        string result = InputValidator.SanitizeEmail(input);
        Assert.That(result, Is.EqualTo("test@example.com"));
    }

    [Test]
    public void TestSanitizeEmail_NullInput()
    {
        string result = InputValidator.SanitizeEmail(null!);
        Assert.That(result, Is.EqualTo(string.Empty));
    }

    [Test]
    public void TestSanitizeEmail_ComplexValidEmail()
    {
        string input = "user.name+tag@example.co.uk";
        string result = InputValidator.SanitizeEmail(input);
        Assert.That(result, Is.EqualTo("user.name+tag@example.co.uk"));
    }

    [Test]
    public void TestSanitizeEmail_ExceedsMaxLength()
    {
        string input = new string('a', 300) + "@example.com";
        string result = InputValidator.SanitizeEmail(input);
        Assert.That(result.Length, Is.EqualTo(254));
    }

    #endregion

    #region SQL Injection Detection Tests

    [Test]
    public void TestIsSqlSafe_ValidInput()
    {
        string input = "john_doe";
        bool result = InputValidator.IsSqlSafe(input);
        Assert.That(result, Is.True);
    }

    [Test]
    public void TestForSQLInjection_UnionSelect()
    {
        string input = "admin' UNION SELECT * FROM users--";
        bool result = InputValidator.IsSqlSafe(input);
        Assert.That(result, Is.False);
    }

    [Test]
    public void TestForSQLInjection_OrStatement()
    {
        string input = "' OR '1'='1";
        bool result = InputValidator.IsSqlSafe(input);
        Assert.That(result, Is.False);
    }

    [Test]
    public void TestForSQLInjection_DropTable()
    {
        string input = "'; DROP TABLE users;--";
        bool result = InputValidator.IsSqlSafe(input);
        Assert.That(result, Is.False);
    }

    [Test]
    public void TestForSQLInjection_Insert()
    {
        string input = "INSERT INTO users VALUES (...)";
        bool result = InputValidator.IsSqlSafe(input);
        Assert.That(result, Is.False);
    }

    [Test]
    public void TestForSQLInjection_SqlComment()
    {
        string input = "user; -- comment";
        bool result = InputValidator.IsSqlSafe(input);
        Assert.That(result, Is.False);
    }

    [Test]
    public void TestIsSqlSafe_NullInput()
    {
        bool result = InputValidator.IsSqlSafe(null!);
        Assert.That(result, Is.True);
    }

    #endregion

    #region XSS Detection Tests

    [Test]
    public void TestForXSS_ValidInput()
    {
        string input = "john_doe";
        bool result = InputValidator.IsXssSafe(input);
        Assert.That(result, Is.True);
    }

    [Test]
    public void TestForXSS_ScriptTag()
    {
        string input = "<script>alert('xss')</script>";
        bool result = InputValidator.IsXssSafe(input);
        Assert.That(result, Is.False);
    }

    [Test]
    public void TestForXSS_JavascriptProtocol()
    {
        string input = "<a href=\"javascript:alert('xss')\">Click</a>";
        bool result = InputValidator.IsXssSafe(input);
        Assert.That(result, Is.False);
    }

    [Test]
    public void TestForXSS_OnErrorAttribute()
    {
        string input = "<img src=x onerror=alert('xss')>";
        bool result = InputValidator.IsXssSafe(input);
        Assert.That(result, Is.False);
    }

    [Test]
    public void TestForXSS_IframeTag()
    {
        string input = "<iframe src=\"evil.com\"></iframe>";
        bool result = InputValidator.IsXssSafe(input);
        Assert.That(result, Is.False);
    }

    [Test]
    public void TestForXSS_OnClickAttribute()
    {
        string input = "<button onclick=\"alert('xss')\">Click</button>";
        bool result = InputValidator.IsXssSafe(input);
        Assert.That(result, Is.False);
    }

    [Test]
    public void TestIsXssSafe_NullInput()
    {
        bool result = InputValidator.IsXssSafe(null!);
        Assert.That(result, Is.True);
    }

    [Test]
    public void TestForXSS_EmbedTag()
    {
        string input = "<embed src=\"evil.swf\">";
        bool result = InputValidator.IsXssSafe(input);
        Assert.That(result, Is.False);
    }

    #endregion

    #region HTML Encoding Tests

    [Test]
    public void TestHtmlEncode_ConvertsLessThan()
    {
        string input = "<";
        string result = InputValidator.HtmlEncode(input);
        Assert.That(result, Is.EqualTo("&lt;"));
    }

    [Test]
    public void TestHtmlEncode_ConvertsGreaterThan()
    {
        string input = ">";
        string result = InputValidator.HtmlEncode(input);
        Assert.That(result, Is.EqualTo("&gt;"));
    }

    [Test]
    public void TestHtmlEncode_ConvertsAmpersand()
    {
        string input = "&";
        string result = InputValidator.HtmlEncode(input);
        Assert.That(result, Is.EqualTo("&amp;"));
    }

    [Test]
    public void TestHtmlEncode_ConvertsDoubleQuote()
    {
        string input = "\"";
        string result = InputValidator.HtmlEncode(input);
        Assert.That(result, Is.EqualTo("&quot;"));
    }

    [Test]
    public void TestHtmlEncode_ConvertsSingleQuote()
    {
        string input = "'";
        string result = InputValidator.HtmlEncode(input);
        Assert.That(result, Is.EqualTo("&#39;"));
    }

    [Test]
    public void TestHtmlEncode_ComplexString()
    {
        string input = "<script>alert('XSS');</script>";
        string result = InputValidator.HtmlEncode(input);
        Assert.That(result, Is.EqualTo("&lt;script&gt;alert(&#39;XSS&#39;);&lt;/script&gt;"));
    }

    [Test]
    public void TestHtmlEncode_NullInput()
    {
        string result = InputValidator.HtmlEncode(null!);
        Assert.That(result, Is.Null);
    }

    [Test]
    public void TestHtmlEncode_ValidInput()
    {
        string input = "Hello World";
        string result = InputValidator.HtmlEncode(input);
        Assert.That(result, Is.EqualTo("Hello World"));
    }

    #endregion

    #region Integration Tests

    [Test]
    public void TestFullFlow_ValidUserRegistration()
    {
        string username = "john_doe123";
        string email = "john@example.com";

        // Check security
        Assert.That(InputValidator.IsXssSafe(username), Is.True);
        Assert.That(InputValidator.IsXssSafe(email), Is.True);
        Assert.That(InputValidator.IsSqlSafe(username), Is.True);
        Assert.That(InputValidator.IsSqlSafe(email), Is.True);

        // Sanitize
        string sanitizedUsername = InputValidator.SanitizeUsername(username);
        string sanitizedEmail = InputValidator.SanitizeEmail(email);

        // Verify results
        Assert.That(string.IsNullOrEmpty(sanitizedUsername), Is.False);
        Assert.That(string.IsNullOrEmpty(sanitizedEmail), Is.False);
        Assert.That(sanitizedUsername, Is.EqualTo("john_doe123"));
        Assert.That(sanitizedEmail, Is.EqualTo("john@example.com"));
    }

    [Test]
    public void TestFullFlow_MaliciousInput()
    {
        string username = "<script>alert('xss')</script>";
        string email = "test@example.com' OR '1'='1";

        // Check security - should fail
        Assert.That(InputValidator.IsXssSafe(username), Is.False);
        Assert.That(InputValidator.IsSqlSafe(email), Is.False);
    }

    #endregion
}