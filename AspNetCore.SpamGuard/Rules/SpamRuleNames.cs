namespace AspNetCore.SpamGuard.Rules;

/// <summary>
/// Names of the built-in rules. Use these with <see cref="SpamGuardOptions.DisabledRules"/>.
/// </summary>
public static class SpamRuleNames
{
    public const string Honeypot = "Honeypot";
    public const string Recaptcha = "Recaptcha";
    public const string Timing = "Timing";
    public const string RandomText = "RandomText";
    public const string RateLimit = "RateLimit";
    public const string KeywordBlacklist = "KeywordBlacklist";
    public const string SuspiciousEmail = "SuspiciousEmail";
    public const string SpamDatabase = "SpamDatabase";
}
