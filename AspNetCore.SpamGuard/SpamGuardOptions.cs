namespace AspNetCore.SpamGuard;

/// <summary>
/// Configuration options for SpamGuard.
/// </summary>
/// <remarks>
/// Collection properties default to <c>null</c> on purpose: <c>ConfigurationBinder</c> appends configured
/// array items to pre-populated arrays, so built-in defaults are applied by the rules instead.
/// </remarks>
public class SpamGuardOptions
{
    /// <summary>
    /// Default configuration section name ("SpamGuard").
    /// </summary>
    public const string SectionName = "SpamGuard";

    /// <summary>
    /// Field names checked by <see cref="Rules.RandomTextRule"/> when <see cref="RandomTextCheckFields"/> is not configured.
    /// </summary>
    public static readonly IReadOnlyList<string> DefaultRandomTextCheckFields = new[] { "name", "message", "subject", "comment" };

    /// <summary>
    /// Google reCAPTCHA v3 secret key. Get this from https://www.google.com/recaptcha/admin.
    /// Required when <see cref="RequireRecaptcha"/> is true.
    /// </summary>
    public string? RecaptchaSecretKey { get; set; }

    /// <summary>
    /// Google reCAPTCHA v3 site (public) key. Not used by the library itself; exposed for convenience in views.
    /// </summary>
    public string? RecaptchaSiteKey { get; set; }

    /// <summary>
    /// Minimum acceptable reCAPTCHA score (0.0 to 1.0). Default: 0.5.
    /// </summary>
    public double RecaptchaMinScore { get; set; } = 0.5;

    /// <summary>
    /// Whether a reCAPTCHA token is required for all submissions. A missing token is treated as spam.
    /// When true, <see cref="RecaptchaSecretKey"/> must be configured (validated at startup). Default: true.
    /// </summary>
    public bool RequireRecaptcha { get; set; } = true;

    /// <summary>
    /// Expected reCAPTCHA action (e.g. "submit"). When set, tokens issued for a different action are rejected.
    /// </summary>
    public string? RecaptchaExpectedAction { get; set; }

    /// <summary>
    /// Allowed hostnames for reCAPTCHA tokens. When set, tokens solved on other hostnames are rejected.
    /// </summary>
    public string[]? RecaptchaAllowedHostnames { get; set; }

    /// <summary>
    /// Minimum time in seconds a user should take to fill the form. Default: 2 seconds.
    /// </summary>
    public double MinFormFillTimeSeconds { get; set; } = 2;

    /// <summary>
    /// Maximum time in seconds before a form submission is considered stale. Default: 3600 seconds (1 hour).
    /// Only enforced when <see cref="FlagStaleSubmissions"/> is true.
    /// </summary>
    public double MaxFormFillTimeSeconds { get; set; } = 3600;

    /// <summary>
    /// Flag submissions older than <see cref="MaxFormFillTimeSeconds"/> as spam. Default: false.
    /// </summary>
    public bool FlagStaleSubmissions { get; set; }

    /// <summary>
    /// Require a server-signed form token (see <see cref="Abstractions.ISpamGuardFormTokenService"/>).
    /// When true, submissions without a token are flagged by the timing rule. Default: false.
    /// </summary>
    public bool RequireFormToken { get; set; }

    /// <summary>
    /// Name of the hidden form field that carries the signed form token. Default: "__SpamGuardToken".
    /// </summary>
    public string FormTokenFieldName { get; set; } = "__SpamGuardToken";

    /// <summary>
    /// Name of the honeypot form field. Default: "website".
    /// </summary>
    public string HoneypotFieldName { get; set; } = "website";

    /// <summary>
    /// Name of the form field that carries the reCAPTCHA token. Default: "recaptchaToken".
    /// </summary>
    public string RecaptchaTokenFieldName { get; set; } = "recaptchaToken";

    /// <summary>
    /// Name of the (client-side) form-rendered timestamp field, in Unix milliseconds. Default: "formRenderedAt".
    /// </summary>
    public string FormRenderedAtFieldName { get; set; } = "formRenderedAt";

    /// <summary>
    /// Name of the email field inspected by email-based rules. Default: "email".
    /// </summary>
    public string EmailFieldName { get; set; } = "email";

    /// <summary>
    /// Field names to check for random text patterns.
    /// Default (when null or empty): <see cref="DefaultRandomTextCheckFields"/>.
    /// </summary>
    public string[]? RandomTextCheckFields { get; set; }

    /// <summary>
    /// Number of fields that must contain random text to trigger the rule. Default: 1.
    /// </summary>
    public int RandomTextThreshold { get; set; } = 1;

    /// <summary>
    /// Maximum number of characters per field analysed by the random text rule. Default: 2000.
    /// </summary>
    public int RandomTextMaxInputLength { get; set; } = 2000;

    /// <summary>
    /// Enable rate limiting based on IP address. Default: true.
    /// </summary>
    public bool EnableRateLimit { get; set; } = true;

    /// <summary>
    /// Time window in minutes for rate limiting. Default: 10 minutes.
    /// </summary>
    public int RateLimitWindowMinutes { get; set; } = 10;

    /// <summary>
    /// Maximum number of submissions allowed per IP within the time window. Default: 3.
    /// </summary>
    public int RateLimitMaxSubmissions { get; set; } = 3;

    /// <summary>
    /// Overall confidence threshold (0-1) to classify as spam. Default: 0.7.
    /// The confidence score combines triggered rule severities as <c>1 - Π(1 - severity)</c>.
    /// </summary>
    public double SpamConfidenceThreshold { get; set; } = 0.7;

    /// <summary>
    /// Keyword blacklist. Matched case-insensitively on whole words. Default: none.
    /// </summary>
    public string[]? SpamKeywords { get; set; }

    /// <summary>
    /// Names of rules (see <see cref="Rules.SpamRuleNames"/> or custom <c>RuleName</c>s) that should not be evaluated.
    /// </summary>
    public string[]? DisabledRules { get; set; }

    /// <summary>
    /// Options for the StopForumSpam database lookup rule (disabled by default).
    /// </summary>
    public SpamDatabaseOptions SpamDatabase { get; set; } = new();
}

/// <summary>
/// Options for the StopForumSpam (https://www.stopforumspam.com) lookup rule.
/// </summary>
public class SpamDatabaseOptions
{
    /// <summary>
    /// Enables StopForumSpam lookups. Default: false (opt-in, because it sends data to a third party).
    /// </summary>
    public bool Enabled { get; set; }

    /// <summary>
    /// API endpoint. Default: https://api.stopforumspam.org/api.
    /// </summary>
    public string BaseUrl { get; set; } = "https://api.stopforumspam.org/api";

    /// <summary>
    /// Look up the client IP address (private, loopback and link-local addresses are never sent). Default: true.
    /// </summary>
    public bool CheckIp { get; set; } = true;

    /// <summary>
    /// Look up the submitted email address. Only an MD5 hash of the email is sent. Default: true.
    /// </summary>
    public bool CheckEmail { get; set; } = true;

    /// <summary>
    /// Minimum StopForumSpam confidence (0-100) required to flag a submission. Default: 50.
    /// </summary>
    public double MinConfidence { get; set; } = 50;

    /// <summary>
    /// How long lookup results are cached, in minutes. 0 disables caching. Default: 60.
    /// </summary>
    public int CacheMinutes { get; set; } = 60;

    /// <summary>
    /// HTTP timeout for lookups, in seconds. Default: 3.
    /// </summary>
    public double TimeoutSeconds { get; set; } = 3;
}
