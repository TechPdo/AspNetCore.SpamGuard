namespace AspNetCore.SpamGuard;

/// <summary>
/// Configuration options for SpamGuard.
/// </summary>
public class SpamGuardOptions
{
    /// <summary>
    /// Google reCAPTCHA v3 secret key.
    /// Get this from https://www.google.com/recaptcha/admin
    /// </summary>
    public string? RecaptchaSecretKey { get; set; }

    /// <summary>
    /// Minimum acceptable reCAPTCHA score (0.0 to 1.0).
    /// Default: 0.5. Lower scores indicate higher likelihood of bot activity.
    /// Google recommends: 0.5 for general use, 0.7 for stricter filtering.
    /// </summary>
    public double RecaptchaMinScore { get; set; } = 0.5;

    /// <summary>
    /// Whether reCAPTCHA token is required for all submissions.
    /// If true, missing token will be treated as spam.
    /// Default: true.
    /// </summary>
    public bool RequireRecaptcha { get; set; } = true;

    /// <summary>
    /// Minimum time in seconds a user should take to fill the form.
    /// Submissions faster than this are likely bots.
    /// Default: 2 seconds.
    /// </summary>
    public double MinFormFillTimeSeconds { get; set; } = 2;

    /// <summary>
    /// Maximum time in seconds before a form submission is considered stale.
    /// Default: 3600 seconds (1 hour).
    /// </summary>
    public double MaxFormFillTimeSeconds { get; set; } = 3600;

    /// <summary>
    /// Field names to check for random text patterns.
    /// Default: name, message, subject, comment.
    /// </summary>
    public string[]? RandomTextCheckFields { get; set; } = new[] { "name", "message", "subject", "comment" };

    /// <summary>
    /// Number of fields that must contain random text to trigger the rule.
    /// Default: 1 (any single field with random text triggers it).
    /// </summary>
    public int RandomTextThreshold { get; set; } = 1;

    /// <summary>
    /// Enable rate limiting based on IP address.
    /// Default: true.
    /// </summary>
    public bool EnableRateLimit { get; set; } = true;

    /// <summary>
    /// Time window in minutes for rate limiting.
    /// Default: 10 minutes.
    /// </summary>
    public int RateLimitWindowMinutes { get; set; } = 10;

    /// <summary>
    /// Maximum number of submissions allowed per IP within the time window.
    /// Default: 3 submissions.
    /// </summary>
    public int RateLimitMaxSubmissions { get; set; } = 3;

    /// <summary>
    /// Overall confidence threshold (0-1) to classify as spam.
    /// If the weighted average of triggered rules exceeds this, it's spam.
    /// Default: 0.7.
    /// </summary>
    public double SpamConfidenceThreshold { get; set; } = 0.7;

    /// <summary>
    /// Keyword blacklist loaded from configuration. If null/empty, the rule falls back to built-in defaults.
    /// </summary>
    public string[]? SpamKeywords { get; set; } = new[]
    {
        "casino", "lottery", "winner", "click here", "limited time","make money fast", "free money"
    };
}
