namespace AspNetCore.SpamGuard.Models;

/// <summary>
/// Context object containing all data needed for spam detection.
/// </summary>
public class SpamCheckContext
{
    /// <summary>
    /// Form field values (e.g., name, email, message, etc.).
    /// </summary>
    public Dictionary<string, string> FormData { get; set; } = new();

    /// <summary>
    /// reCAPTCHA v3 token from the client.
    /// </summary>
    public string? RecaptchaToken { get; set; }

    /// <summary>
    /// Honeypot field value (should be empty in legitimate submissions).
    /// </summary>
    public string? HoneypotValue { get; set; }

    /// <summary>
    /// Time when the form was rendered (UTC timestamp in milliseconds).
    /// Used for timing analysis.
    /// </summary>
    public long? FormRenderedAt { get; set; }

    /// <summary>
    /// Time when the form was submitted (UTC timestamp in milliseconds).
    /// Used for timing analysis.
    /// </summary>
    public long? FormSubmittedAt { get; set; }

    /// <summary>
    /// Client IP address for rate limiting.
    /// </summary>
    public string? IpAddress { get; set; }

    /// <summary>
    /// User agent string.
    /// </summary>
    public string? UserAgent { get; set; }

    /// <summary>
    /// Additional metadata for custom rules.
    /// </summary>
    public Dictionary<string, object> Metadata { get; set; } = new();
}
