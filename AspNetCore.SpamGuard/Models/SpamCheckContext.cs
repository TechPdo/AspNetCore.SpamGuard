namespace AspNetCore.SpamGuard.Models;

/// <summary>
/// Context object containing all data needed for spam detection.
/// </summary>
public class SpamCheckContext
{
    private Dictionary<string, string> _formData = new(StringComparer.OrdinalIgnoreCase);

    /// <summary>
    /// Form field values (e.g., name, email, message, etc.). Keys are matched case-insensitively;
    /// an assigned dictionary is copied into a case-insensitive one if necessary.
    /// </summary>
    public Dictionary<string, string> FormData
    {
        get => _formData;
        set => _formData = ToCaseInsensitive(value);
    }

    /// <summary>
    /// reCAPTCHA v3 token from the client.
    /// </summary>
    public string? RecaptchaToken { get; set; }

    /// <summary>
    /// Honeypot field value (should be empty in legitimate submissions).
    /// </summary>
    public string? HoneypotValue { get; set; }

    /// <summary>
    /// Server-signed form token issued when the form was rendered
    /// (see <see cref="Abstractions.ISpamGuardFormTokenService"/>). Preferred over client timestamps.
    /// </summary>
    public string? FormToken { get; set; }

    /// <summary>
    /// Time when the form was rendered (UTC timestamp in milliseconds), as reported by the client.
    /// Used for timing analysis when no <see cref="FormToken"/> is present. Can be spoofed.
    /// </summary>
    public long? FormRenderedAt { get; set; }

    /// <summary>
    /// Time when the form was submitted (UTC timestamp in milliseconds). Defaults to the server time when null.
    /// </summary>
    public long? FormSubmittedAt { get; set; }

    /// <summary>
    /// Client IP address for rate limiting and reputation lookups.
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

    private static Dictionary<string, string> ToCaseInsensitive(Dictionary<string, string>? source)
    {
        if (source is null)
        {
            return new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        }

        if (ReferenceEquals(source.Comparer, StringComparer.OrdinalIgnoreCase))
        {
            return source;
        }

        var copy = new Dictionary<string, string>(source.Count, StringComparer.OrdinalIgnoreCase);
        foreach (var (key, value) in source)
        {
            copy[key] = value;
        }

        return copy;
    }
}
