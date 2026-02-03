using System.Text.Json.Serialization;

namespace AspNetCore.SpamGuard.Recaptcha;

/// <summary>
/// Response from Google reCAPTCHA verification API.
/// </summary>
public class RecaptchaResponse
{
    /// <summary>
    /// Whether the verification was successful.
    /// </summary>
    [JsonPropertyName("success")]
    public bool Success { get; set; }

    /// <summary>
    /// Score between 0.0 and 1.0, where 1.0 indicates very likely a good interaction.
    /// </summary>
    [JsonPropertyName("score")]
    public double Score { get; set; }

    /// <summary>
    /// The action name for this request (important for token verification).
    /// </summary>
    [JsonPropertyName("action")]
    public string? Action { get; set; }

    /// <summary>
    /// Timestamp of the challenge (ISO format).
    /// </summary>
    [JsonPropertyName("challenge_ts")]
    public string? ChallengeTimestamp { get; set; }

    /// <summary>
    /// Hostname of the site where the reCAPTCHA was solved.
    /// </summary>
    [JsonPropertyName("hostname")]
    public string? Hostname { get; set; }

    /// <summary>
    /// Error codes if verification failed.
    /// </summary>
    [JsonPropertyName("error-codes")]
    public List<string>? ErrorCodes { get; set; }
}
