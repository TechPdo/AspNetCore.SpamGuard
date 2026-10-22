namespace AspNetCore.SpamGuard.Models;

/// <summary>
/// Result of spam detection check.
/// </summary>
public class SpamCheckResult
{
    /// <summary>
    /// Indicates whether the submission is classified as spam.
    /// </summary>
    public bool IsSpam { get; set; }

    /// <summary>
    /// Confidence score (0-1). Higher values indicate higher confidence that it's spam.
    /// Computed as <c>1 - Π(1 - severity)</c> over the triggered rules.
    /// </summary>
    public double ConfidenceScore { get; set; }

    /// <summary>
    /// List of rule names that were triggered.
    /// </summary>
    public List<string> TriggeredRules { get; set; } = new();

    /// <summary>
    /// List of rule names that threw an exception and could not be evaluated (details are logged).
    /// </summary>
    public List<string> FailedRules { get; set; } = new();

    /// <summary>
    /// Detailed messages explaining why certain rules were triggered.
    /// </summary>
    public List<string> Messages { get; set; } = new();

    /// <summary>
    /// Creates a result indicating the submission is not spam.
    /// </summary>
    public static SpamCheckResult NotSpam() => new()
    {
        IsSpam = false,
        ConfidenceScore = 0
    };

    /// <summary>
    /// Creates a result indicating the submission is spam.
    /// </summary>
    public static SpamCheckResult Spam(string ruleName, double confidence, string? message = null)
    {
        var result = new SpamCheckResult
        {
            IsSpam = true,
            ConfidenceScore = confidence,
            TriggeredRules = new List<string> { ruleName }
        };

        if (!string.IsNullOrEmpty(message))
        {
            result.Messages.Add(message);
        }

        return result;
    }
}
