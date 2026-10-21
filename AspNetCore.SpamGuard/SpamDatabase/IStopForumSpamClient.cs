namespace AspNetCore.SpamGuard.SpamDatabase;

/// <summary>
/// Client for the StopForumSpam reputation database (https://www.stopforumspam.com/usage).
/// </summary>
public interface IStopForumSpamClient
{
    /// <summary>
    /// Looks up an IP address and/or email address. Only an MD5 hash of the email is transmitted.
    /// </summary>
    /// <returns>The lookup result. <see cref="StopForumSpamResult.Success"/> is false when the lookup failed.</returns>
    Task<StopForumSpamResult> LookupAsync(string? ipAddress, string? email, CancellationToken cancellationToken = default);
}

/// <summary>
/// Result of a StopForumSpam lookup.
/// </summary>
public sealed record StopForumSpamResult(
    bool Success,
    bool IpAppears = false,
    double IpConfidence = 0,
    bool EmailAppears = false,
    double EmailConfidence = 0)
{
    /// <summary>
    /// A failed lookup.
    /// </summary>
    public static StopForumSpamResult Failed { get; } = new(false);
}
