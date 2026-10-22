namespace AspNetCore.SpamGuard.Abstractions;

/// <summary>
/// Issues and validates tamper-proof form tokens that carry the server time at which a form was rendered.
/// </summary>
public interface ISpamGuardFormTokenService
{
    /// <summary>
    /// Generates a new protected token containing the current server time.
    /// </summary>
    string GenerateToken();

    /// <summary>
    /// Validates a token and returns the time it was issued.
    /// </summary>
    /// <returns>False if the token is malformed, tampered with, or was issued by a different key ring.</returns>
    bool TryValidateToken(string? token, out DateTimeOffset issuedAt);
}
