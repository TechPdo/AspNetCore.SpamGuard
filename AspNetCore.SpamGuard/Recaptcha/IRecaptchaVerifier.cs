namespace AspNetCore.SpamGuard.Recaptcha;

/// <summary>
/// Service for verifying reCAPTCHA v3 tokens.
/// </summary>
public interface IRecaptchaVerifier
{
    /// <summary>
    /// Verifies a reCAPTCHA token with Google's API.
    /// </summary>
    /// <param name="token">The reCAPTCHA token from the client.</param>
    /// <param name="remoteIp">Optional IP address of the user.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>The verification response from Google.</returns>
    Task<RecaptchaResponse> VerifyAsync(string token, string? remoteIp = null, CancellationToken cancellationToken = default);
}
