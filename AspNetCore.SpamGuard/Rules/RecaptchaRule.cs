using AspNetCore.SpamGuard.Abstractions;
using AspNetCore.SpamGuard.Models;
using AspNetCore.SpamGuard.Recaptcha;
using Microsoft.Extensions.Options;

namespace AspNetCore.SpamGuard.Rules;

/// <summary>
/// Validates Google reCAPTCHA v3 token and score.
/// </summary>
public class RecaptchaRule : ISpamRule
{
    private readonly IRecaptchaVerifier _verifier;
    private readonly SpamGuardOptions _options;

    public string RuleName => "Recaptcha";
    public double Severity => 0.8;

    public RecaptchaRule(IRecaptchaVerifier verifier, IOptions<SpamGuardOptions> options)
    {
        _verifier = verifier;
        _options = options.Value;
    }

    public async Task<bool> IsSpamAsync(SpamCheckContext context, CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrWhiteSpace(context.RecaptchaToken))
        {
            // If reCAPTCHA is required but missing, consider it spam
            return _options.RequireRecaptcha;
        }

        var response = await _verifier.VerifyAsync(
            context.RecaptchaToken, 
            context.IpAddress, 
            cancellationToken);

        if (!response.Success)
        {
            return true; // Verification failed
        }

        // Check if score is below threshold
        return response.Score < _options.RecaptchaMinScore;
    }
}
