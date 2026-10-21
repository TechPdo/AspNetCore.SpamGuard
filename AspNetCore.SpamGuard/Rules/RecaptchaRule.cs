using AspNetCore.SpamGuard.Abstractions;
using AspNetCore.SpamGuard.Models;
using AspNetCore.SpamGuard.Recaptcha;
using Microsoft.Extensions.Options;

namespace AspNetCore.SpamGuard.Rules;

/// <summary>
/// Validates Google reCAPTCHA v3 token, score, and (optionally) action and hostname.
/// </summary>
public class RecaptchaRule : ISpamRule
{
    private readonly IRecaptchaVerifier _verifier;
    private readonly SpamGuardOptions _options;

    public string RuleName => SpamRuleNames.Recaptcha;
    public double Severity => 0.8;

    public RecaptchaRule(IRecaptchaVerifier verifier, IOptions<SpamGuardOptions> options)
    {
        _verifier = verifier;
        _options = options.Value;
    }

    public async Task<bool> IsSpamAsync(SpamCheckContext context, CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrWhiteSpace(_options.RecaptchaSecretKey))
        {
            // Not configured. Options validation prevents this when RequireRecaptcha is true.
            return false;
        }

        if (string.IsNullOrWhiteSpace(context.RecaptchaToken))
        {
            return _options.RequireRecaptcha;
        }

        var response = await _verifier.VerifyAsync(context.RecaptchaToken, context.IpAddress, cancellationToken)
            .ConfigureAwait(false);

        if (!response.Success || response.Score < _options.RecaptchaMinScore)
        {
            return true;
        }

        if (!string.IsNullOrWhiteSpace(_options.RecaptchaExpectedAction) &&
            !string.Equals(response.Action, _options.RecaptchaExpectedAction, StringComparison.Ordinal))
        {
            return true;
        }

        if (_options.RecaptchaAllowedHostnames is { Length: > 0 } hostnames &&
            !hostnames.Contains(response.Hostname, StringComparer.OrdinalIgnoreCase))
        {
            return true;
        }

        return false;
    }
}
