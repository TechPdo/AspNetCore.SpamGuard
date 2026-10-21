using AspNetCore.SpamGuard.Abstractions;
using AspNetCore.SpamGuard.Models;
using Microsoft.Extensions.Options;

namespace AspNetCore.SpamGuard.Rules;

/// <summary>
/// Detects spam based on form submission timing.
/// Prefers the server-signed <see cref="SpamCheckContext.FormToken"/>; falls back to client timestamps.
/// </summary>
public class TimingRule : ISpamRule
{
    private readonly SpamGuardOptions _options;
    private readonly ISpamGuardFormTokenService _tokenService;
    private readonly TimeProvider _timeProvider;

    public string RuleName => SpamRuleNames.Timing;
    public double Severity => 0.7;

    public TimingRule(IOptions<SpamGuardOptions> options, ISpamGuardFormTokenService tokenService, TimeProvider timeProvider)
    {
        _options = options.Value;
        _tokenService = tokenService;
        _timeProvider = timeProvider;
    }

    public Task<bool> IsSpamAsync(SpamCheckContext context, CancellationToken cancellationToken = default)
    {
        double elapsedSeconds;

        if (!string.IsNullOrWhiteSpace(context.FormToken))
        {
            if (!_tokenService.TryValidateToken(context.FormToken, out var issuedAt))
            {
                return Task.FromResult(true); // forged or tampered token
            }

            elapsedSeconds = (_timeProvider.GetUtcNow() - issuedAt).TotalSeconds;
        }
        else if (_options.RequireFormToken)
        {
            return Task.FromResult(true);
        }
        else if (context.FormRenderedAt is > 0)
        {
            var submittedAt = context.FormSubmittedAt ?? _timeProvider.GetUtcNow().ToUnixTimeMilliseconds();
            elapsedSeconds = (submittedAt - context.FormRenderedAt.Value) / 1000.0;
        }
        else
        {
            return Task.FromResult(false); // no timing information available
        }

        if (elapsedSeconds < _options.MinFormFillTimeSeconds)
        {
            return Task.FromResult(true);
        }

        return Task.FromResult(_options.FlagStaleSubmissions && elapsedSeconds > _options.MaxFormFillTimeSeconds);
    }
}
