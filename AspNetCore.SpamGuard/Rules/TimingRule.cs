using AspNetCore.SpamGuard.Abstractions;
using AspNetCore.SpamGuard.Models;
using Microsoft.Extensions.Options;

namespace AspNetCore.SpamGuard.Rules;

/// <summary>
/// Detects spam based on form submission timing.
/// Bots typically submit forms too quickly or at suspiciously consistent intervals.
/// </summary>
public class TimingRule : ISpamRule
{
    private readonly SpamGuardOptions _options;

    public string RuleName => "Timing";
    public double Severity => 0.7;

    public TimingRule(IOptions<SpamGuardOptions> options)
    {
        _options = options.Value;
    }

    public Task<bool> IsSpamAsync(SpamCheckContext context, CancellationToken cancellationToken = default)
    {
        if (!context.FormRenderedAt.HasValue || !context.FormSubmittedAt.HasValue)
        {
            // Can't check timing without both timestamps
            return Task.FromResult(false);
        }

        var elapsedMs = context.FormSubmittedAt.Value - context.FormRenderedAt.Value;
        var elapsedSeconds = elapsedMs / 1000.0;

        // Too fast - bot filled it instantly
        if (elapsedSeconds < _options.MinFormFillTimeSeconds)
        {
            return Task.FromResult(true);
        }

        // Too slow - might be a bot that waits a fixed time
        // or someone who left the form open for days (less reliable signal)
        if (elapsedSeconds > _options.MaxFormFillTimeSeconds)
        {
            // This is a weaker signal, so you might want to lower severity
            // or only flag if combined with other rules
            return Task.FromResult(false); // Disabled by default - can enable if needed
        }

        return Task.FromResult(false);
    }
}
