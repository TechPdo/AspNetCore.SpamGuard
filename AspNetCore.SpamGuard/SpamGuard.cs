using AspNetCore.SpamGuard.Abstractions;
using AspNetCore.SpamGuard.Models;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace AspNetCore.SpamGuard;

/// <summary>
/// Main spam detection service that orchestrates all spam rules.
/// </summary>
internal sealed class SpamGuard : ISpamGuard
{
    private readonly IEnumerable<ISpamRule> _rules;
    private readonly SpamGuardOptions _options;
    private readonly ILogger<SpamGuard> _logger;

    public SpamGuard(IEnumerable<ISpamRule> rules, IOptions<SpamGuardOptions> options, ILogger<SpamGuard> logger)
    {
        _rules = rules;
        _options = options.Value;
        _logger = logger;
    }

    public async Task<SpamCheckResult> CheckAsync(SpamCheckContext context, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(context);

        var result = new SpamCheckResult();
        var disabled = new HashSet<string>(_options.DisabledRules ?? Array.Empty<string>(), StringComparer.OrdinalIgnoreCase);
        var notSpamProbability = 1.0;

        foreach (var rule in _rules)
        {
            if (disabled.Contains(rule.RuleName))
            {
                continue;
            }

            cancellationToken.ThrowIfCancellationRequested();

            try
            {
                if (await rule.IsSpamAsync(context, cancellationToken).ConfigureAwait(false))
                {
                    var severity = Math.Clamp(rule.Severity, 0, 1);
                    notSpamProbability *= 1 - severity;
                    result.TriggeredRules.Add(rule.RuleName);
                    result.Messages.Add($"{rule.RuleName} rule triggered (severity: {severity:F2})");
                }
            }
            catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
            {
                throw;
            }
            catch (Exception ex)
            {
                // A failing rule must not break the whole check; details go to the log, not the result.
                _logger.LogError(ex, "SpamGuard rule {RuleName} failed and was skipped.", rule.RuleName);
                result.FailedRules.Add(rule.RuleName);
                result.Messages.Add($"{rule.RuleName} rule could not be evaluated.");
            }
        }

        result.ConfidenceScore = result.TriggeredRules.Count == 0 ? 0 : 1 - notSpamProbability;
        result.IsSpam = result.TriggeredRules.Count > 0 && result.ConfidenceScore >= _options.SpamConfidenceThreshold;

        if (result.IsSpam)
        {
            _logger.LogInformation(
                "SpamGuard flagged submission as spam. Score: {Score:F2}, Rules: {Rules}",
                result.ConfidenceScore,
                string.Join(", ", result.TriggeredRules));
        }

        return result;
    }
}
