using AspNetCore.SpamGuard.Abstractions;
using AspNetCore.SpamGuard.Models;
using Microsoft.Extensions.Options;

namespace AspNetCore.SpamGuard;

/// <summary>
/// Main spam detection service that orchestrates all spam rules.
/// </summary>
internal class SpamGuard : ISpamGuard
{
    private readonly IEnumerable<ISpamRule> _rules;
    private readonly SpamGuardOptions _options;

    public SpamGuard(IEnumerable<ISpamRule> rules, IOptions<SpamGuardOptions> options)
    {
        _rules = rules;
        _options = options.Value;
    }

    public async Task<SpamCheckResult> CheckAsync(SpamCheckContext context, CancellationToken cancellationToken = default)
    {
        var result = new SpamCheckResult();
        var triggeredRules = new List<(string Name, double Severity)>();

        // Execute all rules
        foreach (var rule in _rules)
        {
            try
            {
                var isSpam = await rule.IsSpamAsync(context, cancellationToken);
                
                if (isSpam)
                {
                    triggeredRules.Add((rule.RuleName, rule.Severity));
                    result.TriggeredRules.Add(rule.RuleName);
                    result.Messages.Add($"{rule.RuleName} rule triggered (severity: {rule.Severity:F2})");
                }
            }
            catch (Exception ex)
            {
                // Log the exception in production
                // Don't let one rule failure break the entire check
                result.Messages.Add($"{rule.RuleName} rule failed: {ex.Message}");
            }
        }

        // Calculate overall confidence score
        if (triggeredRules.Any())
        {
            // Use weighted average of triggered rules
            result.ConfidenceScore = triggeredRules.Average(r => r.Severity);
            
            // Determine if it's spam based on threshold
            result.IsSpam = result.ConfidenceScore >= _options.SpamConfidenceThreshold;
        }
        else
        {
            result.IsSpam = false;
            result.ConfidenceScore = 0;
        }

        return result;
    }
}
