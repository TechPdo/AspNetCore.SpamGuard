using AspNetCore.SpamGuard.Abstractions;
using AspNetCore.SpamGuard.Models;

namespace AspNetCore.SpamGuard.Rules;

/// <summary>
/// Detects spam by checking if a honeypot field (invisible to users) has been filled.
/// Bots typically fill all fields, including hidden ones.
/// </summary>
public class HoneypotRule : ISpamRule
{
    public string RuleName => SpamRuleNames.Honeypot;
    public double Severity => 0.95;

    public Task<bool> IsSpamAsync(SpamCheckContext context, CancellationToken cancellationToken = default)
    {
        return Task.FromResult(!string.IsNullOrWhiteSpace(context.HoneypotValue));
    }
}
