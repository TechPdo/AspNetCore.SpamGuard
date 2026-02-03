using AspNetCore.SpamGuard.Abstractions;
using AspNetCore.SpamGuard.Models;

namespace AspNetCore.SpamGuard.Rules;

/// <summary>
/// Detects spam by checking if a honeypot field (invisible to users) has been filled.
/// Bots typically fill all fields, including hidden ones.
/// </summary>
public class HoneypotRule : ISpamRule
{
    public string RuleName => "Honeypot";
    public double Severity => 0.95; // Very high confidence if honeypot is filled

    public Task<bool> IsSpamAsync(SpamCheckContext context, CancellationToken cancellationToken = default)
    {
        // If honeypot field has any value, it's likely spam
        var isSpam = !string.IsNullOrWhiteSpace(context.HoneypotValue);
        return Task.FromResult(isSpam);
    }
}
