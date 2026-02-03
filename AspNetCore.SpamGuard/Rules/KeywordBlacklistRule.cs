using AspNetCore.SpamGuard.Abstractions;
using AspNetCore.SpamGuard.Models;
using Microsoft.Extensions.Options;

namespace AspNetCore.SpamGuard.Rules;

/// <summary>
/// Example: Detects known spam keywords. Keywords are loaded from configuration (SpamGuard:SpamKeywords).
/// If none are provided, the rule uses an empty list (no fallback defaults).
/// </summary>
public class KeywordBlacklistRule : ISpamRule
{
    public string RuleName => "KeywordBlacklist";
    public double Severity => 0.65;

    private readonly string[] _spamKeywords;

    public KeywordBlacklistRule(IOptions<SpamGuardOptions> options)
    {
        // Use configured keywords or an empty array when not provided.
        _spamKeywords = options?.Value?.SpamKeywords ?? Array.Empty<string>();
    }

    public Task<bool> IsSpamAsync(SpamCheckContext context, CancellationToken cancellationToken = default)
    {
        var textFields = context.FormData.Values
            .Where(v => !string.IsNullOrWhiteSpace(v))
            .Select(v => v.ToLowerInvariant());

        var loweredKeywords = _spamKeywords
            .Where(k => !string.IsNullOrWhiteSpace(k))
            .Select(k => k.ToLowerInvariant())
            .ToArray();

        foreach (var text in textFields)
        {
            foreach (var keyword in loweredKeywords)
            {
                if (text.Contains(keyword))
                {
                    return Task.FromResult(true);
                }
            }
        }

        return Task.FromResult(false);
    }
}
