using System.Text.RegularExpressions;
using AspNetCore.SpamGuard.Abstractions;
using AspNetCore.SpamGuard.Models;
using Microsoft.Extensions.Options;

namespace AspNetCore.SpamGuard.Rules;

/// <summary>
/// Detects known spam keywords (whole-word, case-insensitive). Keywords come from
/// <see cref="SpamGuardOptions.SpamKeywords"/>; the rule does nothing when none are configured.
/// </summary>
public class KeywordBlacklistRule : ISpamRule
{
    private static readonly TimeSpan MatchTimeout = TimeSpan.FromMilliseconds(250);

    private readonly Regex? _keywordRegex;

    public string RuleName => SpamRuleNames.KeywordBlacklist;
    public double Severity => 0.65;

    public KeywordBlacklistRule(IOptions<SpamGuardOptions> options)
    {
        var keywords = (options.Value.SpamKeywords ?? Array.Empty<string>())
            .Where(k => !string.IsNullOrWhiteSpace(k))
            .Select(k => Regex.Escape(k.Trim()))
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToArray();

        if (keywords.Length > 0)
        {
            _keywordRegex = new Regex(
                $@"(?<!\w)(?:{string.Join("|", keywords)})(?!\w)",
                RegexOptions.IgnoreCase | RegexOptions.CultureInvariant,
                MatchTimeout);
        }
    }

    public Task<bool> IsSpamAsync(SpamCheckContext context, CancellationToken cancellationToken = default)
    {
        if (_keywordRegex is null)
        {
            return Task.FromResult(false);
        }

        foreach (var value in context.FormData.Values)
        {
            if (!string.IsNullOrWhiteSpace(value) && _keywordRegex.IsMatch(value))
            {
                return Task.FromResult(true);
            }
        }

        return Task.FromResult(false);
    }
}
