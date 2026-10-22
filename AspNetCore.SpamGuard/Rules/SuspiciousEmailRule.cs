using System.Text.RegularExpressions;
using AspNetCore.SpamGuard.Abstractions;
using AspNetCore.SpamGuard.Models;
using Microsoft.Extensions.Options;

namespace AspNetCore.SpamGuard.Rules;

/// <summary>
/// Detects email patterns commonly used by spammers (disposable domains, dotted-out local parts, "+spam" tags).
/// </summary>
public class SuspiciousEmailRule : ISpamRule
{
    private static readonly TimeSpan MatchTimeout = TimeSpan.FromMilliseconds(100);
    private const RegexOptions Options = RegexOptions.IgnoreCase | RegexOptions.CultureInvariant | RegexOptions.Compiled;

    private static readonly Regex[] SuspiciousPatterns =
    {
        // Many dots in the local part: a.b.c.d@example.com
        new(@"^[^@.]+(?:\.[^@.]+){3,}@", Options, MatchTimeout),
        // Well-known disposable email providers
        new(@"@(?:[\w-]+\.)*(?:tempmail|temp-mail|throwaway|guerrillamail|guerrilla|mailinator|10minutemail|yopmail|trashmail|sharklasers|dispostable|maildrop|getnada|fakeinbox)\.", Options, MatchTimeout),
        // Explicit +spam tag
        new(@"\+spam@", Options, MatchTimeout),
    };

    private readonly string _emailFieldName;

    public string RuleName => SpamRuleNames.SuspiciousEmail;
    public double Severity => 0.6;

    public SuspiciousEmailRule(IOptions<SpamGuardOptions> options)
    {
        _emailFieldName = options.Value.EmailFieldName;
    }

    public Task<bool> IsSpamAsync(SpamCheckContext context, CancellationToken cancellationToken = default)
    {
        if (!context.FormData.TryGetValue(_emailFieldName, out var email) || string.IsNullOrWhiteSpace(email))
        {
            return Task.FromResult(false);
        }

        email = email.Trim();
        if (email.Length > 320)
        {
            return Task.FromResult(true); // longer than any valid address
        }

        foreach (var pattern in SuspiciousPatterns)
        {
            if (pattern.IsMatch(email))
            {
                return Task.FromResult(true);
            }
        }

        return Task.FromResult(false);
    }
}
