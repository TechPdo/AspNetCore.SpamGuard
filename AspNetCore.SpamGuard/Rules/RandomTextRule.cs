using System.Text.RegularExpressions;
using AspNetCore.SpamGuard.Abstractions;
using AspNetCore.SpamGuard.Models;
using Microsoft.Extensions.Options;

namespace AspNetCore.SpamGuard.Rules;

/// <summary>
/// Detects spam by analyzing text patterns for random character sequences.
/// Example spam patterns: "MruwAXBlxLlfnUjjZooNVL", "VAZRauGhTcJWjswjx".
/// </summary>
/// <remarks>
/// Language-specific heuristics (vowel ratio, consonant runs, missing spaces) only apply to text
/// written predominantly in Latin script, to avoid flagging other languages.
/// </remarks>
public class RandomTextRule : ISpamRule
{
    private static readonly TimeSpan MatchTimeout = TimeSpan.FromMilliseconds(100);

    private static readonly Regex ConsecutiveConsonantsRegex =
        new(@"[bcdfghjklmnpqrstvwxz]{5,}", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant | RegexOptions.Compiled, MatchTimeout);

    private static readonly Regex ConsecutiveUpperLowerRegex =
        new(@"[A-Z][a-z][A-Z][a-z]", RegexOptions.CultureInvariant | RegexOptions.Compiled, MatchTimeout);

    // Bounded group length keeps backtracking linear-ish (the unbounded version was vulnerable to ReDoS).
    private static readonly Regex RepeatingPatternsRegex =
        new(@"(.{2,20})\1{2,}", RegexOptions.CultureInvariant | RegexOptions.Compiled, MatchTimeout);

    private readonly SpamGuardOptions _options;

    public string RuleName => SpamRuleNames.RandomText;
    public double Severity => 0.85;

    public RandomTextRule(IOptions<SpamGuardOptions> options)
    {
        _options = options.Value;
    }

    public Task<bool> IsSpamAsync(SpamCheckContext context, CancellationToken cancellationToken = default)
    {
        IReadOnlyList<string> fieldsToCheck = _options.RandomTextCheckFields is { Length: > 0 } configured
            ? configured
            : SpamGuardOptions.DefaultRandomTextCheckFields;

        var suspiciousCount = 0;

        foreach (var fieldName in fieldsToCheck.Distinct(StringComparer.OrdinalIgnoreCase))
        {
            if (context.FormData.TryGetValue(fieldName, out var value) &&
                !string.IsNullOrWhiteSpace(value) &&
                IsRandomText(value))
            {
                suspiciousCount++;
            }
        }

        return Task.FromResult(suspiciousCount >= _options.RandomTextThreshold);
    }

    internal bool IsRandomText(string text)
    {
        text = text.Trim();
        if (text.Length > _options.RandomTextMaxInputLength)
        {
            text = text[.._options.RandomTextMaxInputLength];
        }

        if (text.Length < 5)
        {
            return false; // Too short to analyze
        }

        var letterCount = 0;
        var asciiLetterCount = 0;
        var vowelCount = 0;
        foreach (var c in text)
        {
            if (!char.IsLetter(c))
            {
                continue;
            }

            letterCount++;
            if (char.IsAsciiLetter(c))
            {
                asciiLetterCount++;
                if ("aeiouAEIOU".Contains(c))
                {
                    vowelCount++;
                }
            }
        }

        var isLatinText = letterCount > 0 && asciiLetterCount >= letterCount * 0.8;
        var points = 0;

        if (isLatinText)
        {
            // Check 1: Too many consecutive consonants (5+)
            if (SafeIsMatch(ConsecutiveConsonantsRegex, text))
            {
                points += 2;
            }

            // Check 2: Alternating upper/lower case (CamelCase spam pattern)
            if (SafeCount(ConsecutiveUpperLowerRegex, text) > text.Length / 10)
            {
                points += 2;
            }

            // Check 3: Very low vowel ratio
            var consonantCount = asciiLetterCount - vowelCount;
            if (consonantCount > 0 && (double)vowelCount / consonantCount < 0.2)
            {
                points += 2;
            }

            // Check 5: No spaces in long text (bots often generate continuous strings)
            if (text.Length > 15 && !text.Contains(' '))
            {
                points += 1;
            }
        }

        // Check 4: High character diversity (short texts are naturally diverse, so require some length)
        if (text.Length >= 12 && (double)text.Distinct().Count() / text.Length > 0.7)
        {
            points += 1;
        }

        // Check 6: Contains repeating patterns
        if (SafeIsMatch(RepeatingPatternsRegex, text))
        {
            points += 1;
        }

        return points >= 4;
    }

    private static bool SafeIsMatch(Regex regex, string input)
    {
        try
        {
            return regex.IsMatch(input);
        }
        catch (RegexMatchTimeoutException)
        {
            return false;
        }
    }

    private static int SafeCount(Regex regex, string input)
    {
        try
        {
            return regex.Count(input);
        }
        catch (RegexMatchTimeoutException)
        {
            return 0;
        }
    }
}
