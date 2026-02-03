using AspNetCore.SpamGuard.Abstractions;
using AspNetCore.SpamGuard.Models;
using Microsoft.Extensions.Options;
using System.Text.RegularExpressions;

namespace AspNetCore.SpamGuard.Rules;

/// <summary>
/// Detects spam by analyzing text patterns for random character sequences.
/// Example spam patterns: "MruwAXBlxLlfnUjjZooNVL", "VAZRauGhTcJWjswjx"
/// </summary>
public class RandomTextRule : ISpamRule
{
    private readonly SpamGuardOptions _options;
    private static readonly Regex ConsecutiveConsonantsRegex = new(@"[bcdfghjklmnpqrstvwxyz]{5,}", RegexOptions.IgnoreCase | RegexOptions.Compiled);
    private static readonly Regex ConsecutiveUpperLowerRegex = new(@"[A-Z][a-z][A-Z][a-z]", RegexOptions.Compiled);
    private static readonly Regex RepeatingPatternsRegex = new(@"(.{2,})\1{2,}", RegexOptions.Compiled);

    public string RuleName => "RandomText";
    public double Severity => 0.85;

    public RandomTextRule(IOptions<SpamGuardOptions> options)
    {
        _options = options.Value;
    }

    public Task<bool> IsSpamAsync(SpamCheckContext context, CancellationToken cancellationToken = default)
    {
        var fieldsToCheck = _options.RandomTextCheckFields ?? new[] { "name", "message", "subject", "comment" };
        var suspiciousCount = 0;

        foreach (var fieldName in fieldsToCheck)
        {
            if (context.FormData.TryGetValue(fieldName, out var value) && !string.IsNullOrWhiteSpace(value))
            {
                if (IsRandomText(value))
                {
                    suspiciousCount++;
                }
            }
        }

        // If multiple fields contain random text, it's very likely spam
        return Task.FromResult(suspiciousCount >= _options.RandomTextThreshold);
    }

    private bool IsRandomText(string text)
    {
        if (text.Length < 5)
        {
            return false; // Too short to analyze
        }

        var points = 0;

        // Check 1: Too many consecutive consonants (5+)
        if (ConsecutiveConsonantsRegex.IsMatch(text))
        {
            points += 2;
        }

        // Check 2: Alternating upper/lower case (CamelCase spam pattern)
        var upperLowerMatches = ConsecutiveUpperLowerRegex.Matches(text);
        if (upperLowerMatches.Count > text.Length / 10)
        {
            points += 2;
        }

        // Check 3: Very low vowel ratio
        var vowelCount = text.Count(c => "aeiouAEIOU".Contains(c));
        var consonantCount = text.Count(c => char.IsLetter(c)) - vowelCount;
        if (consonantCount > 0)
        {
            var vowelRatio = (double)vowelCount / consonantCount;
            if (vowelRatio < 0.2) // Less than 20% vowels
            {
                points += 2;
            }
        }

        // Check 4: High character diversity (random chars have high entropy)
        var uniqueChars = text.Distinct().Count();
        var diversityRatio = (double)uniqueChars / text.Length;
        if (diversityRatio > 0.7) // More than 70% unique characters
        {
            points += 1;
        }

        // Check 5: No spaces in long text (bots often generate continuous strings)
        if (text.Length > 15 && !text.Contains(' '))
        {
            points += 1;
        }

        // Check 6: Contains repeating patterns
        if (RepeatingPatternsRegex.IsMatch(text))
        {
            points += 1;
        }

        // Threshold: 4+ points indicates random text
        return points >= 4;
    }
}
