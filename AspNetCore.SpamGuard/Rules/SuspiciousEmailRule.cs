using AspNetCore.SpamGuard.Abstractions;
using AspNetCore.SpamGuard.Models;
using System.Text.RegularExpressions;

namespace AspNetCore.SpamGuard.Rules;

/// <summary>
/// Example: Detects suspicious email patterns commonly used by spammers.
/// </summary>
public class SuspiciousEmailRule : ISpamRule
{
    public string RuleName => "SuspiciousEmail";
    public double Severity => 0.6;

    // Common patterns in spam emails
    private static readonly string[] SuspiciousPatterns = new[]
    {
        @"^\w+\.\w+\.\w+\.\w+@",           // Multiple dots: a.b.c.d@gmail.com
        @"^\d+@",                           // Starts with numbers: 123456@gmail.com
        @"@(tempmail|throwaway|guerrilla)", // Disposable email services
        @"\+spam@",                         // Contains +spam
    };

    public Task<bool> IsSpamAsync(SpamCheckContext context, CancellationToken cancellationToken = default)
    {
        if (!context.FormData.TryGetValue("email", out var email) || string.IsNullOrWhiteSpace(email))
        {
            return Task.FromResult(false);
        }

        email = email.ToLower().Trim();

        // Check against suspicious patterns
        foreach (var pattern in SuspiciousPatterns)
        {
            if (Regex.IsMatch(email, pattern, RegexOptions.IgnoreCase))
            {
                return Task.FromResult(true);
            }
        }

        return Task.FromResult(false);
    }
}
