using AspNetCore.SpamGuard.Abstractions;
using AspNetCore.SpamGuard.Models;

namespace AspNetCore.SpamGuard.Web.CustomSpamRules
{
    /// <summary>
    /// Example: Detects excessive capitalization (SCREAMING).
    /// </summary>
    public class ExcessiveCapsRule : ISpamRule
    {
        public string RuleName => "ExcessiveCaps";
        public double Severity => 0.4;

        public Task<bool> IsSpamAsync(SpamCheckContext context, CancellationToken cancellationToken = default)
        {
            if (!context.FormData.TryGetValue("message", out var message) || string.IsNullOrWhiteSpace(message))
            {
                return Task.FromResult(false);
            }

            var letters = message.Where(char.IsLetter).ToList();
            if (letters.Count < 10) // Too short to judge
            {
                return Task.FromResult(false);
            }

            var upperCount = letters.Count(char.IsUpper);
            var upperRatio = (double)upperCount / letters.Count;

            // More than 70% uppercase is suspicious
            return Task.FromResult(upperRatio > 0.7);
        }
    }
}
