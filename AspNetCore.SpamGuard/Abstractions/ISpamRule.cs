using AspNetCore.SpamGuard.Models;

namespace AspNetCore.SpamGuard.Abstractions;

/// <summary>
/// Base interface for spam detection rules.
/// Implement this interface to create custom spam detection rules.
/// </summary>
public interface ISpamRule
{
    /// <summary>
    /// Gets the unique name of this rule.
    /// </summary>
    string RuleName { get; }

    /// <summary>
    /// Evaluates the context against this rule.
    /// </summary>
    /// <param name="context">The spam check context.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>
    /// A task that returns true if the submission is spam according to this rule, false otherwise.
    /// </returns>
    Task<bool> IsSpamAsync(SpamCheckContext context, CancellationToken cancellationToken = default);

    /// <summary>
    /// Gets the severity/confidence score of this rule (0-1).
    /// Higher values indicate stronger signals of spam.
    /// </summary>
    double Severity { get; }
}
