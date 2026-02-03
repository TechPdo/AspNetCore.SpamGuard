using AspNetCore.SpamGuard.Models;

namespace AspNetCore.SpamGuard.Abstractions;

/// <summary>
/// Main service interface for spam detection.
/// </summary>
public interface ISpamGuard
{
    /// <summary>
    /// Evaluates form submission data against configured spam rules.
    /// </summary>
    /// <param name="context">The spam check context containing form data and metadata.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>Result indicating whether the submission is spam and which rules were triggered.</returns>
    Task<SpamCheckResult> CheckAsync(SpamCheckContext context, CancellationToken cancellationToken = default);
}
