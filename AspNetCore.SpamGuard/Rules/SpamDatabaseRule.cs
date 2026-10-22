using AspNetCore.SpamGuard.Abstractions;
using AspNetCore.SpamGuard.Models;
using AspNetCore.SpamGuard.SpamDatabase;
using Microsoft.Extensions.Options;

namespace AspNetCore.SpamGuard.Rules;

/// <summary>
/// Checks the client IP and email against the StopForumSpam reputation database.
/// Opt-in via <see cref="SpamDatabaseOptions.Enabled"/>. Private/loopback IPs are never sent, and
/// emails are sent as an MD5 hash. Lookup failures never flag a submission (fail-open).
/// </summary>
public class SpamDatabaseRule : ISpamRule
{
    private readonly IStopForumSpamClient _client;
    private readonly SpamGuardOptions _options;

    public string RuleName => SpamRuleNames.SpamDatabase;
    public double Severity => 0.9;

    public SpamDatabaseRule(IStopForumSpamClient client, IOptions<SpamGuardOptions> options)
    {
        _client = client;
        _options = options.Value;
    }

    public async Task<bool> IsSpamAsync(SpamCheckContext context, CancellationToken cancellationToken = default)
    {
        var db = _options.SpamDatabase;
        if (!db.Enabled)
        {
            return false;
        }

        var ip = db.CheckIp && IpAddressHelper.IsPublic(context.IpAddress) ? context.IpAddress : null;

        string? email = null;
        if (db.CheckEmail &&
            context.FormData.TryGetValue(_options.EmailFieldName, out var rawEmail) &&
            !string.IsNullOrWhiteSpace(rawEmail) &&
            rawEmail.Contains('@'))
        {
            email = rawEmail.Trim();
        }

        if (ip is null && email is null)
        {
            return false;
        }

        var result = await _client.LookupAsync(ip, email, cancellationToken).ConfigureAwait(false);
        if (!result.Success)
        {
            return false;
        }

        return (result.IpAppears && result.IpConfidence >= db.MinConfidence) ||
               (result.EmailAppears && result.EmailConfidence >= db.MinConfidence);
    }
}
