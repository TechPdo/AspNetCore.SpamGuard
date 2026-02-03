using AspNetCore.SpamGuard.Abstractions;
using AspNetCore.SpamGuard.Models;
using Microsoft.Extensions.Caching.Memory;
using Microsoft.Extensions.Options;

namespace AspNetCore.SpamGuard.Rules;

/// <summary>
/// Detects spam by rate limiting submissions from the same IP address.
/// </summary>
public class RateLimitRule : ISpamRule
{
    private readonly IMemoryCache _cache;
    private readonly SpamGuardOptions _options;
    private const string CacheKeyPrefix = "SpamGuard_RateLimit_";

    public string RuleName => "RateLimit";
    public double Severity => 0.75;

    public RateLimitRule(IMemoryCache cache, IOptions<SpamGuardOptions> options)
    {
        _cache = cache;
        _options = options.Value;
    }

    public Task<bool> IsSpamAsync(SpamCheckContext context, CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrWhiteSpace(context.IpAddress) || !_options.EnableRateLimit)
        {
            return Task.FromResult(false);
        }

        var cacheKey = $"{CacheKeyPrefix}{context.IpAddress}";
        var now = DateTimeOffset.UtcNow;

        // Get or create submission history for this IP
        var submissions = _cache.GetOrCreate(cacheKey, entry =>
        {
            entry.AbsoluteExpirationRelativeToNow = TimeSpan.FromMinutes(_options.RateLimitWindowMinutes);
            return new List<DateTimeOffset>();
        }) ?? new List<DateTimeOffset>();

        // Remove old submissions outside the time window
        var windowStart = now.AddMinutes(-_options.RateLimitWindowMinutes);
        submissions.RemoveAll(s => s < windowStart);

        // Check if limit exceeded
        if (submissions.Count >= _options.RateLimitMaxSubmissions)
        {
            return Task.FromResult(true);
        }

        // Add current submission
        submissions.Add(now);
        _cache.Set(cacheKey, submissions, TimeSpan.FromMinutes(_options.RateLimitWindowMinutes));

        return Task.FromResult(false);
    }
}
