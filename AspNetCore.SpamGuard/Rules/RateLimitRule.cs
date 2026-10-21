using AspNetCore.SpamGuard.Abstractions;
using AspNetCore.SpamGuard.Models;
using Microsoft.Extensions.Caching.Memory;
using Microsoft.Extensions.Options;

namespace AspNetCore.SpamGuard.Rules;

/// <summary>
/// Detects spam by rate limiting submissions from the same IP address (sliding window, per process).
/// </summary>
/// <remarks>
/// State lives in <see cref="IMemoryCache"/>, so limits are per application instance. Make sure
/// <c>UseForwardedHeaders</c> is configured when running behind a proxy, otherwise all clients share the proxy IP.
/// </remarks>
public class RateLimitRule : ISpamRule
{
    private const string CacheKeyPrefix = "SpamGuard_RateLimit_";
    private static readonly object[] CreationLocks = Enumerable.Range(0, 64).Select(_ => new object()).ToArray();

    private readonly IMemoryCache _cache;
    private readonly SpamGuardOptions _options;
    private readonly TimeProvider _timeProvider;

    public string RuleName => SpamRuleNames.RateLimit;
    public double Severity => 0.75;

    public RateLimitRule(IMemoryCache cache, IOptions<SpamGuardOptions> options, TimeProvider timeProvider)
    {
        _cache = cache;
        _options = options.Value;
        _timeProvider = timeProvider;
    }

    public Task<bool> IsSpamAsync(SpamCheckContext context, CancellationToken cancellationToken = default)
    {
        if (!_options.EnableRateLimit || string.IsNullOrWhiteSpace(context.IpAddress))
        {
            return Task.FromResult(false);
        }

        var window = TimeSpan.FromMinutes(_options.RateLimitWindowMinutes);
        var bucket = GetBucket(CacheKeyPrefix + IpAddressHelper.GetClientKey(context.IpAddress), window);
        var now = _timeProvider.GetUtcNow();
        var windowStart = now - window;

        lock (bucket)
        {
            while (bucket.Count > 0 && bucket.Peek() <= windowStart)
            {
                bucket.Dequeue();
            }

            if (bucket.Count >= _options.RateLimitMaxSubmissions)
            {
                return Task.FromResult(true);
            }

            bucket.Enqueue(now);
            return Task.FromResult(false);
        }
    }

    private Queue<DateTimeOffset> GetBucket(string key, TimeSpan window)
    {
        if (_cache.TryGetValue(key, out Queue<DateTimeOffset>? existing) && existing is not null)
        {
            return existing;
        }

        // IMemoryCache.GetOrCreate is not atomic; serialize creation so concurrent requests share one bucket.
        var creationLock = CreationLocks[(key.GetHashCode() & int.MaxValue) % CreationLocks.Length];
        lock (creationLock)
        {
            return _cache.GetOrCreate(key, entry =>
            {
                entry.SlidingExpiration = window;
                entry.Size = 1;
                return new Queue<DateTimeOffset>();
            })!;
        }
    }
}
