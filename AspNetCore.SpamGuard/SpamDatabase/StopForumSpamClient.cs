using System.Globalization;
using System.Net.Http.Json;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json.Serialization;
using Microsoft.Extensions.Caching.Memory;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace AspNetCore.SpamGuard.SpamDatabase;

/// <summary>
/// Default <see cref="IStopForumSpamClient"/> with in-memory result caching.
/// </summary>
internal sealed class StopForumSpamClient : IStopForumSpamClient
{
    private const string CacheKeyPrefix = "SpamGuard_SFS_";

    private readonly HttpClient _httpClient;
    private readonly IMemoryCache _cache;
    private readonly SpamDatabaseOptions _options;
    private readonly ILogger<StopForumSpamClient> _logger;

    public StopForumSpamClient(
        HttpClient httpClient,
        IMemoryCache cache,
        IOptions<SpamGuardOptions> options,
        ILogger<StopForumSpamClient> logger)
    {
        _httpClient = httpClient;
        _cache = cache;
        _options = options.Value.SpamDatabase;
        _logger = logger;
    }

    public async Task<StopForumSpamResult> LookupAsync(string? ipAddress, string? email, CancellationToken cancellationToken = default)
    {
        var emailHash = string.IsNullOrWhiteSpace(email) ? null : HashEmail(email);
        if (string.IsNullOrWhiteSpace(ipAddress) && emailHash is null)
        {
            return StopForumSpamResult.Failed;
        }

        var cacheKey = $"{CacheKeyPrefix}{ipAddress}|{emailHash}";
        if (_options.CacheMinutes > 0 && _cache.TryGetValue(cacheKey, out StopForumSpamResult? cached) && cached is not null)
        {
            return cached;
        }

        var query = new StringBuilder("json");
        if (!string.IsNullOrWhiteSpace(ipAddress))
        {
            query.Append("&ip=").Append(Uri.EscapeDataString(ipAddress));
        }
        if (emailHash is not null)
        {
            query.Append("&emailhash=").Append(emailHash);
        }

        var url = $"{_options.BaseUrl.TrimEnd('?')}?{query}";

        StopForumSpamResponse? response;
        try
        {
            using var httpResponse = await _httpClient.GetAsync(url, cancellationToken).ConfigureAwait(false);
            if (!httpResponse.IsSuccessStatusCode)
            {
                _logger.LogWarning("StopForumSpam lookup failed with HTTP {StatusCode}.", (int)httpResponse.StatusCode);
                return StopForumSpamResult.Failed;
            }

            response = await httpResponse.Content.ReadFromJsonAsync<StopForumSpamResponse>(cancellationToken).ConfigureAwait(false);
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            throw;
        }
        catch (Exception ex)
        {
            // Fail open: an unavailable reputation service must not block legitimate users.
            _logger.LogWarning(ex, "StopForumSpam lookup failed.");
            return StopForumSpamResult.Failed;
        }

        if (response is null || response.Success != 1)
        {
            _logger.LogWarning("StopForumSpam lookup returned an error: {Error}", response?.Error ?? "empty response");
            return StopForumSpamResult.Failed;
        }

        var result = new StopForumSpamResult(
            Success: true,
            IpAppears: response.Ip?.Appears > 0,
            IpConfidence: response.Ip?.Confidence ?? 0,
            EmailAppears: response.EmailHash?.Appears > 0,
            EmailConfidence: response.EmailHash?.Confidence ?? 0);

        if (_options.CacheMinutes > 0)
        {
            _cache.Set(cacheKey, result, new MemoryCacheEntryOptions
            {
                AbsoluteExpirationRelativeToNow = TimeSpan.FromMinutes(_options.CacheMinutes),
                Size = 1
            });
        }

        return result;
    }

    internal static string HashEmail(string email)
    {
        // StopForumSpam's documented emailhash parameter is an MD5 of the email address.
#pragma warning disable CA5351
        var bytes = MD5.HashData(Encoding.UTF8.GetBytes(email.Trim().ToLowerInvariant()));
#pragma warning restore CA5351
        return Convert.ToHexString(bytes).ToLower(CultureInfo.InvariantCulture);
    }

    private sealed class StopForumSpamResponse
    {
        [JsonPropertyName("success")]
        public int Success { get; set; }

        [JsonPropertyName("error")]
        public string? Error { get; set; }

        [JsonPropertyName("ip")]
        public Entry? Ip { get; set; }

        [JsonPropertyName("emailhash")]
        public Entry? EmailHash { get; set; }
    }

    private sealed class Entry
    {
        [JsonPropertyName("appears")]
        public int Appears { get; set; }

        [JsonPropertyName("confidence")]
        public double? Confidence { get; set; }
    }
}
