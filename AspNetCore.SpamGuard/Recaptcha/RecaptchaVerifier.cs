using System.Net.Http.Json;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace AspNetCore.SpamGuard.Recaptcha;

/// <summary>
/// Default implementation of reCAPTCHA v3 verification.
/// </summary>
internal sealed class RecaptchaVerifier : IRecaptchaVerifier
{
    private const string VerifyUrl = "https://www.google.com/recaptcha/api/siteverify";

    private readonly HttpClient _httpClient;
    private readonly SpamGuardOptions _options;
    private readonly ILogger<RecaptchaVerifier> _logger;

    public RecaptchaVerifier(HttpClient httpClient, IOptions<SpamGuardOptions> options, ILogger<RecaptchaVerifier> logger)
    {
        _httpClient = httpClient;
        _options = options.Value;
        _logger = logger;
    }

    public async Task<RecaptchaResponse> VerifyAsync(
        string token,
        string? remoteIp = null,
        CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrWhiteSpace(token))
        {
            return Failed("missing-input-response");
        }

        if (string.IsNullOrWhiteSpace(_options.RecaptchaSecretKey))
        {
            throw new InvalidOperationException(
                "reCAPTCHA secret key is not configured. Set RecaptchaSecretKey in SpamGuardOptions.");
        }

        var parameters = new Dictionary<string, string>
        {
            ["secret"] = _options.RecaptchaSecretKey,
            ["response"] = token
        };

        if (!string.IsNullOrWhiteSpace(remoteIp))
        {
            parameters["remoteip"] = remoteIp;
        }

        try
        {
            using var content = new FormUrlEncodedContent(parameters);
            using var response = await _httpClient.PostAsync(VerifyUrl, content, cancellationToken).ConfigureAwait(false);
            response.EnsureSuccessStatusCode();

            var result = await response.Content.ReadFromJsonAsync<RecaptchaResponse>(cancellationToken).ConfigureAwait(false);
            if (result is null)
            {
                return Failed("empty-response");
            }

            if (!result.Success)
            {
                _logger.LogDebug("reCAPTCHA verification failed: {ErrorCodes}", string.Join(", ", result.ErrorCodes ?? new()));
            }

            return result;
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            throw;
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "reCAPTCHA verification request failed.");
            return Failed("verification-request-failed");
        }
    }

    private static RecaptchaResponse Failed(string errorCode) =>
        new() { Success = false, Score = 0, ErrorCodes = new List<string> { errorCode } };
}
