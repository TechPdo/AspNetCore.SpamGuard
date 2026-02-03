using System.Text.Json;
using Microsoft.Extensions.Options;

namespace AspNetCore.SpamGuard.Recaptcha;

/// <summary>
/// Default implementation of reCAPTCHA v3 verification.
/// </summary>
internal class RecaptchaVerifier : IRecaptchaVerifier
{
    private readonly HttpClient _httpClient;
    private readonly SpamGuardOptions _options;
    private const string VerifyUrl = "https://www.google.com/recaptcha/api/siteverify";

    public RecaptchaVerifier(HttpClient httpClient, IOptions<SpamGuardOptions> options)
    {
        _httpClient = httpClient;
        _options = options.Value;
    }

    public async Task<RecaptchaResponse> VerifyAsync(
        string token, 
        string? remoteIp = null, 
        CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrWhiteSpace(token))
        {
            return new RecaptchaResponse { Success = false, Score = 0 };
        }

        if (string.IsNullOrWhiteSpace(_options.RecaptchaSecretKey))
        {
            throw new InvalidOperationException(
                "reCAPTCHA secret key is not configured. Set RecaptchaSecretKey in SpamGuardOptions.");
        }

        var parameters = new Dictionary<string, string>
        {
            { "secret", _options.RecaptchaSecretKey },
            { "response", token }
        };

        if (!string.IsNullOrWhiteSpace(remoteIp))
        {
            parameters.Add("remoteip", remoteIp);
        }

        try
        {
            var response = await _httpClient.PostAsync(
                VerifyUrl,
                new FormUrlEncodedContent(parameters),
                cancellationToken);

            response.EnsureSuccessStatusCode();

            var json = await response.Content.ReadAsStringAsync(cancellationToken);
            var result = JsonSerializer.Deserialize<RecaptchaResponse>(json, new JsonSerializerOptions
            {
                PropertyNameCaseInsensitive = true
            });

            return result ?? new RecaptchaResponse { Success = false, Score = 0 };
        }
        catch (Exception)
        {
            // Log exception in production
            return new RecaptchaResponse { Success = false, Score = 0 };
        }
    }
}
