
using AspNetCore.SpamGuard.Abstractions;
using AspNetCore.SpamGuard.Models;

namespace AspNetCore.SpamGuard.Rules;

/// <summary>
/// Example: Integration with an external spam database API.
/// </summary>
public class SpamDatabaseRule : ISpamRule
{
    private readonly HttpClient _httpClient;
    private const string ApiUrl = "https://api.spamcheck.example/check";

    public string RuleName => "SpamDatabase";
    public double Severity => 0.9;

    public SpamDatabaseRule(HttpClient httpClient)
    {
        _httpClient = httpClient;
    }

    public async Task<bool> IsSpamAsync(SpamCheckContext context, CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrWhiteSpace(context.IpAddress))
        {
            return false;
        }

        try
        {
            // Call external API to check if IP is in spam database
            var response = await _httpClient.GetAsync(
                $"{ApiUrl}?ip={context.IpAddress}",
                cancellationToken
            );

            if (response.IsSuccessStatusCode)
            {
                var result = await response.Content.ReadAsStringAsync(cancellationToken);
                // Parse response and return true if IP is flagged
                // This is a simplified example
                return result.Contains("\"spam\":true");
            }
        }
        catch
        {
            // Don't fail the entire spam check if external API is down
            return false;
        }

        return false;
    }
}
