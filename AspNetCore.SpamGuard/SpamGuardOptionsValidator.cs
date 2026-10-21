using Microsoft.Extensions.Options;

namespace AspNetCore.SpamGuard;

/// <summary>
/// Validates <see cref="SpamGuardOptions"/> at startup.
/// </summary>
internal sealed class SpamGuardOptionsValidator : IValidateOptions<SpamGuardOptions>
{
    public ValidateOptionsResult Validate(string? name, SpamGuardOptions options)
    {
        var errors = new List<string>();

        if (options.RequireRecaptcha && string.IsNullOrWhiteSpace(options.RecaptchaSecretKey))
        {
            errors.Add($"{nameof(SpamGuardOptions.RecaptchaSecretKey)} is required when {nameof(SpamGuardOptions.RequireRecaptcha)} is true. " +
                       $"Configure the secret key or set {nameof(SpamGuardOptions.RequireRecaptcha)} to false.");
        }

        if (options.RecaptchaMinScore is < 0 or > 1)
            errors.Add($"{nameof(SpamGuardOptions.RecaptchaMinScore)} must be between 0 and 1.");

        if (options.SpamConfidenceThreshold is <= 0 or > 1)
            errors.Add($"{nameof(SpamGuardOptions.SpamConfidenceThreshold)} must be greater than 0 and at most 1.");

        if (options.MinFormFillTimeSeconds < 0)
            errors.Add($"{nameof(SpamGuardOptions.MinFormFillTimeSeconds)} must not be negative.");

        if (options.MaxFormFillTimeSeconds <= options.MinFormFillTimeSeconds)
            errors.Add($"{nameof(SpamGuardOptions.MaxFormFillTimeSeconds)} must be greater than {nameof(SpamGuardOptions.MinFormFillTimeSeconds)}.");

        if (options.RateLimitWindowMinutes <= 0)
            errors.Add($"{nameof(SpamGuardOptions.RateLimitWindowMinutes)} must be greater than 0.");

        if (options.RateLimitMaxSubmissions <= 0)
            errors.Add($"{nameof(SpamGuardOptions.RateLimitMaxSubmissions)} must be greater than 0.");

        if (options.RandomTextThreshold < 1)
            errors.Add($"{nameof(SpamGuardOptions.RandomTextThreshold)} must be at least 1.");

        if (options.RandomTextMaxInputLength <= 0)
            errors.Add($"{nameof(SpamGuardOptions.RandomTextMaxInputLength)} must be greater than 0.");

        if (string.IsNullOrWhiteSpace(options.HoneypotFieldName))
            errors.Add($"{nameof(SpamGuardOptions.HoneypotFieldName)} must not be empty.");

        if (string.IsNullOrWhiteSpace(options.FormTokenFieldName))
            errors.Add($"{nameof(SpamGuardOptions.FormTokenFieldName)} must not be empty.");

        var db = options.SpamDatabase;
        if (db is null)
        {
            errors.Add($"{nameof(SpamGuardOptions.SpamDatabase)} must not be null.");
        }
        else if (db.Enabled)
        {
            if (!Uri.TryCreate(db.BaseUrl, UriKind.Absolute, out var uri) || uri.Scheme != Uri.UriSchemeHttps)
                errors.Add("SpamDatabase.BaseUrl must be an absolute https URL.");
            if (db.MinConfidence is < 0 or > 100)
                errors.Add("SpamDatabase.MinConfidence must be between 0 and 100.");
            if (db.TimeoutSeconds <= 0)
                errors.Add("SpamDatabase.TimeoutSeconds must be greater than 0.");
            if (db.CacheMinutes < 0)
                errors.Add("SpamDatabase.CacheMinutes must not be negative.");
            if (!db.CheckIp && !db.CheckEmail)
                errors.Add("SpamDatabase requires CheckIp and/or CheckEmail when enabled.");
        }

        return errors.Count == 0 ? ValidateOptionsResult.Success : ValidateOptionsResult.Fail(errors);
    }
}
