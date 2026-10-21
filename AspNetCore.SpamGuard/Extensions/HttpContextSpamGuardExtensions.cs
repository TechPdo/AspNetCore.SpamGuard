using System.Globalization;
using AspNetCore.SpamGuard.Models;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;

namespace AspNetCore.SpamGuard;

/// <summary>
/// Helpers for building a <see cref="SpamCheckContext"/> from the current request.
/// </summary>
public static class HttpContextSpamGuardExtensions
{
    private const string AntiforgeryFieldName = "__RequestVerificationToken";

    /// <summary>
    /// Builds a <see cref="SpamCheckContext"/> from a form post (<c>application/x-www-form-urlencoded</c> or
    /// <c>multipart/form-data</c>). The honeypot, reCAPTCHA, form-token and rendered-at fields are read using the
    /// names configured in <see cref="SpamGuardOptions"/>; all other fields go to <see cref="SpamCheckContext.FormData"/>.
    /// </summary>
    public static async Task<SpamCheckContext> CreateSpamCheckContextAsync(
        this HttpContext httpContext,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(httpContext);

        var options = GetOptions(httpContext);
        var formData = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        string? honeypot = null, recaptcha = null, token = null;
        long? renderedAt = null;

        if (httpContext.Request.HasFormContentType)
        {
            var form = await httpContext.Request.ReadFormAsync(cancellationToken).ConfigureAwait(false);
            foreach (var (key, value) in form)
            {
                var text = value.ToString();
                if (Is(key, options.HoneypotFieldName)) honeypot = text;
                else if (Is(key, options.RecaptchaTokenFieldName)) recaptcha = text;
                else if (Is(key, options.FormTokenFieldName)) token = text;
                else if (Is(key, options.FormRenderedAtFieldName)) renderedAt = ParseLong(text);
                else if (!Is(key, AntiforgeryFieldName)) formData[key] = text;
            }
        }

        return Build(httpContext, formData, recaptcha, honeypot, token, renderedAt);
    }

    /// <summary>
    /// Builds a <see cref="SpamCheckContext"/> for JSON APIs or bound models, filling in the client IP,
    /// user agent and submission time from the request.
    /// </summary>
    public static SpamCheckContext CreateSpamCheckContext(
        this HttpContext httpContext,
        IEnumerable<KeyValuePair<string, string?>> formData,
        string? recaptchaToken = null,
        string? honeypotValue = null,
        string? formToken = null,
        long? formRenderedAt = null)
    {
        ArgumentNullException.ThrowIfNull(httpContext);
        ArgumentNullException.ThrowIfNull(formData);

        var data = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        foreach (var (key, value) in formData)
        {
            data[key] = value ?? string.Empty;
        }

        return Build(httpContext, data, recaptchaToken, honeypotValue, formToken, formRenderedAt);
    }

    private static SpamCheckContext Build(
        HttpContext httpContext,
        Dictionary<string, string> formData,
        string? recaptchaToken,
        string? honeypotValue,
        string? formToken,
        long? formRenderedAt)
    {
        var timeProvider = httpContext.RequestServices.GetService<TimeProvider>() ?? TimeProvider.System;

        return new SpamCheckContext
        {
            FormData = formData,
            RecaptchaToken = recaptchaToken,
            HoneypotValue = honeypotValue,
            FormToken = formToken,
            FormRenderedAt = formRenderedAt is > 0 ? formRenderedAt : null,
            FormSubmittedAt = timeProvider.GetUtcNow().ToUnixTimeMilliseconds(),
            IpAddress = IpAddressHelper.Normalize(httpContext.Connection.RemoteIpAddress),
            UserAgent = httpContext.Request.Headers.UserAgent.ToString()
        };
    }

    private static SpamGuardOptions GetOptions(HttpContext httpContext) =>
        httpContext.RequestServices.GetRequiredService<IOptions<SpamGuardOptions>>().Value;

    private static bool Is(string key, string? name) =>
        !string.IsNullOrEmpty(name) && string.Equals(key, name, StringComparison.OrdinalIgnoreCase);

    private static long? ParseLong(string value) =>
        long.TryParse(value, NumberStyles.Integer, CultureInfo.InvariantCulture, out var result) ? result : null;
}
