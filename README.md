# Our.AspNetCore.SpamGuard

[![NuGet](https://img.shields.io/nuget/v/Our.AspNetCore.SpamGuard.svg)](https://www.nuget.org/packages/Our.AspNetCore.SpamGuard/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

SpamGuard protects ASP.NET Core forms from spam by combining several checks: honeypot fields, a signed timing token, Google reCAPTCHA v3, gibberish detection, keyword and email heuristics, per-IP rate limiting, and an optional StopForumSpam lookup. Each rule produces a signal, and the signals are combined into one confidence score.

## Features

- **Honeypot field.** Catches bots that fill in every input.
- **Signed timing token.** The form's render time is protected with ASP.NET Core Data Protection, so a client cannot forge it.
- **Google reCAPTCHA v3.** Checks the score, and optionally the expected action and allowed hostnames.
- **Random text detection.** Flags gibberish such as `MruwAXBlxLlfnUjjZooNVL`. It is Unicode-aware and protected against ReDoS.
- **Keyword blacklist.** Matches whole words only, case-insensitively.
- **Suspicious email patterns.** Flags disposable domains, `+spam` tags and dotted local parts.
- **Thread-safe per-IP rate limiting.**
- **StopForumSpam lookup (opt-in).** Checks the client IP and an MD5 hash of the email, with caching. If the service is unavailable, the check passes.
- **`<spam-guard-fields />` tag helper and `HttpContext` helpers.** Wire up a form in a few lines.
- **Extensible.** Add your own rules, or disable any built-in rule by name.
- **Startup validation.** Configuration errors are reported when the app starts, not on the first submission.

## Installation

```bash
dotnet add package Our.AspNetCore.SpamGuard
```

Requires .NET 10.

## Quick start

### 1. Register services

```csharp
using AspNetCore.SpamGuard;

builder.Services
    .AddSpamGuard(builder.Configuration.GetSection("SpamGuard")) // or .AddSpamGuard() to bind "SpamGuard" automatically
    .AddSpamRule<MyCustomRule>();                                // optional
```

There are three overloads:

| Overload | Behavior |
|---|---|
| `AddSpamGuard()` | Binds the `SpamGuard` configuration section. |
| `AddSpamGuard(IConfiguration section, Action<SpamGuardOptions>? configure = null)` | Binds the section you pass, then applies the optional delegate. |
| `AddSpamGuard(Action<SpamGuardOptions> configure)` | Code-only configuration; nothing is bound from configuration. |

Calling `AddSpamGuard` more than once is safe; the built-in rules are not registered twice.

### 2. Add the fields to your form (Razor)

In `_ViewImports.cshtml`:

```cshtml
@addTagHelper *, AspNetCore.SpamGuard
```

In the form:

```cshtml
<form method="post" asp-action="Contact">
    <input name="name" />
    <input name="email" type="email" />
    <textarea name="message"></textarea>

    <!-- Renders an off-screen honeypot and a signed render-time token -->
    <spam-guard-fields />

    <button type="submit">Send</button>
</form>
```

The tag helper accepts these attributes:

| Attribute | Default | Description |
|---|---|---|
| `include-honeypot` | `true` | Renders the honeypot input (`HoneypotFieldName`). |
| `include-form-token` | `true` | Renders the signed timestamp (`FormTokenFieldName`). |
| `include-recaptcha` | `false` | Renders an empty hidden input (`RecaptchaTokenFieldName`) for your reCAPTCHA script to fill. |
| `honeypot-label` | `Leave this field empty` | Label text read by screen readers. |

### 3. Check the submission

**Classic form post:**

```csharp
using AspNetCore.SpamGuard;
using AspNetCore.SpamGuard.Abstractions;

[HttpPost, ValidateAntiForgeryToken]
public async Task<IActionResult> Contact([FromServices] ISpamGuard spamGuard)
{
    var context = await HttpContext.CreateSpamCheckContextAsync(HttpContext.RequestAborted);
    var result = await spamGuard.CheckAsync(context, HttpContext.RequestAborted);

    if (result.IsSpam)
    {
        _logger.LogWarning("Spam blocked ({Score:F2}): {Rules}", result.ConfidenceScore, string.Join(", ", result.TriggeredRules));
    }

    // Show the same response either way, so bots cannot learn which submissions were blocked.
    return RedirectToAction("ThankYou");
}
```

`CreateSpamCheckContextAsync` reads every form field into `FormData`. It reads the honeypot, reCAPTCHA token, form token and `formRenderedAt` fields using their configured names, and ignores `__RequestVerificationToken`. It also fills in the client IP, user agent and submission time.

**JSON API:** post the hidden `__SpamGuardToken` value along with your model, then:

```csharp
var context = HttpContext.CreateSpamCheckContext(
    new Dictionary<string, string?>
    {
        ["name"] = model.Name,
        ["email"] = model.Email,
        ["message"] = model.Message
    },
    recaptchaToken: model.RecaptchaToken,
    honeypotValue: model.Website,
    formToken: model.FormToken);

var result = await spamGuard.CheckAsync(context, HttpContext.RequestAborted);
```

You can still build `SpamCheckContext` by hand. `FormData` keys are matched case-insensitively.

## How scoring works

Every rule that triggers adds its `Severity` (a value from 0 to 1) to a combined score using noisy-OR:

```
score = 1 - (1 - s1) * (1 - s2) * ... * (1 - sn)
```

The submission is spam when `score >= SpamConfidenceThreshold` (0.7 by default).

- The score never goes above 1.
- Each extra signal raises the score.
- With the default threshold:
  - These rules flag a submission on their own: Honeypot, SpamDatabase, RandomText, Recaptcha, RateLimit and Timing.
  - These rules need another signal before the submission is flagged: KeywordBlacklist and SuspiciousEmail. For example, two 0.6 signals give a score of 0.84.

`SpamCheckResult` contains:

| Property | Contents |
|---|---|
| `IsSpam` | Whether the score reached the threshold. |
| `ConfidenceScore` | The combined score. |
| `TriggeredRules` | Names of the rules that triggered. |
| `FailedRules` | Rules that threw an exception. These count as not triggered and are logged. |
| `Messages` | Human-readable notes. |

## Built-in rules

| Rule (`SpamRuleNames`) | Severity | Triggers when |
|---|---|---|
| `Honeypot` | 0.95 | The honeypot field has a value. |
| `SpamDatabase` | 0.90 | **Opt-in.** StopForumSpam lists the client IP or email hash with confidence ≥ `SpamDatabase.MinConfidence`. |
| `RandomText` | 0.85 | Checked fields look like gibberish. Latin-only heuristics are skipped for non-Latin scripts. |
| `Recaptcha` | 0.80 | Verification fails, the score is below `RecaptchaMinScore`, or the action or hostname doesn't match. |
| `RateLimit` | 0.75 | More than `RateLimitMaxSubmissions` from one IP within the window. |
| `Timing` | 0.70 | Submitted faster than `MinFormFillTimeSeconds`, or the form token is invalid. |
| `KeywordBlacklist` | 0.65 | A configured keyword appears as a whole word. |
| `SuspiciousEmail` | 0.60 | Disposable domain, `+spam@`, 4 or more dot-separated local-part segments, or longer than 320 characters. |

To disable a rule without removing it:

```json
"SpamGuard": { "DisabledRules": [ "KeywordBlacklist" ] }
```

### reCAPTCHA

- If `RecaptchaSecretKey` is not set, the rule is skipped. This is allowed only when `RequireRecaptcha` is `false`; otherwise startup fails.
- If the token is missing, the submission counts as spam only when `RequireRecaptcha` is `true`.
- Set `RecaptchaExpectedAction` (for example `"submit"`) and `RecaptchaAllowedHostnames` to stop tokens issued for another page or site from being reused.
- `RecaptchaSiteKey` is provided so your views can read it from options instead of hard-coding it.
- Store the secret in user-secrets, environment variables or Key Vault, never in `appsettings.json`.

### Timing and the signed form token

`<spam-guard-fields />` (or `ISpamGuardFormTokenService.GenerateToken()`) issues a token containing the server time when the form was rendered, protected with Data Protection.

- An invalid or tampered token counts as spam.
- Set `RequireFormToken: true` to also treat a missing token as spam. This is recommended once all your forms render the token.
- Without a token, the rule falls back to the client-supplied `FormRenderedAt` value, which a client can forge.
- `FlagStaleSubmissions: true` also flags forms submitted later than `MaxFormFillTimeSeconds` after rendering.

> **Multiple servers or containers:** Data Protection keys must be shared, for example with `PersistKeysToAzureBlobStorage`, `PersistKeysToStackExchangeRedis` or a shared file system. Otherwise a token issued by one instance fails validation on another, and that submission is flagged.

### Rate limiting and client IPs

The rate limiter keeps per-client counts in `IMemoryCache`, so each app instance counts separately. IPv4 clients are counted per address, and IPv6 clients per /64 prefix, because one host usually controls a whole /64. Behind a reverse proxy or load balancer, configure forwarded headers so SpamGuard sees the real client IP:

```csharp
builder.Services.Configure<ForwardedHeadersOptions>(o =>
{
    o.ForwardedHeaders = ForwardedHeaders.XForwardedFor | ForwardedHeaders.XForwardedProto;
    // o.KnownProxies.Add(IPAddress.Parse("10.0.0.1"));
});
app.UseForwardedHeaders();
```

### StopForumSpam (`SpamDatabase`)

This check is disabled by default because it sends data to a third party:

- the client IP, but only if it is public (private, loopback and link-local addresses are never sent);
- the MD5 hash of the lowercased email (never the raw address).

```json
"SpamGuard": {
  "SpamDatabase": {
    "Enabled": true,
    "MinConfidence": 50,
    "CheckIp": true,
    "CheckEmail": true,
    "CacheMinutes": 60,
    "TimeoutSeconds": 3
  }
}
```

If the service is slow or unavailable, the check passes (it fails open). Mention this lookup in your privacy policy.

## Configuration reference

```json
{
  "SpamGuard": {
    "SpamConfidenceThreshold": 0.7,

    "RecaptchaSecretKey": "",
    "RecaptchaSiteKey": "",
    "RecaptchaMinScore": 0.5,
    "RequireRecaptcha": true,
    "RecaptchaExpectedAction": null,
    "RecaptchaAllowedHostnames": null,

    "MinFormFillTimeSeconds": 2,
    "MaxFormFillTimeSeconds": 3600,
    "FlagStaleSubmissions": false,
    "RequireFormToken": false,

    "RandomTextCheckFields": null,
    "RandomTextThreshold": 1,
    "RandomTextMaxInputLength": 2000,

    "EnableRateLimit": true,
    "RateLimitWindowMinutes": 10,
    "RateLimitMaxSubmissions": 3,

    "SpamKeywords": null,
    "DisabledRules": null,

    "HoneypotFieldName": "website",
    "FormTokenFieldName": "__SpamGuardToken",
    "RecaptchaTokenFieldName": "recaptchaToken",
    "FormRenderedAtFieldName": "formRenderedAt",
    "EmailFieldName": "email",

    "SpamDatabase": { "Enabled": false }
  }
}
```

Notes on the defaults:

- When `RandomTextCheckFields` is null, the rule checks `name`, `message`, `subject` and `comment`.
- Lists default to `null`, so configured values replace the defaults instead of being appended to them.
- `RequireRecaptcha` defaults to `true`, so you must either set `RecaptchaSecretKey` or set `RequireRecaptcha` to `false`. Invalid settings throw an `OptionsValidationException` at startup.

## Custom rules

```csharp
public sealed class ExcessiveCapsRule : ISpamRule
{
    public string RuleName => "ExcessiveCaps";
    public double Severity => 0.4;

    public Task<bool> IsSpamAsync(SpamCheckContext context, CancellationToken cancellationToken = default)
    {
        if (!context.FormData.TryGetValue("message", out var message) || message.Length < 10)
            return Task.FromResult(false);

        var letters = message.Where(char.IsLetter).ToArray();
        return Task.FromResult(letters.Length >= 10 && letters.Count(char.IsUpper) > letters.Length * 0.7);
    }
}

builder.Services.AddSpamGuard().AddSpamRule<ExcessiveCapsRule>();
```

Rules are scoped services, so they can inject `DbContext`, `HttpClient` (via `IHttpClientFactory`) and so on. A rule that throws is reported in `FailedRules` and does not count toward the score.

## Best practices

- **Don't reveal detection.** Return the same response for spam and legitimate submissions.
- **Log scores, not PII.** Log the triggered rules and score, then tune `SpamConfidenceThreshold` and severities from real data.
- **Enable `RequireFormToken`** once every form renders `<spam-guard-fields />`.
- **Keep secrets out of source control.** Use user-secrets locally and a secret store in production.

## Upgrading from 1.x

Version 2.0 contains breaking changes:

1. **Scoring is noisy-OR.** 1.x averaged the triggered severities, so adding a weak signal could lower the score; for example, Honeypot (0.95) plus SuspiciousEmail (0.6) averaged to 0.775. Re-check `SpamConfidenceThreshold` if you tuned it.
2. **`AddSpamGuard(...)` returns `ISpamGuardBuilder`** instead of `IServiceCollection`.
   - `.AddSpamRule<T>()` still chains.
   - Other `IServiceCollection` calls need `builder.Services`.
   - New overloads bind configuration directly.
3. **Options are validated at startup.** `RequireRecaptcha = true` (the default) with no `RecaptchaSecretKey` now fails at startup. Previously the reCAPTCHA check threw on every request, and the error was swallowed, so reCAPTCHA was silently skipped.
4. **`SpamDatabaseRule` is now a real StopForumSpam integration** and is **disabled by default**. The 1.x rule called a placeholder URL (`api.spamcheck.example`) on every submission.
5. **List options default to `null`.**
   - Configured arrays now replace the built-in defaults instead of being appended to them.
   - `SpamKeywords` no longer has built-in words.
6. **Keyword matching uses whole words** ("sex" no longer matches "Essex").
7. **`SuspiciousEmailRule` no longer flags numeric local parts** such as `12345@gmail.com`.
8. **Rule exceptions** are listed in `SpamCheckResult.FailedRules`, and exception messages are no longer returned in `Messages`.
9. **`ISpamGuard` and `ISpamRule` live in `AspNetCore.SpamGuard.Abstractions`.**
10. **The package uses the shared framework** (`Microsoft.AspNetCore.App`) instead of the deprecated `Microsoft.AspNetCore.Http.Abstractions` 2.x package.

## Demo

`AspNetCore.SpamGuard.Web` is a sample app with a JSON contact form at `/Home/Contact`. It runs without reCAPTCHA by default. In Development, the API response includes diagnostics showing the score and the triggered rules.

## Contributing

1. Fork the repository and create a feature branch.
2. Add tests in `AspNetCore.SpamGuard.Tests` and run `dotnet test`.
3. Open a pull request.

## License

MIT
