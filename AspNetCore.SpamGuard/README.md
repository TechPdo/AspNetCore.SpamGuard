# AspNetCore.SpamGuard

A comprehensive, multi-layered spam protection library for ASP.NET Core applications. Combines Google reCAPTCHA v3, honeypot fields, timing analysis, pattern detection, and rate limiting to effectively block spam submissions.

## Features

✅ **Google reCAPTCHA v3 Integration** - Invisible verification with score-based detection  
✅ **Honeypot Fields** - Catches bots that auto-fill hidden fields  
✅ **Timing Analysis** - Detects suspiciously fast or automated submissions  
✅ **Random Text Detection** - Identifies gibberish patterns like "MruwAXBlxLlfnUjjZooNVL"  
✅ **Rate Limiting** - Prevents spam floods from the same IP  
✅ **Extensible Rule System** - Add custom spam detection rules  
✅ **Production-Ready** - Clean architecture, well-tested, fully documented

## Installation

```bash
dotnet add package AspNetCore.SpamGuard
```

Or via NuGet Package Manager:
```
Install-Package AspNetCore.SpamGuard
```

## Quick Start

### 1. Register Services

In your `Program.cs`:

```csharp
using AspNetCore.SpamGuard;

builder.Services.AddSpamGuard(options =>
{
    builder.Configuration.GetSection("SpamGuard").Bind(options);
});
```

### 2. Add reCAPTCHA to Your Form

```html
<!-- Include Google reCAPTCHA v3 script -->
<script src="https://www.google.com/recaptcha/api.js?render=YOUR_SITE_KEY"></script>

<form id="contactForm" method="post">
    <input type="text" name="name" placeholder="Name" />
    <input type="email" name="email" placeholder="Email" />
    
    <!-- Honeypot field - hide with CSS, not display:none -->
    <input type="text" name="website" style="position:absolute;left:-9999px" tabindex="-1" autocomplete="off" />
    
    <textarea name="message" placeholder="Message"></textarea>
    
    <!-- Hidden timing fields -->
    <input type="hidden" name="formRenderedAt" id="formRenderedAt" />
    <input type="hidden" name="recaptchaToken" id="recaptchaToken" />
    
    <button type="submit">Send</button>
</form>

<script>
    // Set form render time
    document.getElementById('formRenderedAt').value = Date.now();
    
    // Execute reCAPTCHA on form submit
    document.getElementById('contactForm').addEventListener('submit', function(e) {
        e.preventDefault();
        
        grecaptcha.ready(function() {
            grecaptcha.execute('YOUR_SITE_KEY', {action: 'submit'}).then(function(token) {
                document.getElementById('recaptchaToken').value = token;
                e.target.submit();
            });
        });
    });
</script>
```

### 3. Check for Spam in Your Controller

```csharp
using AspNetCore.SpamGuard;
using AspNetCore.SpamGuard.Models;
using Microsoft.AspNetCore.Mvc;

public class ContactController : Controller
{
    private readonly ISpamGuard _spamGuard;
    
    public ContactController(ISpamGuard spamGuard)
    {
        _spamGuard = spamGuard;
    }
    
    [HttpPost]
    public async Task<IActionResult> Submit(ContactModel model)
    {
        var context = new SpamCheckContext
        {
            FormData = new Dictionary<string, string>
            {
                ["name"] = model.Name,
                ["email"] = model.Email,
                ["message"] = model.Message
            },
            RecaptchaToken = model.RecaptchaToken,
            HoneypotValue = model.Website, // Should be empty
            FormRenderedAt = model.FormRenderedAt,
            FormSubmittedAt = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds(),
            IpAddress = HttpContext.Connection.RemoteIpAddress?.ToString(),
            UserAgent = Request.Headers["User-Agent"].ToString()
        };
        
        var result = await _spamGuard.CheckAsync(context);
        
        if (result.IsSpam)
        {
            // Log spam attempt
            _logger.LogWarning("Spam detected: {Rules}", string.Join(", ", result.TriggeredRules));
            
            // Return success to avoid revealing spam detection
            return Ok(new { message = "Thank you for your submission." });
        }
        
        return Ok(new { message = "Message sent successfully!" });
    }
}

public class ContactModel
{
    public string Name { get; set; }
    public string Email { get; set; }
    public string Message { get; set; }
    public string Website { get; set; } // Honeypot
    public string RecaptchaToken { get; set; }
    public long FormRenderedAt { get; set; }
}
```

## Configuration

All configuration is done through `SpamGuardOptions`:

### Using appsettings.json

```json
{
  "SpamGuard": {
    "RecaptchaSecretKey": "",
    "RecaptchaMinScore": 0.5,
    "RequireRecaptcha": true,
    "MinFormFillTimeSeconds": 2,
    "MaxFormFillTimeSeconds": 3600,
    "RandomTextCheckFields": [
      "name",
      "message"
    ],
    "RandomTextThreshold": 1,
    "EnableRateLimit": true,
    "RateLimitWindowMinutes": 10,
    "RateLimitMaxSubmissions": 3,
    "SpamConfidenceThreshold": 0.7,
    "SpamKeywords": [
      "casino",
      "lottery"
    ]
  }
}
```

Then in `Program.cs`:

```csharp
builder.Services.AddSpamGuard(options =>
{
    builder.Configuration.GetSection("SpamGuard").Bind(options);
});
```

## Built-in Rules

### 1. **HoneypotRule** (Severity: 0.95)
Detects if a honeypot field has been filled. Very high confidence spam indicator.

### 2. **RecaptchaRule** (Severity: 0.8)
Validates Google reCAPTCHA v3 token and score.

### 3. **TimingRule** (Severity: 0.7)
Flags submissions that are too fast (< 2 seconds by default).

### 4. **RandomTextRule** (Severity: 0.85)
Detects gibberish patterns like:
- Excessive consonants: "MruwAXBlxLlfnUjjZooNVL"
- Random case patterns: "VaZrAuGhTc"
- Low vowel ratios
- High character diversity

### 5. **RateLimitRule** (Severity: 0.75)
Limits submissions per IP (3 per 10 minutes by default).



## Best Practices

### 1. **Don't Reveal Spam Detection**
Always return a success message even for spam to avoid helping bots adapt:

```csharp
if (result.IsSpam)
{
    _logger.LogWarning("Spam detected from {IP}", context.IpAddress);
    return Ok(new { message = "Thank you!" }); // Same as success
}
```

### 2. **Style Honeypot Properly**
Use `position:absolute; left:-9999px` instead of `display:none` (bots check for this):

```html
<input type="text" name="website" style="position:absolute;left:-9999px" tabindex="-1" autocomplete="off" />
```

### 3. **Log Spam Attempts**
Monitor spam patterns to fine-tune your rules:

```csharp
if (result.IsSpam)
{
    _logger.LogWarning("Spam: {Score} - Rules: {Rules} - IP: {IP}", 
        result.ConfidenceScore, 
        string.Join(", ", result.TriggeredRules),
        context.IpAddress);
}
```

### 4. **Adjust Thresholds**
Start with defaults, then tune based on false positives/negatives:

```csharp
options.SpamConfidenceThreshold = 0.6; // More aggressive
options.RecaptchaMinScore = 0.7;       // Stricter reCAPTCHA
```


## Contributing

Contributions welcome! Please:

1. Fork the repository
2. Create a feature branch
3. Add tests for new rules
4. Submit a pull request

## License

MIT License

---

Built with ❤️ for a spam-free web