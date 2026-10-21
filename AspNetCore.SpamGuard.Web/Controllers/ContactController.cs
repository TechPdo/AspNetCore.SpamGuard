using AspNetCore.SpamGuard.Abstractions;
using AspNetCore.SpamGuard.Web.Models;
using Microsoft.AspNetCore.Mvc;

namespace AspNetCore.SpamGuard.Web.Controllers
{
    [ApiController]
    [Route("api/[controller]")]
    public class ContactController : ControllerBase
    {
        private readonly ISpamGuard _spamGuard;
        private readonly ILogger<ContactController> _logger;
        private readonly IWebHostEnvironment _environment;

        public ContactController(ISpamGuard spamGuard, ILogger<ContactController> logger, IWebHostEnvironment environment)
        {
            _spamGuard = spamGuard;
            _logger = logger;
            _environment = environment;
        }

        [HttpPost]
        public async Task<IActionResult> Submit([FromBody] ContactModel model)
        {
            var context = HttpContext.CreateSpamCheckContext(
                new Dictionary<string, string?>
                {
                    ["name"] = model.Name,
                    ["email"] = model.Email,
                    ["phone"] = model.Phone,
                    ["message"] = model.Message
                },
                recaptchaToken: model.RecaptchaToken,
                honeypotValue: model.Website,
                formToken: model.FormToken,
                formRenderedAt: model.FormRenderedAt);

            var result = await _spamGuard.CheckAsync(context, HttpContext.RequestAborted);

            if (result.IsSpam)
            {
                _logger.LogWarning(
                    "Spam submission detected - Score: {Score}, Rules: {Rules}, IP: {IP}",
                    result.ConfidenceScore,
                    string.Join(", ", result.TriggeredRules),
                    context.IpAddress);
            }
            else
            {
                // Avoid logging PII (email, message) at Information level.
                _logger.LogInformation("Legitimate contact form submission received");
            }

            // Always return the same response so bots cannot learn which submissions were flagged.
            // In Development, include diagnostics to make the demo useful.
            return Ok(new
            {
                success = true,
                message = "Thank you for your message. We'll be in touch soon!",
                diagnostics = _environment.IsDevelopment()
                    ? new
                    {
                        result.IsSpam,
                        result.ConfidenceScore,
                        result.TriggeredRules,
                        result.FailedRules,
                        result.Messages
                    }
                    : null
            });
        }
    }
}
