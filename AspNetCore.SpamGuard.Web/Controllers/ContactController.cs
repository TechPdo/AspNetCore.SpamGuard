using AspNetCore.SpamGuard.Abstractions;
using AspNetCore.SpamGuard.Models;
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

        public ContactController(ISpamGuard spamGuard, ILogger<ContactController> logger)
        {
            _spamGuard = spamGuard;
            _logger = logger;
        }

        [HttpPost]
        public async Task<IActionResult> Submit([FromBody] ContactModel model)
        {
            // Build spam check context
            var context = new SpamCheckContext
            {
                FormData = new Dictionary<string, string>
                {
                    ["name"] = model.Name,
                    ["email"] = model.Email,
                    ["phone"] = model.Phone,
                    ["message"] = model.Message
                },
                RecaptchaToken = model.RecaptchaToken,
                HoneypotValue = model.Website,
                FormRenderedAt = model.FormRenderedAt,
                FormSubmittedAt = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds(),
                IpAddress = HttpContext.Connection.RemoteIpAddress?.ToString(),
                UserAgent = Request.Headers["User-Agent"].ToString()
            };

            // Check for spam
            var result = await _spamGuard.CheckAsync(context);

            if (result.IsSpam)
            {
                // Log spam attempt with details
                _logger.LogWarning(
                    "Spam submission detected - Score: {Score}, Rules: {Rules}, IP: {IP}, Data: {@FormData}",
                    result.ConfidenceScore,
                    string.Join(", ", result.TriggeredRules),
                    context.IpAddress,
                    new { model.Name, model.Email, model.Phone, MessageLength = model.Message.Length }
                );

                // IMPORTANT: Return success message to avoid revealing spam detection
                // This prevents bots from learning and adapting
                return Ok(new
                {
                    success = true,
                    message = "Thank you for your submission. We'll be in touch soon!"
                });
            }

            // Process legitimate submission
            _logger.LogInformation("Legitimate contact form submission from {Email}", model.Email);

            return Ok(new
            {
                success = true,
                message = "Thank you for your message. We'll respond within 24 hours!"
            });
        }
    }
}