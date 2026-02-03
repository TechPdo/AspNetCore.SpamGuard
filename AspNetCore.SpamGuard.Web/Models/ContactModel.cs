namespace AspNetCore.SpamGuard.Web.Models
{
    public class ContactModel
    {
        public string Name { get; set; } = string.Empty;
        public string Email { get; set; } = string.Empty;
        public string Phone { get; set; } = string.Empty;
        public string Message { get; set; } = string.Empty;

        // Honeypot field (should be empty)
        public string? Website { get; set; }

        // reCAPTCHA token from client
        public string? RecaptchaToken { get; set; }

        // Timing information
        public long FormRenderedAt { get; set; }
    }
}
