using System.ComponentModel.DataAnnotations;

namespace AspNetCore.SpamGuard.Web.Models
{
    public class ContactModel
    {
        [Required, StringLength(100)]
        public string Name { get; set; } = string.Empty;

        [Required, EmailAddress, StringLength(320)]
        public string Email { get; set; } = string.Empty;

        [StringLength(30)]
        public string? Phone { get; set; }

        [Required, StringLength(5000)]
        public string Message { get; set; } = string.Empty;

        // Honeypot field (should be empty)
        public string? Website { get; set; }

        // reCAPTCHA token from client
        public string? RecaptchaToken { get; set; }

        // Signed server-side render timestamp (rendered by <spam-guard-fields />)
        public string? FormToken { get; set; }

        // Legacy client-side timestamp; only used when no FormToken is present
        public long? FormRenderedAt { get; set; }
    }
}
