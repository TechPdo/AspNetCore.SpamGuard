using System.Text.Encodings.Web;
using AspNetCore.SpamGuard.Abstractions;
using Microsoft.AspNetCore.Razor.TagHelpers;
using Microsoft.Extensions.Options;

namespace AspNetCore.SpamGuard.TagHelpers;

/// <summary>
/// Renders the hidden SpamGuard form fields: an off-screen honeypot input, a server-signed form token,
/// and (optionally) a hidden reCAPTCHA token input.
/// Usage: <c>&lt;spam-guard-fields /&gt;</c> after <c>@addTagHelper *, AspNetCore.SpamGuard</c>.
/// </summary>
[HtmlTargetElement("spam-guard-fields", TagStructure = TagStructure.WithoutEndTag)]
public class SpamGuardFieldsTagHelper : TagHelper
{
    private readonly ISpamGuardFormTokenService _tokenService;
    private readonly SpamGuardOptions _options;
    private readonly HtmlEncoder _encoder;

    public SpamGuardFieldsTagHelper(ISpamGuardFormTokenService tokenService, IOptions<SpamGuardOptions> options, HtmlEncoder encoder)
    {
        _tokenService = tokenService;
        _options = options.Value;
        _encoder = encoder;
    }

    /// <summary>
    /// Render the honeypot field. Default: true.
    /// </summary>
    [HtmlAttributeName("include-honeypot")]
    public bool IncludeHoneypot { get; set; } = true;

    /// <summary>
    /// Render the signed form token. Default: true.
    /// </summary>
    [HtmlAttributeName("include-form-token")]
    public bool IncludeFormToken { get; set; } = true;

    /// <summary>
    /// Render an empty hidden input for the reCAPTCHA token (filled by client script). Default: false.
    /// </summary>
    [HtmlAttributeName("include-recaptcha")]
    public bool IncludeRecaptcha { get; set; }

    /// <summary>
    /// Label text for the honeypot (read only by assistive technology that ignores aria-hidden, and by bots).
    /// </summary>
    [HtmlAttributeName("honeypot-label")]
    public string HoneypotLabel { get; set; } = "Leave this field empty";

    public override void Process(TagHelperContext context, TagHelperOutput output)
    {
        output.TagName = null;
        output.TagMode = TagMode.StartTagAndEndTag;

        var html = output.Content;

        if (IncludeHoneypot)
        {
            var name = _encoder.Encode(_options.HoneypotFieldName);
            html.AppendHtml(
                "<div aria-hidden=\"true\" style=\"position:absolute!important;left:-10000px!important;top:auto!important;width:1px!important;height:1px!important;overflow:hidden!important;\">" +
                $"<label for=\"{name}\">{_encoder.Encode(HoneypotLabel)}</label>" +
                $"<input type=\"text\" id=\"{name}\" name=\"{name}\" value=\"\" tabindex=\"-1\" autocomplete=\"off\" />" +
                "</div>");
        }

        if (IncludeFormToken)
        {
            var name = _encoder.Encode(_options.FormTokenFieldName);
            var token = _encoder.Encode(_tokenService.GenerateToken());
            html.AppendHtml($"<input type=\"hidden\" name=\"{name}\" value=\"{token}\" />");
        }

        if (IncludeRecaptcha)
        {
            var name = _encoder.Encode(_options.RecaptchaTokenFieldName);
            html.AppendHtml($"<input type=\"hidden\" id=\"{name}\" name=\"{name}\" value=\"\" />");
        }
    }
}
