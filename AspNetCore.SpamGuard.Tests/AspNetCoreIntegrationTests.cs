using System.Text;
using System.Text.Encodings.Web;
using AspNetCore.SpamGuard.Abstractions;
using AspNetCore.SpamGuard.TagHelpers;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Razor.TagHelpers;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;

namespace AspNetCore.SpamGuard.Tests;

public class AspNetCoreIntegrationTests
{
    [Fact]
    public async Task Tag_helper_renders_honeypot_and_valid_token()
    {
        using var sp = TestServices.Build(o => o.HoneypotFieldName = "url");
        var tokens = sp.GetRequiredService<ISpamGuardFormTokenService>();
        var helper = new SpamGuardFieldsTagHelper(tokens, sp.GetRequiredService<IOptions<SpamGuardOptions>>(), HtmlEncoder.Default)
        {
            IncludeRecaptcha = true
        };

        var context = new TagHelperContext(new TagHelperAttributeList(), new Dictionary<object, object>(), "id");
        var output = new TagHelperOutput("spam-guard-fields", new TagHelperAttributeList(),
            (_, _) => Task.FromResult<TagHelperContent>(new DefaultTagHelperContent()));

        helper.Process(context, output);
        var html = output.Content.GetContent();

        Assert.Null(output.TagName);
        Assert.Contains("name=\"url\"", html);
        Assert.Contains("tabindex=\"-1\"", html);
        Assert.Contains("aria-hidden=\"true\"", html);
        Assert.Contains("name=\"recaptchaToken\"", html);

        var marker = "name=\"__SpamGuardToken\" value=\"";
        var start = html.IndexOf(marker, StringComparison.Ordinal) + marker.Length;
        var token = html[start..html.IndexOf('"', start)];
        Assert.True(tokens.TryValidateToken(token, out _));
        await Task.CompletedTask;
    }

    [Fact]
    public async Task Context_is_built_from_form_post()
    {
        using var sp = TestServices.Build();
        var http = new DefaultHttpContext { RequestServices = sp };
        http.Connection.RemoteIpAddress = System.Net.IPAddress.Parse("::ffff:203.0.113.7");
        http.Request.Headers.UserAgent = "TestAgent";
        http.Request.Method = "POST";
        http.Request.ContentType = "application/x-www-form-urlencoded";
        http.Request.Body = new MemoryStream(Encoding.UTF8.GetBytes(
            "Name=Pasang&message=Hi&website=bot&recaptchaToken=rt&__SpamGuardToken=tok&formRenderedAt=123&__RequestVerificationToken=af"));

        var context = await http.CreateSpamCheckContextAsync();

        Assert.Equal("Pasang", context.FormData["name"]);
        Assert.Equal(new[] { "Name", "message" }, context.FormData.Keys);
        Assert.Equal("bot", context.HoneypotValue);
        Assert.Equal("rt", context.RecaptchaToken);
        Assert.Equal("tok", context.FormToken);
        Assert.Equal(123, context.FormRenderedAt);
        Assert.Equal("203.0.113.7", context.IpAddress);
        Assert.Equal("TestAgent", context.UserAgent);
        Assert.NotNull(context.FormSubmittedAt);
    }

    [Fact]
    public void Context_is_built_for_json_apis()
    {
        using var sp = TestServices.Build();
        var http = new DefaultHttpContext { RequestServices = sp };

        var context = http.CreateSpamCheckContext(
            new Dictionary<string, string?> { ["email"] = null, ["Message"] = "hi" },
            honeypotValue: "", formRenderedAt: 0);

        Assert.Equal(string.Empty, context.FormData["EMAIL"]);
        Assert.Equal("hi", context.FormData["message"]);
        Assert.Null(context.FormRenderedAt);
    }
}
