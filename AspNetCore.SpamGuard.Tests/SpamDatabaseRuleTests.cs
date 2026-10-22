using System.Net;
using AspNetCore.SpamGuard.Models;
using AspNetCore.SpamGuard.Rules;
using AspNetCore.SpamGuard.SpamDatabase;
using Microsoft.Extensions.DependencyInjection;

namespace AspNetCore.SpamGuard.Tests;

public class SpamDatabaseRuleTests
{
    private const string ListedResponse =
        """{"success":1,"ip":{"value":"8.8.8.8","appears":1,"frequency":42,"confidence":91.5},"emailhash":{"value":"x","appears":0,"frequency":0}}""";

    private static (ServiceProvider Sp, StubHandler Handler) Setup(Func<HttpRequestMessage, HttpResponseMessage> respond, Action<SpamGuardOptions>? configure = null)
    {
        var handler = new StubHandler(respond);
        var sp = TestServices.Build(
            o => { o.SpamDatabase.Enabled = true; configure?.Invoke(o); },
            s => s.AddHttpClient<IStopForumSpamClient, StopForumSpamClient>().ConfigurePrimaryHttpMessageHandler(() => handler));
        return (sp, handler);
    }

    private static HttpResponseMessage Json(string json) => new(HttpStatusCode.OK) { Content = new StringContent(json, System.Text.Encoding.UTF8, "application/json") };

    [Fact]
    public async Task Disabled_by_default_and_makes_no_calls()
    {
        var handler = new StubHandler(_ => Json(ListedResponse));
        using var sp = TestServices.Build(extra: s => s.AddHttpClient<IStopForumSpamClient, StopForumSpamClient>().ConfigurePrimaryHttpMessageHandler(() => handler));

        Assert.False(await sp.Rule<SpamDatabaseRule>().IsSpamAsync(new SpamCheckContext { IpAddress = "8.8.8.8" }));
        Assert.Empty(handler.Requests);
    }

    [Fact]
    public async Task Listed_ip_above_confidence_is_spam_and_result_is_cached()
    {
        var (sp, handler) = Setup(_ => Json(ListedResponse));
        using var _ = sp;
        var context = new SpamCheckContext { IpAddress = "8.8.8.8" };

        Assert.True(await sp.Rule<SpamDatabaseRule>().IsSpamAsync(context));
        Assert.True(await sp.Rule<SpamDatabaseRule>().IsSpamAsync(context));

        var request = Assert.Single(handler.Requests);
        Assert.Equal("api.stopforumspam.org", request.Host);
        Assert.Contains("ip=8.8.8.8", request.Query);
        Assert.Contains("json", request.Query);
    }

    [Fact]
    public async Task Below_confidence_threshold_is_not_spam()
    {
        var (sp, _) = Setup(_ => Json(ListedResponse), o => o.SpamDatabase.MinConfidence = 95);
        using var _ = sp;
        Assert.False(await sp.Rule<SpamDatabaseRule>().IsSpamAsync(new SpamCheckContext { IpAddress = "8.8.8.8" }));
    }

    [Theory]
    [InlineData("127.0.0.1")]
    [InlineData("10.1.2.3")]
    [InlineData("192.168.1.1")]
    [InlineData("::1")]
    [InlineData("fd00::1")]
    public async Task Non_global_ips_are_never_sent(string ip)
    {
        var (sp, handler) = Setup(_ => Json(ListedResponse));
        using var _ = sp;

        Assert.False(await sp.Rule<SpamDatabaseRule>().IsSpamAsync(new SpamCheckContext { IpAddress = ip }));
        Assert.Empty(handler.Requests);
    }

    [Theory]
    [InlineData("192.0.2.1")]
    [InlineData("198.18.0.1")]
    [InlineData("203.0.113.5")]
    [InlineData("2001:db8::1")]
    [InlineData("64:ff9b:1::1")]
    public async Task Special_use_ips_are_never_sent(string ip)
    {
        var (sp, handler) = Setup(_ => Json(ListedResponse));
        using var _ = sp;

        Assert.False(await sp.Rule<SpamDatabaseRule>().IsSpamAsync(new SpamCheckContext { IpAddress = ip }));
        Assert.Empty(handler.Requests);
    }

    [Fact]
    public async Task Email_is_sent_as_md5_hash_only()
    {
        const string response = """{"success":1,"emailhash":{"value":"x","appears":1,"frequency":3,"confidence":80}}""";
        var (sp, handler) = Setup(_ => Json(response));
        using var _ = sp;

        var flagged = await sp.Rule<SpamDatabaseRule>().IsSpamAsync(TestServices.Context(("email", " Spammer@Example.com ")));

        Assert.True(flagged);
        var query = Assert.Single(handler.Requests).Query;
        Assert.DoesNotContain("spammer", query, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("emailhash=" + StopForumSpamClient.HashEmail("spammer@example.com"), query);
    }

    [Fact]
    public async Task Service_failures_fail_open()
    {
        var (sp, _) = Setup(_ => new HttpResponseMessage(HttpStatusCode.InternalServerError));
        using var _ = sp;
        Assert.False(await sp.Rule<SpamDatabaseRule>().IsSpamAsync(new SpamCheckContext { IpAddress = "8.8.8.8" }));

        var (sp2, _) = Setup(_ => Json("""{"success":0,"error":"rate limited"}"""));
        using var _2 = sp2;
        Assert.False(await sp2.Rule<SpamDatabaseRule>().IsSpamAsync(new SpamCheckContext { IpAddress = "8.8.8.8" }));

        var (sp3, _) = Setup(_ => throw new HttpRequestException("down"));
        using var _3 = sp3;
        Assert.False(await sp3.Rule<SpamDatabaseRule>().IsSpamAsync(new SpamCheckContext { IpAddress = "8.8.8.8" }));
    }

    [Theory]
    [InlineData("8.8.8.8", true)]
    [InlineData("2001:4860:4860::8888", true)]
    [InlineData("::ffff:8.8.8.8", true)]
    [InlineData("::ffff:192.168.0.1", false)]
    [InlineData("172.20.0.1", false)]
    [InlineData("100.64.0.1", false)]
    [InlineData("169.254.1.1", false)]
    [InlineData("192.0.2.1", false)]
    [InlineData("198.18.0.1", false)]
    [InlineData("203.0.113.5", false)]
    [InlineData("2001:db8::1", false)]
    [InlineData("64:ff9b:1::1", false)]
    [InlineData("2002::1", false)]
    [InlineData("3fff::1", false)]
    [InlineData("not-an-ip", false)]
    [InlineData(null, false)]
    public void Public_ip_detection(string? ip, bool expected) => Assert.Equal(expected, IpAddressHelper.IsPublic(ip));
}
