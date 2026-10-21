using System.Diagnostics;
using AspNetCore.SpamGuard.Abstractions;
using AspNetCore.SpamGuard.Models;
using AspNetCore.SpamGuard.Recaptcha;
using AspNetCore.SpamGuard.Rules;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;

namespace AspNetCore.SpamGuard.Tests;

public class RandomTextRuleTests
{
    private static RandomTextRule Rule(Action<SpamGuardOptions>? configure = null)
    {
        var options = new SpamGuardOptions();
        configure?.Invoke(options);
        return new RandomTextRule(Options.Create(options));
    }

    [Theory]
    [InlineData("MruwAXBlxLlfnUjjZooNVL")]
    [InlineData("VAZRauGhTcJWjswjx")]
    public void Flags_gibberish(string text) => Assert.True(Rule().IsRandomText(text));

    [Theory]
    [InlineData("Pasang Tamang")]
    [InlineData("Hello, I would like to know more about your pricing and services.")]
    [InlineData("Christopher Strengthsworth")]
    [InlineData("पासाङ तामाङलाई नमस्कार, तपाईंको सेवाको बारेमा जान्न चाहन्छु")]
    [InlineData("我想了解更多关于你们的服务和价格信息谢谢")]
    [InlineData("Здравствуйте, хотел бы узнать подробнее о ваших услугах")]
    public void Does_not_flag_legitimate_text(string text) => Assert.False(Rule().IsRandomText(text));

    [Fact]
    public void Long_adversarial_input_is_analysed_quickly()
    {
        var input = new string('a', 1500) + "b" + new string('a', 50_000);
        var sw = Stopwatch.StartNew();
        Rule().IsRandomText(input);
        Assert.True(sw.Elapsed < TimeSpan.FromSeconds(2), $"took {sw.Elapsed}");
    }

    [Fact]
    public async Task Configured_fields_replace_defaults()
    {
        var context = TestServices.Context(("message", "MruwAXBlxLlfnUjjZooNVL"));
        Assert.True(await Rule().IsSpamAsync(context));
        Assert.False(await Rule(o => o.RandomTextCheckFields = new[] { "name" }).IsSpamAsync(context));
    }
}

public class KeywordAndEmailRuleTests
{
    [Fact]
    public async Task Keywords_match_whole_words_case_insensitively()
    {
        var rule = new KeywordBlacklistRule(Options.Create(new SpamGuardOptions { SpamKeywords = new[] { "casino", "sex", "click here" } }));

        Assert.True(await rule.IsSpamAsync(TestServices.Context(("message", "Best CASINO bonuses"))));
        Assert.True(await rule.IsSpamAsync(TestServices.Context(("message", "Please Click Here now"))));
        Assert.False(await rule.IsSpamAsync(TestServices.Context(("message", "I live in Essex"))));
    }

    [Fact]
    public async Task No_keywords_configured_never_triggers()
    {
        var rule = new KeywordBlacklistRule(Options.Create(new SpamGuardOptions()));
        Assert.False(await rule.IsSpamAsync(TestServices.Context(("message", "casino lottery"))));
    }

    [Theory]
    [InlineData("a.b.c.d@gmail.com", true)]
    [InlineData("someone@mailinator.com", true)]
    [InlineData("x@sub.guerrillamail.com", true)]
    [InlineData("john+spam@gmail.com", true)]
    [InlineData("12345@gmail.com", false)]
    [InlineData("john.doe@gmail.com", false)]
    [InlineData("first.middle.last@company.co.uk", false)]
    public async Task Suspicious_email_patterns(string email, bool expected)
    {
        var rule = new SuspiciousEmailRule(Options.Create(new SpamGuardOptions()));
        Assert.Equal(expected, await rule.IsSpamAsync(TestServices.Context(("Email", email))));
    }
}

public class RateLimitRuleTests
{
    [Fact]
    public async Task Blocks_after_limit_and_recovers_after_window()
    {
        var time = new ManualTimeProvider();
        using var sp = TestServices.Build(o => { o.RateLimitMaxSubmissions = 2; o.RateLimitWindowMinutes = 10; }, time: time);
        var rule = sp.Rule<RateLimitRule>();
        var context = new SpamCheckContext { IpAddress = "203.0.113.1" };

        Assert.False(await rule.IsSpamAsync(context));
        Assert.False(await rule.IsSpamAsync(context));
        Assert.True(await rule.IsSpamAsync(context));
        Assert.False(await rule.IsSpamAsync(new SpamCheckContext { IpAddress = "203.0.113.2" }));

        time.Advance(TimeSpan.FromMinutes(11));
        Assert.False(await rule.IsSpamAsync(context));
    }

    [Fact]
    public async Task Ipv6_clients_are_limited_per_64_prefix()
    {
        using var sp = TestServices.Build(o => o.RateLimitMaxSubmissions = 2);
        var rule = sp.Rule<RateLimitRule>();

        Assert.False(await rule.IsSpamAsync(new SpamCheckContext { IpAddress = "2001:db8:1:2::1" }));
        Assert.False(await rule.IsSpamAsync(new SpamCheckContext { IpAddress = "2001:db8:1:2:aaaa::9" }));
        Assert.True(await rule.IsSpamAsync(new SpamCheckContext { IpAddress = "2001:db8:1:2:ffff:ffff:ffff:ffff" }));
        Assert.False(await rule.IsSpamAsync(new SpamCheckContext { IpAddress = "2001:db8:1:3::1" }));
    }

    [Fact]
    public async Task Is_thread_safe_under_concurrency()
    {
        using var sp = TestServices.Build(o => o.RateLimitMaxSubmissions = 50);
        var context = new SpamCheckContext { IpAddress = "203.0.113.9" };

        var results = await Task.WhenAll(Enumerable.Range(0, 500).Select(_ =>
            Task.Run(() => sp.Rule<RateLimitRule>().IsSpamAsync(context))));

        Assert.Equal(50, results.Count(r => !r));
    }
}

public class TimingRuleTests
{
    private static (ServiceProvider Sp, ManualTimeProvider Time, TimingRule Rule, ISpamGuardFormTokenService Tokens) Setup(Action<SpamGuardOptions>? configure = null)
    {
        var time = new ManualTimeProvider();
        var sp = TestServices.Build(configure, time: time);
        return (sp, time, sp.Rule<TimingRule>(), sp.GetRequiredService<ISpamGuardFormTokenService>());
    }

    [Fact]
    public async Task Signed_token_uses_server_time()
    {
        var (sp, time, rule, tokens) = Setup();
        using var _ = sp;
        var context = new SpamCheckContext { FormToken = tokens.GenerateToken() };

        Assert.True(await rule.IsSpamAsync(context)); // submitted instantly

        time.Advance(TimeSpan.FromSeconds(5));
        Assert.False(await rule.IsSpamAsync(context));
    }

    [Fact]
    public async Task Signed_token_uses_submission_time_after_delayed_rule_evaluation()
    {
        var (sp, time, rule, tokens) = Setup();
        using var _ = sp;
        var context = new SpamCheckContext
        {
            FormToken = tokens.GenerateToken(),
            FormSubmittedAt = time.GetUtcNow().ToUnixTimeMilliseconds()
        };

        time.Advance(TimeSpan.FromSeconds(5));

        Assert.True(await rule.IsSpamAsync(context));
    }

    [Fact]
    public async Task Tampered_token_is_spam()
    {
        var (sp, time, rule, tokens) = Setup();
        using var _ = sp;
        var token = tokens.GenerateToken();
        time.Advance(TimeSpan.FromSeconds(30));

        Assert.True(await rule.IsSpamAsync(new SpamCheckContext { FormToken = token[..^4] + "AAAA" }));
        Assert.True(await rule.IsSpamAsync(new SpamCheckContext { FormToken = "not-a-token" }));
    }

    [Fact]
    public async Task Missing_token_is_spam_only_when_required()
    {
        var (sp1, _, optional, _) = Setup();
        var (sp2, _, required, _) = Setup(o => o.RequireFormToken = true);
        using var _1 = sp1;
        using var _2 = sp2;

        Assert.False(await optional.IsSpamAsync(new SpamCheckContext()));
        Assert.True(await required.IsSpamAsync(new SpamCheckContext()));
    }

    [Fact]
    public async Task Falls_back_to_client_timestamps()
    {
        var (sp, _, rule, _) = Setup();
        using var _ = sp;

        Assert.True(await rule.IsSpamAsync(new SpamCheckContext { FormRenderedAt = 1_000, FormSubmittedAt = 1_500 }));
        Assert.False(await rule.IsSpamAsync(new SpamCheckContext { FormRenderedAt = 1_000, FormSubmittedAt = 10_000 }));
    }

    [Fact]
    public async Task Stale_submissions_flagged_only_when_enabled()
    {
        var (sp, time, rule, tokens) = Setup(o => o.FlagStaleSubmissions = true);
        using var _ = sp;
        var context = new SpamCheckContext { FormToken = tokens.GenerateToken() };
        time.Advance(TimeSpan.FromHours(2));

        Assert.True(await rule.IsSpamAsync(context));
    }

    [Fact]
    public async Task Delayed_rule_evaluation_does_not_flag_submission_as_stale()
    {
        var (sp, time, rule, tokens) = Setup(o => o.FlagStaleSubmissions = true);
        using var _ = sp;
        var token = tokens.GenerateToken();
        time.Advance(TimeSpan.FromSeconds(30));
        var context = new SpamCheckContext
        {
            FormToken = token,
            FormSubmittedAt = time.GetUtcNow().ToUnixTimeMilliseconds()
        };

        time.Advance(TimeSpan.FromHours(2));

        Assert.False(await rule.IsSpamAsync(context));
    }
}

public class RecaptchaRuleTests
{
    private sealed class FakeVerifier : IRecaptchaVerifier
    {
        public RecaptchaResponse Response { get; set; } = new() { Success = true, Score = 0.9, Action = "submit", Hostname = "example.com" };
        public int Calls { get; private set; }
        public Task<RecaptchaResponse> VerifyAsync(string token, string? remoteIp = null, CancellationToken cancellationToken = default)
        {
            Calls++;
            return Task.FromResult(Response);
        }
    }

    private static RecaptchaRule Rule(FakeVerifier verifier, Action<SpamGuardOptions> configure)
    {
        var options = new SpamGuardOptions { RecaptchaSecretKey = "secret" };
        configure(options);
        return new RecaptchaRule(verifier, Options.Create(options));
    }

    [Fact]
    public async Task Valid_token_passes_and_low_score_fails()
    {
        var verifier = new FakeVerifier();
        var rule = Rule(verifier, _ => { });
        var context = new SpamCheckContext { RecaptchaToken = "t" };

        Assert.False(await rule.IsSpamAsync(context));
        verifier.Response.Score = 0.1;
        Assert.True(await rule.IsSpamAsync(context));
    }

    [Fact]
    public async Task Action_and_hostname_are_enforced_when_configured()
    {
        var verifier = new FakeVerifier();
        var context = new SpamCheckContext { RecaptchaToken = "t" };

        Assert.True(await Rule(verifier, o => o.RecaptchaExpectedAction = "login").IsSpamAsync(context));
        Assert.True(await Rule(verifier, o => o.RecaptchaAllowedHostnames = new[] { "other.com" }).IsSpamAsync(context));
        Assert.False(await Rule(verifier, o => { o.RecaptchaExpectedAction = "submit"; o.RecaptchaAllowedHostnames = new[] { "EXAMPLE.com" }; }).IsSpamAsync(context));
    }

    [Fact]
    public async Task Missing_token_respects_RequireRecaptcha()
    {
        var verifier = new FakeVerifier();
        Assert.True(await Rule(verifier, o => o.RequireRecaptcha = true).IsSpamAsync(new SpamCheckContext()));
        Assert.False(await Rule(verifier, o => o.RequireRecaptcha = false).IsSpamAsync(new SpamCheckContext()));
    }

    [Fact]
    public async Task Skipped_when_not_configured()
    {
        var verifier = new FakeVerifier();
        var rule = Rule(verifier, o => { o.RecaptchaSecretKey = null; o.RequireRecaptcha = false; });

        Assert.False(await rule.IsSpamAsync(new SpamCheckContext { RecaptchaToken = "t" }));
        Assert.Equal(0, verifier.Calls);
    }
}
