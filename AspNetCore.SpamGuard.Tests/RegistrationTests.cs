using AspNetCore.SpamGuard.Abstractions;
using AspNetCore.SpamGuard.Rules;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;

namespace AspNetCore.SpamGuard.Tests;

public class RegistrationTests
{
    [Fact]
    public void All_built_in_rules_resolve_from_DI()
    {
        using var sp = TestServices.Build();
        using var scope = sp.CreateScope();

        var names = scope.ServiceProvider.GetServices<ISpamRule>().Select(r => r.RuleName).ToArray();

        Assert.Equal(new[]
        {
            SpamRuleNames.Honeypot, SpamRuleNames.Recaptcha, SpamRuleNames.Timing, SpamRuleNames.RandomText,
            SpamRuleNames.RateLimit, SpamRuleNames.KeywordBlacklist, SpamRuleNames.SuspiciousEmail, SpamRuleNames.SpamDatabase
        }, names);
        Assert.NotNull(scope.ServiceProvider.GetRequiredService<ISpamGuard>());
    }

    [Fact]
    public void Calling_AddSpamGuard_twice_does_not_duplicate_rules()
    {
        var services = new ServiceCollection();
        services.AddSpamGuard(TestServices.NoRecaptcha).AddSpamRule<HoneypotRule>();
        services.AddSpamGuard(TestServices.NoRecaptcha);
        using var sp = services.BuildServiceProvider();

        Assert.Equal(8, sp.CreateScope().ServiceProvider.GetServices<ISpamRule>().Count());
    }

    [Fact]
    public void Configuration_arrays_replace_defaults_instead_of_appending()
    {
        var config = new ConfigurationBuilder().AddInMemoryCollection(new Dictionary<string, string?>
        {
            ["SpamGuard:RequireRecaptcha"] = "false",
            ["SpamGuard:SpamKeywords:0"] = "casino",
            ["SpamGuard:SpamKeywords:1"] = "lottery",
            ["SpamGuard:RandomTextCheckFields:0"] = "name",
        }).Build();

        var services = new ServiceCollection();
        services.AddSingleton<IConfiguration>(config);
        services.AddSpamGuard();
        using var sp = services.BuildServiceProvider();

        var options = sp.GetRequiredService<IOptions<SpamGuardOptions>>().Value;
        Assert.Equal(new[] { "casino", "lottery" }, options.SpamKeywords);
        Assert.Equal(new[] { "name" }, options.RandomTextCheckFields);
    }

    [Fact]
    public void RequireRecaptcha_without_secret_fails_validation()
    {
        var services = new ServiceCollection();
        services.AddSpamGuard(o => o.RequireRecaptcha = true);
        using var sp = services.BuildServiceProvider();

        var ex = Assert.Throws<OptionsValidationException>(() => sp.GetRequiredService<IOptions<SpamGuardOptions>>().Value);
        Assert.Contains("RecaptchaSecretKey", ex.Message);
    }

    [Fact]
    public void Invalid_ranges_fail_validation()
    {
        using var sp = TestServices.Build(o =>
        {
            o.SpamConfidenceThreshold = 1.5;
            o.SpamDatabase.Enabled = true;
            o.SpamDatabase.BaseUrl = "http://insecure";
        });

        var ex = Assert.Throws<OptionsValidationException>(() => sp.GetRequiredService<IOptions<SpamGuardOptions>>().Value);
        Assert.Contains(ex.Failures, f => f.Contains("SpamConfidenceThreshold"));
        Assert.Contains(ex.Failures, f => f.Contains("BaseUrl"));
    }

    [Theory]
    [InlineData(double.NaN)]
    [InlineData(double.PositiveInfinity)]
    [InlineData(double.NegativeInfinity)]
    public void Non_finite_score_thresholds_fail_validation(double threshold)
    {
        using var sp = TestServices.Build(o =>
        {
            o.RecaptchaMinScore = threshold;
            o.SpamConfidenceThreshold = threshold;
        });

        var ex = Assert.Throws<OptionsValidationException>(() => sp.GetRequiredService<IOptions<SpamGuardOptions>>().Value);
        Assert.Contains(ex.Failures, f => f.Contains("RecaptchaMinScore"));
        Assert.Contains(ex.Failures, f => f.Contains("SpamConfidenceThreshold"));
    }

    [Fact]
    public void FormData_lookup_is_case_insensitive_even_for_assigned_dictionaries()
    {
        var context = new Models.SpamCheckContext { FormData = new Dictionary<string, string> { ["Email"] = "a@b.c" } };
        Assert.True(context.FormData.ContainsKey("email"));
    }
}
