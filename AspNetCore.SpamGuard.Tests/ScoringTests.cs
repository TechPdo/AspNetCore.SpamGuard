using AspNetCore.SpamGuard.Abstractions;
using AspNetCore.SpamGuard.Models;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;

namespace AspNetCore.SpamGuard.Tests;

public class ScoringTests
{
    private static SpamGuard CreateGuard(SpamGuardOptions options, params ISpamRule[] rules) =>
        new(rules, Options.Create(options), NullLogger<SpamGuard>.Instance);

    [Fact]
    public async Task Additional_weak_rules_increase_the_score()
    {
        var guard = CreateGuard(new SpamGuardOptions(),
            new StubRule("Honeypot", 0.95, true),
            new StubRule("Caps", 0.4, true),
            new StubRule("Email", 0.6, true));

        var result = await guard.CheckAsync(new SpamCheckContext());

        Assert.True(result.IsSpam);
        Assert.Equal(1 - 0.05 * 0.6 * 0.4, result.ConfidenceScore, 6);
        Assert.Equal(new[] { "Honeypot", "Caps", "Email" }, result.TriggeredRules);
    }

    [Fact]
    public async Task Two_weak_signals_combine_into_spam_but_one_does_not()
    {
        var one = await CreateGuard(new SpamGuardOptions(), new StubRule("A", 0.6, true)).CheckAsync(new SpamCheckContext());
        var two = await CreateGuard(new SpamGuardOptions(), new StubRule("A", 0.6, true), new StubRule("B", 0.6, true)).CheckAsync(new SpamCheckContext());

        Assert.False(one.IsSpam);
        Assert.True(two.IsSpam);
        Assert.Equal(0.84, two.ConfidenceScore, 6);
    }

    [Fact]
    public async Task No_triggered_rules_is_not_spam()
    {
        var result = await CreateGuard(new SpamGuardOptions(), new StubRule("A", 0.9, false)).CheckAsync(new SpamCheckContext());
        Assert.False(result.IsSpam);
        Assert.Equal(0, result.ConfidenceScore);
    }

    [Fact]
    public async Task Disabled_rules_are_skipped()
    {
        var called = false;
        var guard = CreateGuard(new SpamGuardOptions { DisabledRules = new[] { "honeypot" } },
            new StubRule("Honeypot", 0.95, (_, _) => { called = true; return Task.FromResult(true); }));

        var result = await guard.CheckAsync(new SpamCheckContext());

        Assert.False(called);
        Assert.False(result.IsSpam);
    }

    [Fact]
    public async Task Failing_rule_is_reported_without_leaking_exception_details()
    {
        var guard = CreateGuard(new SpamGuardOptions(),
            new StubRule("Broken", 0.9, (_, _) => throw new InvalidOperationException("secret connection string")),
            new StubRule("Honeypot", 0.95, true));

        var result = await guard.CheckAsync(new SpamCheckContext());

        Assert.True(result.IsSpam);
        Assert.Equal(new[] { "Broken" }, result.FailedRules);
        Assert.DoesNotContain(result.Messages, m => m.Contains("secret connection string"));
    }

    [Fact]
    public async Task Cancellation_is_propagated()
    {
        using var cts = new CancellationTokenSource();
        var guard = CreateGuard(new SpamGuardOptions(),
            new StubRule("Cancels", 0.5, (_, ct) => { cts.Cancel(); ct.ThrowIfCancellationRequested(); return Task.FromResult(false); }));

        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => guard.CheckAsync(new SpamCheckContext(), cts.Token));
    }

    [Fact]
    public async Task End_to_end_clean_submission_is_not_spam()
    {
        using var sp = TestServices.Build(o => o.SpamKeywords = new[] { "casino" });
        using var scope = sp.CreateScope();
        var tokens = sp.GetRequiredService<ISpamGuardFormTokenService>();
        var token = tokens.GenerateToken();
        ((ManualTimeProvider)sp.GetRequiredService<TimeProvider>()).Advance(TimeSpan.FromSeconds(20));

        var context = TestServices.Context(("name", "Pasang Tamang"), ("email", "pasang@example.com"), ("message", "Hello, I would like to know more about your services."));
        context.FormToken = token;
        context.IpAddress = "203.0.113.10";

        var result = await scope.ServiceProvider.GetRequiredService<ISpamGuard>().CheckAsync(context);

        Assert.False(result.IsSpam, string.Join(", ", result.TriggeredRules));
        Assert.Empty(result.FailedRules);
    }
}
