using AspNetCore.SpamGuard.Abstractions;
using AspNetCore.SpamGuard.Models;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;

namespace AspNetCore.SpamGuard.Tests;

internal sealed class ManualTimeProvider : TimeProvider
{
    private DateTimeOffset _now = new(2026, 1, 1, 12, 0, 0, TimeSpan.Zero);
    public override DateTimeOffset GetUtcNow() => _now;
    public void Advance(TimeSpan by) => _now += by;
}

internal sealed class StubRule : ISpamRule
{
    private readonly Func<SpamCheckContext, CancellationToken, Task<bool>> _eval;

    public StubRule(string name, double severity, bool triggers)
        : this(name, severity, (_, _) => Task.FromResult(triggers)) { }

    public StubRule(string name, double severity, Func<SpamCheckContext, CancellationToken, Task<bool>> eval)
    {
        RuleName = name;
        Severity = severity;
        _eval = eval;
    }

    public string RuleName { get; }
    public double Severity { get; }
    public Task<bool> IsSpamAsync(SpamCheckContext context, CancellationToken cancellationToken = default) => _eval(context, cancellationToken);
}

internal sealed class StubHandler : HttpMessageHandler
{
    private readonly Func<HttpRequestMessage, HttpResponseMessage> _respond;
    public List<Uri> Requests { get; } = new();

    public StubHandler(Func<HttpRequestMessage, HttpResponseMessage> respond) => _respond = respond;

    protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
    {
        lock (Requests) Requests.Add(request.RequestUri!);
        return Task.FromResult(_respond(request));
    }
}

internal static class TestServices
{
    public static void NoRecaptcha(SpamGuardOptions o) => o.RequireRecaptcha = false;

    public static ServiceProvider Build(Action<SpamGuardOptions>? configure = null, Action<IServiceCollection>? extra = null, ManualTimeProvider? time = null)
    {
        var services = new ServiceCollection();
        services.AddSingleton<IConfiguration>(new ConfigurationBuilder().Build());
        services.AddSingleton<IDataProtectionProvider>(new EphemeralDataProtectionProvider());
        services.AddSingleton<TimeProvider>(time ?? new ManualTimeProvider());
        services.AddSpamGuard(o =>
        {
            NoRecaptcha(o);
            configure?.Invoke(o);
        });
        extra?.Invoke(services);
        return services.BuildServiceProvider(new ServiceProviderOptions { ValidateOnBuild = true, ValidateScopes = true });
    }

    public static T Rule<T>(this IServiceProvider sp) where T : ISpamRule =>
        sp.CreateScope().ServiceProvider.GetServices<ISpamRule>().OfType<T>().Single();

    public static SpamCheckContext Context(params (string Key, string Value)[] fields)
    {
        var context = new SpamCheckContext();
        foreach (var (key, value) in fields) context.FormData[key] = value;
        return context;
    }
}
