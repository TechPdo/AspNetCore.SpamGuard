using AspNetCore.SpamGuard.Abstractions;
using AspNetCore.SpamGuard.Recaptcha;
using AspNetCore.SpamGuard.Rules;
using AspNetCore.SpamGuard.SpamDatabase;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Options;

namespace AspNetCore.SpamGuard;

/// <summary>
/// Builder returned by <c>AddSpamGuard</c> for further configuration.
/// </summary>
public interface ISpamGuardBuilder
{
    /// <summary>
    /// The underlying service collection.
    /// </summary>
    IServiceCollection Services { get; }
}

internal sealed class SpamGuardBuilder : ISpamGuardBuilder
{
    public SpamGuardBuilder(IServiceCollection services) => Services = services;

    public IServiceCollection Services { get; }
}

/// <summary>
/// Extension methods for configuring SpamGuard services.
/// </summary>
public static class ServiceCollectionExtensions
{
    /// <summary>
    /// Adds SpamGuard services and binds <see cref="SpamGuardOptions"/> from the "SpamGuard" configuration section.
    /// </summary>
    public static ISpamGuardBuilder AddSpamGuard(this IServiceCollection services)
    {
        ArgumentNullException.ThrowIfNull(services);

        services.AddOptions<SpamGuardOptions>().BindConfiguration(SpamGuardOptions.SectionName);
        return services.AddSpamGuardCore();
    }

    /// <summary>
    /// Adds SpamGuard services configured by <paramref name="configure"/>.
    /// No configuration section is bound automatically.
    /// </summary>
    public static ISpamGuardBuilder AddSpamGuard(this IServiceCollection services, Action<SpamGuardOptions> configure)
    {
        ArgumentNullException.ThrowIfNull(services);
        ArgumentNullException.ThrowIfNull(configure);

        services.Configure(configure);
        return services.AddSpamGuardCore();
    }

    /// <summary>
    /// Adds SpamGuard services bound to the given configuration section, optionally followed by <paramref name="configure"/>.
    /// </summary>
    public static ISpamGuardBuilder AddSpamGuard(
        this IServiceCollection services,
        IConfiguration configuration,
        Action<SpamGuardOptions>? configure = null)
    {
        ArgumentNullException.ThrowIfNull(services);
        ArgumentNullException.ThrowIfNull(configuration);

        services.Configure<SpamGuardOptions>(configuration);
        if (configure is not null)
        {
            services.Configure(configure);
        }

        return services.AddSpamGuardCore();
    }

    /// <summary>
    /// Adds a custom spam rule to the rule collection.
    /// </summary>
    public static ISpamGuardBuilder AddSpamRule<TRule>(this ISpamGuardBuilder builder)
        where TRule : class, ISpamRule
    {
        ArgumentNullException.ThrowIfNull(builder);
        builder.Services.AddSpamRule<TRule>();
        return builder;
    }

    /// <summary>
    /// Adds a custom spam rule to the rule collection.
    /// </summary>
    public static IServiceCollection AddSpamRule<TRule>(this IServiceCollection services)
        where TRule : class, ISpamRule
    {
        ArgumentNullException.ThrowIfNull(services);
        services.TryAddEnumerable(ServiceDescriptor.Scoped<ISpamRule, TRule>());
        return services;
    }

    private static ISpamGuardBuilder AddSpamGuardCore(this IServiceCollection services)
    {
        var builder = new SpamGuardBuilder(services);

        if (services.Any(d => d.ServiceType == typeof(SpamGuardMarker)))
        {
            return builder;
        }

        services.AddSingleton<SpamGuardMarker>();

        services.AddOptions<SpamGuardOptions>().ValidateOnStart();
        services.TryAddEnumerable(ServiceDescriptor.Singleton<IValidateOptions<SpamGuardOptions>, SpamGuardOptionsValidator>());

        services.AddLogging();
        services.AddMemoryCache();
        services.AddDataProtection();
        services.TryAddSingleton(TimeProvider.System);

        services.AddHttpClient<IRecaptchaVerifier, RecaptchaVerifier>(client => client.Timeout = TimeSpan.FromSeconds(10));
        services.AddHttpClient<IStopForumSpamClient, StopForumSpamClient>((sp, client) =>
        {
            var options = sp.GetRequiredService<IOptions<SpamGuardOptions>>().Value.SpamDatabase;
            client.Timeout = TimeSpan.FromSeconds(options.TimeoutSeconds > 0 ? options.TimeoutSeconds : 3);
        });

        services.TryAddSingleton<ISpamGuardFormTokenService, SpamGuardFormTokenService>();
        services.TryAddScoped<ISpamGuard, SpamGuard>();

        services.AddSpamRule<HoneypotRule>();
        services.AddSpamRule<RecaptchaRule>();
        services.AddSpamRule<TimingRule>();
        services.AddSpamRule<RandomTextRule>();
        services.AddSpamRule<RateLimitRule>();
        services.AddSpamRule<KeywordBlacklistRule>();
        services.AddSpamRule<SuspiciousEmailRule>();
        services.AddSpamRule<SpamDatabaseRule>();

        return builder;
    }

    private sealed class SpamGuardMarker;
}
