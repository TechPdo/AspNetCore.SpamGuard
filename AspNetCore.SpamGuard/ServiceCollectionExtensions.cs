using AspNetCore.SpamGuard.Abstractions;
using AspNetCore.SpamGuard.Recaptcha;
using AspNetCore.SpamGuard.Rules;
using Microsoft.Extensions.DependencyInjection;

namespace AspNetCore.SpamGuard;

/// <summary>
/// Extension methods for configuring SpamGuard services.
/// </summary>
public static class ServiceCollectionExtensions
{
    /// <summary>
    /// Adds SpamGuard services to the dependency injection container.
    /// </summary>
    /// <param name="services">The service collection.</param>
    /// <param name="configure">Configuration action for SpamGuardOptions.</param>
    /// <returns>The service collection for chaining.</returns>
    public static IServiceCollection AddSpamGuard(
        this IServiceCollection services,
        Action<SpamGuardOptions> configure)
    {
        // Register options
        services.Configure(configure);

        // Register HTTP client for reCAPTCHA verification
        services.AddHttpClient<IRecaptchaVerifier, RecaptchaVerifier>();

        // Register memory cache for rate limiting
        services.AddMemoryCache();

        // Register core service
        services.AddScoped<ISpamGuard, SpamGuard>();

        // Register built-in rules
        services.AddScoped<ISpamRule, HoneypotRule>();
        services.AddScoped<ISpamRule, RecaptchaRule>();
        services.AddScoped<ISpamRule, TimingRule>();
        services.AddScoped<ISpamRule, RandomTextRule>();
        services.AddScoped<ISpamRule, RateLimitRule>();        
        services.AddScoped<ISpamRule, KeywordBlacklistRule>();
        services.AddScoped<ISpamRule, SuspiciousEmailRule>();
        services.AddHttpClient<SpamDatabaseRule>();
        services.AddScoped<ISpamRule, SpamDatabaseRule>();

        return services;
    }

    /// <summary>
    /// Adds SpamGuard services with default configuration.
    /// You must set RecaptchaSecretKey in appsettings.json or environment variables.
    /// </summary>
    public static IServiceCollection AddSpamGuard(this IServiceCollection services)
    {
        return services.AddSpamGuard(options => { });
    }

    /// <summary>
    /// Adds a custom spam rule to the rule collection.
    /// </summary>
    /// <typeparam name="TRule">The custom rule type implementing ISpamRule.</typeparam>
    /// <param name="services">The service collection.</param>
    /// <returns>The service collection for chaining.</returns>
    public static IServiceCollection AddSpamRule<TRule>(this IServiceCollection services)
        where TRule : class, ISpamRule
    {
        services.AddScoped<ISpamRule, TRule>();
        return services;
    }
}
