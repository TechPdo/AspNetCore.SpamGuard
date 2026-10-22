using System.Globalization;
using System.Security.Cryptography;
using AspNetCore.SpamGuard.Abstractions;
using Microsoft.AspNetCore.DataProtection;

namespace AspNetCore.SpamGuard;

/// <summary>
/// Default <see cref="ISpamGuardFormTokenService"/> backed by ASP.NET Core Data Protection.
/// </summary>
internal sealed class SpamGuardFormTokenService : ISpamGuardFormTokenService
{
    private const string Purpose = "AspNetCore.SpamGuard.FormToken.v1";
    private const string Prefix = "sg1:";

    private readonly IDataProtector _protector;
    private readonly TimeProvider _timeProvider;

    public SpamGuardFormTokenService(IDataProtectionProvider dataProtectionProvider, TimeProvider timeProvider)
    {
        _protector = dataProtectionProvider.CreateProtector(Purpose);
        _timeProvider = timeProvider;
    }

    public string GenerateToken()
    {
        var issuedAt = _timeProvider.GetUtcNow().ToUnixTimeMilliseconds();
        return _protector.Protect(Prefix + issuedAt.ToString(CultureInfo.InvariantCulture));
    }

    public bool TryValidateToken(string? token, out DateTimeOffset issuedAt)
    {
        issuedAt = default;

        if (string.IsNullOrWhiteSpace(token))
        {
            return false;
        }

        string payload;
        try
        {
            payload = _protector.Unprotect(token);
        }
        catch (CryptographicException)
        {
            return false;
        }
        catch (FormatException)
        {
            return false;
        }

        if (!payload.StartsWith(Prefix, StringComparison.Ordinal) ||
            !long.TryParse(payload.AsSpan(Prefix.Length), NumberStyles.None, CultureInfo.InvariantCulture, out var ms))
        {
            return false;
        }

        issuedAt = DateTimeOffset.FromUnixTimeMilliseconds(ms);
        return true;
    }
}
