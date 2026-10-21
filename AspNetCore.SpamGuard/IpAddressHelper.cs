using System.Net;
using System.Net.Sockets;

namespace AspNetCore.SpamGuard;

internal static class IpAddressHelper
{
    /// <summary>
    /// Returns true when the address is a publicly routable unicast address.
    /// </summary>
    public static bool IsPublic(string? ipAddress)
    {
        if (string.IsNullOrWhiteSpace(ipAddress) || !IPAddress.TryParse(ipAddress, out var address))
        {
            return false;
        }

        if (address.IsIPv4MappedToIPv6)
        {
            address = address.MapToIPv4();
        }

        if (IPAddress.IsLoopback(address) || address.Equals(IPAddress.Any) || address.Equals(IPAddress.IPv6Any) ||
            address.Equals(IPAddress.None) || address.Equals(IPAddress.IPv6None))
        {
            return false;
        }

        if (address.AddressFamily == AddressFamily.InterNetwork)
        {
            var b = address.GetAddressBytes();
            return !(b[0] == 10 ||
                     b[0] == 0 ||
                     (b[0] == 100 && b[1] >= 64 && b[1] <= 127) ||  // 100.64.0.0/10 (CGNAT)
                     (b[0] == 169 && b[1] == 254) ||                 // link-local
                     (b[0] == 172 && b[1] >= 16 && b[1] <= 31) ||
                     (b[0] == 192 && b[1] == 168) ||
                     b[0] >= 224);                                   // multicast / reserved
        }

        if (address.AddressFamily == AddressFamily.InterNetworkV6)
        {
            var b = address.GetAddressBytes();
            return !(address.IsIPv6LinkLocal ||
                     address.IsIPv6SiteLocal ||
                     address.IsIPv6Multicast ||
                     (b[0] & 0xFE) == 0xFC);                         // fc00::/7 unique local
        }

        return false;
    }

    /// <summary>
    /// Normalizes IPv4-mapped IPv6 addresses (e.g. "::ffff:1.2.3.4") to plain IPv4.
    /// </summary>
    public static string? Normalize(IPAddress? address)
    {
        if (address is null)
        {
            return null;
        }

        return (address.IsIPv4MappedToIPv6 ? address.MapToIPv4() : address).ToString();
    }

    /// <summary>
    /// Returns the key used to group requests from one client: the full address for IPv4, and the /64 prefix for
    /// IPv6 (hosts usually control a whole /64, so per-/128 limits are trivially bypassed). Unparseable values are
    /// returned unchanged.
    /// </summary>
    public static string GetClientKey(string ipAddress)
    {
        if (!IPAddress.TryParse(ipAddress, out var address))
        {
            return ipAddress;
        }

        if (address.IsIPv4MappedToIPv6)
        {
            address = address.MapToIPv4();
        }

        if (address.AddressFamily != AddressFamily.InterNetworkV6)
        {
            return address.ToString();
        }

        var bytes = address.GetAddressBytes();
        Array.Clear(bytes, 8, 8);
        return new IPAddress(bytes) + "/64";
    }
}
