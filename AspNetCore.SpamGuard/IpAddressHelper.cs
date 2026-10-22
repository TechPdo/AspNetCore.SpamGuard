using System.Net;
using System.Net.Sockets;

namespace AspNetCore.SpamGuard;

internal static class IpAddressHelper
{
    private static readonly (IPAddress Network, int PrefixLength)[] NonPublicIPv4Networks =
    {
        (IPAddress.Parse("0.0.0.0"), 8),
        (IPAddress.Parse("10.0.0.0"), 8),
        (IPAddress.Parse("100.64.0.0"), 10),
        (IPAddress.Parse("127.0.0.0"), 8),
        (IPAddress.Parse("169.254.0.0"), 16),
        (IPAddress.Parse("172.16.0.0"), 12),
        (IPAddress.Parse("192.0.0.0"), 24),
        (IPAddress.Parse("192.0.2.0"), 24),
        (IPAddress.Parse("192.88.99.0"), 24),
        (IPAddress.Parse("192.168.0.0"), 16),
        (IPAddress.Parse("198.18.0.0"), 15),
        (IPAddress.Parse("198.51.100.0"), 24),
        (IPAddress.Parse("203.0.113.0"), 24),
        (IPAddress.Parse("224.0.0.0"), 4),
        (IPAddress.Parse("240.0.0.0"), 4)
    };
    private static readonly (IPAddress Network, int PrefixLength)[] NonGlobalIPv6Networks =
    {
        (IPAddress.Parse("2001::"), 23),
        (IPAddress.Parse("2001:db8::"), 32),
        (IPAddress.Parse("2002::"), 16),
        (IPAddress.Parse("3fff::"), 20)
    };
    private static readonly IPAddress IPv6GlobalUnicastNetwork = IPAddress.Parse("2000::");

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

        if (address.AddressFamily == AddressFamily.InterNetwork)
        {
            return !NonPublicIPv4Networks.Any(range => IsInSubnet(address, range.Network, range.PrefixLength));
        }

        if (address.AddressFamily == AddressFamily.InterNetworkV6)
        {
            return IsInSubnet(address, IPv6GlobalUnicastNetwork, 3) &&
                   !NonGlobalIPv6Networks.Any(range => IsInSubnet(address, range.Network, range.PrefixLength));
        }

        return false;
    }

    private static bool IsInSubnet(IPAddress address, IPAddress network, int prefixLength)
    {
        var addressBytes = address.GetAddressBytes();
        var networkBytes = network.GetAddressBytes();
        if (addressBytes.Length != networkBytes.Length)
        {
            return false;
        }

        var fullBytes = prefixLength / 8;
        if (!addressBytes.AsSpan(0, fullBytes).SequenceEqual(networkBytes.AsSpan(0, fullBytes)))
        {
            return false;
        }

        var remainingBits = prefixLength % 8;
        if (remainingBits == 0)
        {
            return true;
        }

        var mask = (byte)(0xFF << (8 - remainingBits));
        return (addressBytes[fullBytes] & mask) == (networkBytes[fullBytes] & mask);
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
