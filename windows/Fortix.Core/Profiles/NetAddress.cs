using System.Globalization;
using System.Text;

namespace Fortix.Core.Profiles;

/// <summary>
/// Strict IP address and prefix parsing with the exact acceptance rules of Go's net/netip.
/// </summary>
/// <remarks>
/// System.Net.IPAddress accepts shorthand IPv4 forms, brackets, and other spellings the helper
/// rejects, so a profile it calls valid could still fail at the helper. This parser accepts
/// exactly what the helper accepts and formats prefixes the way the helper canonicalizes them.
/// </remarks>
internal static class NetAddress
{
    /// <summary>
    /// Reports whether <paramref name="text"/> is an IPv4 or IPv6 literal without a zone.
    /// </summary>
    /// <param name="text">The candidate literal.</param>
    /// <returns>True for an unscoped literal the helper accepts as an address.</returns>
    internal static bool IsUnscopedAddress(string text) => TryParseAddress(text, out _, out _);

    /// <summary>
    /// Parses an IPv4 dotted quad or an IPv6 literal; any zone suffix is rejected.
    /// </summary>
    /// <param name="text">The literal to parse.</param>
    /// <param name="bytes">Receives 4 bytes for IPv4 or 16 bytes for IPv6.</param>
    /// <param name="isIPv4">Receives true when the literal is a dotted quad.</param>
    /// <returns>True when parsing succeeded.</returns>
    internal static bool TryParseAddress(string text, out byte[] bytes, out bool isIPv4)
    {
        bytes = [];
        isIPv4 = false;
        // Dispatch on the first separator, as netip does; a zone always disqualifies.
        foreach (var c in text)
        {
            switch (c)
            {
                case '.':
                    isIPv4 = true;
                    bytes = new byte[4];
                    return TryParseIPv4(text, bytes);
                case ':':
                    return !text.Contains('%', StringComparison.Ordinal) && TryParseIPv6(text, out bytes);
                case '%':
                    return false;
            }
        }
        return false;
    }

    /// <summary>
    /// Parses exactly four decimal octets of at most 255 without leading zeros.
    /// </summary>
    /// <param name="text">The dotted quad.</param>
    /// <param name="fields">Receives the four octets.</param>
    /// <returns>True when the text is a strict dotted quad.</returns>
    private static bool TryParseIPv4(ReadOnlySpan<char> text, Span<byte> fields)
    {
        int value = 0, position = 0, digits = 0;
        for (var i = 0; i < text.Length; i++)
        {
            var c = text[i];
            if (c is >= '0' and <= '9')
            {
                if (digits == 1 && value == 0)
                {
                    return false;
                }
                value = (value * 10) + (c - '0');
                digits++;
                if (value > 255)
                {
                    return false;
                }
            }
            else if (c == '.')
            {
                if (i == 0 || i == text.Length - 1 || text[i - 1] == '.' || position == 3)
                {
                    return false;
                }
                fields[position++] = (byte)value;
                value = 0;
                digits = 0;
            }
            else
            {
                return false;
            }
        }
        if (position < 3)
        {
            return false;
        }
        fields[3] = (byte)value;
        return true;
    }

    /// <summary>
    /// Parses an unscoped IPv6 literal with optional "::" and an optional trailing dotted quad.
    /// </summary>
    /// <param name="text">The literal without a zone.</param>
    /// <param name="bytes">Receives the 16 address bytes.</param>
    /// <returns>True when the literal is valid.</returns>
    private static bool TryParseIPv6(string text, out byte[] bytes)
    {
        bytes = new byte[16];
        var s = text.AsSpan();
        var ellipsis = -1;
        if (s.Length >= 2 && s[0] == ':' && s[1] == ':')
        {
            ellipsis = 0;
            s = s[2..];
            if (s.Length == 0)
            {
                return true;
            }
        }
        var i = 0;
        while (i < 16)
        {
            var offset = 0;
            var accumulator = 0;
            for (; offset < s.Length; offset++)
            {
                var digit = HexValue(s[offset]);
                if (digit < 0)
                {
                    break;
                }
                if (offset > 3)
                {
                    return false;
                }
                accumulator = (accumulator << 4) + digit;
            }
            if (offset == 0)
            {
                return false;
            }
            if (offset < s.Length && s[offset] == '.')
            {
                // A trailing dotted quad replaces the final two groups.
                if ((ellipsis < 0 && i != 12) || i + 4 > 16 || !TryParseIPv4(s, bytes.AsSpan(i, 4)))
                {
                    return false;
                }
                s = [];
                i += 4;
                break;
            }
            bytes[i] = (byte)(accumulator >> 8);
            bytes[i + 1] = (byte)accumulator;
            i += 2;
            s = s[offset..];
            if (s.Length == 0)
            {
                break;
            }
            if (s[0] != ':' || s.Length == 1)
            {
                return false;
            }
            s = s[1..];
            if (s[0] == ':')
            {
                if (ellipsis >= 0)
                {
                    return false;
                }
                ellipsis = i;
                s = s[1..];
                if (s.Length == 0)
                {
                    break;
                }
            }
        }
        if (s.Length != 0)
        {
            return false;
        }
        if (i < 16)
        {
            if (ellipsis < 0)
            {
                return false;
            }
            // Shift the groups after the ellipsis to the end and zero the gap.
            var gap = 16 - i;
            for (var j = i - 1; j >= ellipsis; j--)
            {
                bytes[j + gap] = bytes[j];
            }
            Array.Clear(bytes, ellipsis, gap);
        }
        else if (ellipsis >= 0)
        {
            return false;
        }
        return true;
    }

    /// <summary>
    /// Returns the value of an ASCII hexadecimal digit, or -1 for any other character.
    /// </summary>
    /// <param name="c">The character to convert.</param>
    /// <returns>The digit value or -1.</returns>
    private static int HexValue(char c) => c switch
    {
        >= '0' and <= '9' => c - '0',
        >= 'a' and <= 'f' => c - 'a' + 10,
        >= 'A' and <= 'F' => c - 'A' + 10,
        _ => -1,
    };

    /// <summary>
    /// Parses "address/bits" with netip's rules: no zone, decimal bits without sign or leading zero.
    /// </summary>
    /// <param name="text">The prefix text.</param>
    /// <param name="bytes">Receives the unmasked address bytes.</param>
    /// <param name="isIPv4">Receives true for an IPv4 prefix.</param>
    /// <param name="bits">Receives the prefix length.</param>
    /// <returns>True when the prefix parses.</returns>
    internal static bool TryParsePrefix(string text, out byte[] bytes, out bool isIPv4, out int bits)
    {
        bits = 0;
        var slash = text.LastIndexOf('/');
        if (slash < 0 || !TryParseAddress(text[..slash], out bytes, out isIPv4))
        {
            bytes = [];
            isIPv4 = false;
            return false;
        }
        var digits = text.AsSpan(slash + 1);
        if (digits.Length == 0 || digits.Length > 3 || (digits.Length > 1 && digits[0] is < '1' or > '9'))
        {
            return false;
        }
        foreach (var c in digits)
        {
            if (c is < '0' or > '9')
            {
                return false;
            }
            bits = (bits * 10) + (c - '0');
        }
        return bits <= (isIPv4 ? 32 : 128);
    }

    /// <summary>
    /// Clears every bit below the prefix length.
    /// </summary>
    /// <param name="bytes">The address bytes to mask in place.</param>
    /// <param name="bits">The prefix length.</param>
    internal static void Mask(byte[] bytes, int bits)
    {
        for (var i = 0; i < bytes.Length; i++)
        {
            var keep = Math.Clamp(bits - (i * 8), 0, 8);
            bytes[i] &= (byte)(0xff << (8 - keep));
        }
    }

    /// <summary>
    /// Formats an address the way netip does: dotted quad, RFC 5952 IPv6, or ::ffff:a.b.c.d.
    /// </summary>
    /// <param name="bytes">Four or sixteen address bytes.</param>
    /// <returns>The canonical text.</returns>
    internal static string Format(byte[] bytes)
    {
        if (bytes.Length == 4)
        {
            return string.Join('.', bytes.Select(b => b.ToString(CultureInfo.InvariantCulture)));
        }
        var mapped = bytes.AsSpan(0, 10).IndexOfAnyExcept((byte)0) < 0 && bytes[10] == 0xff && bytes[11] == 0xff;
        if (mapped)
        {
            return "::ffff:" + Format(bytes[12..]);
        }
        var groups = new int[8];
        for (var i = 0; i < 8; i++)
        {
            groups[i] = (bytes[i * 2] << 8) | bytes[(i * 2) + 1];
        }
        // Compress the first longest run of at least two zero groups.
        int zeroStart = -1, zeroLength = 0;
        for (var i = 0; i < 8; i++)
        {
            var j = i;
            while (j < 8 && groups[j] == 0)
            {
                j++;
            }
            if (j - i >= 2 && j - i > zeroLength)
            {
                zeroStart = i;
                zeroLength = j - i;
            }
        }
        var output = new StringBuilder();
        for (var i = 0; i < 8; i++)
        {
            if (i == zeroStart)
            {
                output.Append("::");
                i += zeroLength;
                if (i >= 8)
                {
                    break;
                }
            }
            else if (i > 0)
            {
                output.Append(':');
            }
            output.Append(groups[i].ToString("x", CultureInfo.InvariantCulture));
        }
        return output.ToString();
    }
}
