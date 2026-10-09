using System.Globalization;
using System.Text;

namespace Fortix.Core.Profiles;

/// <summary>
/// One invalid profile field: its JSON path and a fixed explanation that never echoes input.
/// </summary>
/// <param name="Field">The JSON path, including list indexes such as dns.domains[0].</param>
/// <param name="Message">The helper's exact explanation for the failure.</param>
public sealed record ProfileFieldProblem(string Field, string Message)
{
    /// <summary>
    /// Returns the path followed by the message, matching the helper's error text.
    /// </summary>
    /// <returns>The formatted problem.</returns>
    public override string ToString() => Field + ": " + Message;
}

/// <summary>
/// Thrown when a decoded profile breaks one or more field rules.
/// </summary>
public sealed class ProfileValidationException : Exception
{
    /// <summary>
    /// Creates an exception for a non-empty list of problems in helper order.
    /// </summary>
    /// <param name="problems">Every invalid field.</param>
    public ProfileValidationException(IReadOnlyList<ProfileFieldProblem> problems)
        : base(string.Join('\n', problems))
    {
        Problems = problems;
    }

    /// <summary>Gets every invalid field in helper order.</summary>
    public IReadOnlyList<ProfileFieldProblem> Problems { get; }
}

/// <summary>
/// Client-side mirror of the helper's profile defaults and validation, field for field.
/// </summary>
/// <remarks>
/// The helper stays authoritative. These rules exist so the editor can explain every problem
/// before anything is sent, using the same paths and messages the helper would return.
/// </remarks>
public static class ProfileRules
{
    /// <summary>The largest number of excluded ranges; each one can split pushed routes further.</summary>
    public const int MaxExclude = 64;

    /// <summary>The refusal the Windows helper returns for profiles that need a second factor.</summary>
    public const string WindowsMfaUnavailable = "MFA profiles are not available on Windows";

    /// <summary>The refusal the Windows helper returns for the openfortivpn backend.</summary>
    public const string WindowsOpenfortivpnUnavailable = "openfortivpn is not available on Windows; use the native backend";

    /// <summary>
    /// Reports whether <paramref name="id"/> matches ^[a-z0-9][a-z0-9-]{0,62}$ exactly.
    /// </summary>
    /// <param name="id">The candidate identifier.</param>
    /// <returns>True for a safe profile identifier.</returns>
    public static bool ValidId(string? id)
    {
        if (string.IsNullOrEmpty(id) || id.Length > 63 || !IsLowerAlnum(id[0]))
        {
            return false;
        }
        foreach (var c in id)
        {
            if (!IsLowerAlnum(c) && c != '-')
            {
                return false;
            }
        }
        return true;
    }

    /// <summary>
    /// Fills omitted port, MFA, backend, TOTP, routing, and DNS settings in place.
    /// </summary>
    /// <remarks>
    /// Password-only profiles resolve to native and second-factor modes to openfortivpn.
    /// Explicit backend choices, explicit false, and supplied TOTP values are preserved.
    /// </remarks>
    /// <param name="profile">The profile to complete.</param>
    public static void ApplyDefaults(Profile profile)
    {
        ArgumentNullException.ThrowIfNull(profile);
        if (profile.Gateway.Port == 0)
        {
            profile.Gateway.Port = 443;
        }
        if (profile.Mfa.Mode.Length == 0)
        {
            profile.Mfa.Mode = "none";
        }
        if (string.IsNullOrEmpty(profile.Backend))
        {
            profile.Backend = profile.Mfa.Mode == "none" ? "native" : "openfortivpn";
        }
        if (profile.Mfa.Mode == "totp")
        {
            profile.Mfa.Digits ??= 6;
            profile.Mfa.Period ??= 30;
            profile.Mfa.Algorithm ??= "SHA1";
        }
        if (profile.Routes.Mode.Length == 0)
        {
            profile.Routes.Mode = "gateway";
        }
        profile.Routes.PreserveLan ??= true;
        if (profile.Dns.Mode.Length == 0)
        {
            profile.Dns.Mode = "none";
        }
    }

    /// <summary>
    /// Validates like the helper, storing a valid certificate pin in lowercase without colons.
    /// </summary>
    /// <param name="profile">The defaulted profile; only a valid pin is changed.</param>
    /// <returns>Every problem in helper order, or an empty list.</returns>
    public static IReadOnlyList<ProfileFieldProblem> Validate(Profile profile)
    {
        ArgumentNullException.ThrowIfNull(profile);
        var problems = Problems(profile);
        if (!string.IsNullOrEmpty(profile.TrustedCert) && NormalizedPin(profile.TrustedCert) is { } pin)
        {
            profile.TrustedCert = pin;
        }
        return problems;
    }

    /// <summary>
    /// Returns every invalid field in helper order without changing the profile.
    /// </summary>
    /// <param name="profile">The profile to check, normally after <see cref="ApplyDefaults"/>.</param>
    /// <returns>Every problem, or an empty list for a valid profile.</returns>
    public static IReadOnlyList<ProfileFieldProblem> Problems(Profile profile)
    {
        ArgumentNullException.ThrowIfNull(profile);
        var problems = new List<ProfileFieldProblem>();
        void Add(string field, string message) => problems.Add(new ProfileFieldProblem(field, message));

        var backend = profile.Backend ?? "";
        if (profile.SchemaVersion != 1)
        {
            Add("schema_version", "must be 1");
        }
        if (!ValidId(profile.Id))
        {
            Add("id", "must match ^[a-z0-9][a-z0-9-]{0,62}$");
        }
        if (!ValidText(profile.Name, 1, 64))
        {
            Add("name", "must be 1..64 characters with no control characters");
        }
        if (backend.Length != 0 && backend != "native" && backend != "openfortivpn")
        {
            Add("backend", "must be native or openfortivpn");
        }
        if (backend == "native" && profile.Mfa.Mode != "none")
        {
            Add("backend", "native requires mfa.mode none; use openfortivpn for second factors");
        }
        if (!NetAddress.IsUnscopedAddress(profile.Gateway.Host) && !ValidDnsName(profile.Gateway.Host))
        {
            Add("gateway.host", "must be a DNS hostname or an unscoped IP literal");
        }
        if (profile.Gateway.Port is < 1 or > 65535)
        {
            Add("gateway.port", "must be 1..65535");
        }
        var realm = profile.Realm ?? "";
        if (realm.Length > 64 || !realm.All(c => IsLowerAlnum(c) || c is (>= 'A' and <= 'Z') or '.' or '_' or '-'))
        {
            Add("realm", "must be at most 64 characters from A-Z, a-z, 0-9, dot, underscore, or hyphen");
        }
        if (!ValidText(profile.Username, 1, 256) || HasOuterSpace(profile.Username))
        {
            Add("username", "must be 1..256 characters without controls or whitespace at ends");
        }
        if (!string.IsNullOrEmpty(profile.TrustedCert) && NormalizedPin(profile.TrustedCert) is null)
        {
            Add("trusted_cert", "must be 64 lowercase hexadecimal characters");
        }
        MfaProblems(profile.Mfa, Add);
        RouteProblems(profile.Routes, backend, Add);
        DnsProblems(profile.Dns, Add);
        return problems;
    }

    /// <summary>
    /// Returns the Windows helper's refusal for a stored profile, or null when it can connect.
    /// </summary>
    /// <remarks>
    /// The Windows helper has no openfortivpn runtime and no second-factor support, so it refuses
    /// such profiles at connect time. The MFA check comes first, matching the helper.
    /// </remarks>
    /// <param name="profile">A defaulted profile.</param>
    /// <returns>The exact helper message, or null.</returns>
    public static string? WindowsUnavailableReason(Profile profile)
    {
        ArgumentNullException.ThrowIfNull(profile);
        if (profile.Mfa.Mode != "none")
        {
            return WindowsMfaUnavailable;
        }
        return profile.Backend == "native" ? null : WindowsOpenfortivpnUnavailable;
    }

    /// <summary>
    /// Lowercases a domain and strips one leading wildcard label; multiple wildcards stay invalid.
    /// </summary>
    /// <param name="domain">The domain as entered or imported.</param>
    /// <returns>The normalized domain, which still needs validation.</returns>
    public static string NormalizeDomain(string domain)
    {
        ArgumentNullException.ThrowIfNull(domain);
        var lower = domain.ToLowerInvariant();
        return lower.StartsWith("*.", StringComparison.Ordinal) && !lower.AsSpan(2).Contains('*') ? lower[2..] : lower;
    }

    /// <summary>
    /// Trims surrounding whitespace and masks the host bits of a parseable prefix.
    /// </summary>
    /// <remarks>
    /// Malformed text is only trimmed so validation still reports it; IPv6 prefixes are
    /// canonicalized too, exactly as the helper does, and then rejected by validation.
    /// </remarks>
    /// <param name="text">The prefix as entered or imported.</param>
    /// <returns>The normalized prefix text.</returns>
    public static string NormalizePrefix(string text)
    {
        ArgumentNullException.ThrowIfNull(text);
        var trimmed = TrimGoSpace(text);
        if (!NetAddress.TryParsePrefix(trimmed, out var bytes, out _, out var bits))
        {
            return trimmed;
        }
        NetAddress.Mask(bytes, bits);
        return NetAddress.Format(bytes) + "/" + bits.ToString(CultureInfo.InvariantCulture);
    }

    /// <summary>
    /// Returns a valid certificate pin in lowercase without colons, or null when invalid.
    /// </summary>
    /// <param name="pin">The pin as entered.</param>
    /// <returns>The normalized pin or null.</returns>
    public static string? NormalizedPin(string pin)
    {
        ArgumentNullException.ThrowIfNull(pin);
        var normalized = pin.Replace(":", "", StringComparison.Ordinal).ToLowerInvariant();
        return normalized.Length == 64 && normalized.All(c => c is (>= '0' and <= '9') or (>= 'a' and <= 'f')) ? normalized : null;
    }

    /// <summary>
    /// Appends MFA mode and TOTP parameter problems; non-TOTP modes forbid every parameter.
    /// </summary>
    /// <param name="mfa">The MFA settings.</param>
    /// <param name="add">Receives each problem.</param>
    private static void MfaProblems(Mfa mfa, Action<string, string> add)
    {
        switch (mfa.Mode)
        {
            case "totp":
                if (mfa.Digits is not (6 or 8))
                {
                    add("mfa.digits", "must be 6 or 8");
                }
                if (mfa.Period is not (>= 15 and <= 120))
                {
                    add("mfa.period", "must be 15..120");
                }
                if (mfa.Algorithm is not ("SHA1" or "SHA256" or "SHA512"))
                {
                    add("mfa.algorithm", "must be SHA1, SHA256, or SHA512");
                }
                break;
            case "none" or "push" or "prompt" or "static":
                break;
            default:
                add("mfa.mode", "must be none, push, prompt, totp, or static");
                break;
        }
        if (mfa.Mode != "totp")
        {
            if (mfa.Digits is not null)
            {
                add("mfa.digits", "only allowed for totp");
            }
            if (mfa.Period is not null)
            {
                add("mfa.period", "only allowed for totp");
            }
            if (mfa.Algorithm is not null)
            {
                add("mfa.algorithm", "only allowed for totp");
            }
        }
    }

    /// <summary>
    /// Appends routing mode, list presence, exclude limit, and per-prefix problems.
    /// </summary>
    /// <param name="routes">The routing settings.</param>
    /// <param name="backend">The profile backend, which exclusion depends on.</param>
    /// <param name="add">Receives each problem.</param>
    private static void RouteProblems(Routes routes, string backend, Action<string, string> add)
    {
        switch (routes.Mode)
        {
            case "gateway" or "full":
                if (routes.Include is not null)
                {
                    add("routes.include", "only allowed for custom");
                }
                break;
            case "custom":
                if (routes.Include is null || routes.Include.Count == 0)
                {
                    add("routes.include", "custom requires a non-empty list");
                }
                if (routes.Exclude is not null)
                {
                    add("routes.exclude", "only allowed for gateway or full");
                }
                break;
            default:
                add("routes.mode", "must be gateway, custom, or full");
                break;
        }
        if (routes.Exclude is not null)
        {
            if (routes.Exclude.Count is 0 or > MaxExclude)
            {
                add("routes.exclude", $"must list 1..{MaxExclude} prefixes when present");
            }
            else if (backend == "openfortivpn")
            {
                add("routes.exclude", "requires the native backend");
            }
        }
        PrefixProblems("routes.include", routes.Include, add);
        PrefixProblems("routes.exclude", routes.Exclude, add);
    }

    /// <summary>
    /// Requires canonical, non-overlapping IPv4 prefixes of /8 or longer.
    /// </summary>
    /// <param name="name">The list's JSON path.</param>
    /// <param name="list">The prefixes, or null when absent.</param>
    /// <param name="add">Receives each problem.</param>
    private static void PrefixProblems(string name, List<string>? list, Action<string, string> add)
    {
        if (list is null)
        {
            return;
        }
        var previous = new List<(uint Address, int Bits)>();
        for (var i = 0; i < list.Count; i++)
        {
            var field = $"{name}[{i.ToString(CultureInfo.InvariantCulture)}]";
            if (!NetAddress.TryParsePrefix(list[i], out var bytes, out var isIPv4, out var bits) || !isIPv4)
            {
                add(field, "must be an IPv4 CIDR");
                continue;
            }
            var address = ((uint)bytes[0] << 24) | ((uint)bytes[1] << 16) | ((uint)bytes[2] << 8) | bytes[3];
            // A strictly parsed prefix formats back to its own text, so only host bits matter.
            if (address != MaskIPv4(address, bits))
            {
                add(field, "must be a canonical masked prefix");
            }
            if (bits < 8)
            {
                add(field, "prefixes /0 through /7 are too broad");
            }
            foreach (var earlier in previous)
            {
                if (earlier.Address == address && earlier.Bits == bits)
                {
                    add(field, "duplicate prefix");
                    break;
                }
                var shortest = Math.Min(earlier.Bits, bits);
                if (MaskIPv4(earlier.Address, shortest) == MaskIPv4(address, shortest))
                {
                    add(field, "overlaps another prefix in the list");
                    break;
                }
            }
            previous.Add((address, bits));
        }
    }

    /// <summary>
    /// Appends DNS mode, domain count, domain spelling, and duplicate problems.
    /// </summary>
    /// <param name="dns">The DNS settings.</param>
    /// <param name="add">Receives each problem.</param>
    private static void DnsProblems(Dns dns, Action<string, string> add)
    {
        switch (dns.Mode)
        {
            case "none":
                if (dns.Domains is not null)
                {
                    add("dns.domains", "only allowed for split");
                }
                break;
            case "split":
                if (dns.Domains is null || dns.Domains.Count is < 1 or > 32)
                {
                    add("dns.domains", "split requires 1..32 domains");
                }
                break;
            default:
                add("dns.mode", "must be none or split");
                break;
        }
        var seen = new HashSet<string>(StringComparer.Ordinal);
        for (var i = 0; i < (dns.Domains?.Count ?? 0); i++)
        {
            var domain = dns.Domains![i];
            var field = $"dns.domains[{i.ToString(CultureInfo.InvariantCulture)}]";
            if (!ValidDnsName(domain) || !domain.Contains('.', StringComparison.Ordinal) || domain.ToLowerInvariant() != domain)
            {
                add(field, "must be a lowercase DNS name with at least two labels, without trailing dot or wildcard");
            }
            if (!seen.Add(domain))
            {
                add(field, "duplicate domain");
            }
        }
    }

    /// <summary>
    /// Accepts min to max Unicode code points with no C0 or C1 control characters.
    /// </summary>
    /// <param name="text">The text to check.</param>
    /// <param name="min">The minimum code point count.</param>
    /// <param name="max">The maximum code point count.</param>
    /// <returns>True when the text is acceptable.</returns>
    private static bool ValidText(string? text, int min, int max)
    {
        var count = 0;
        foreach (var rune in (text ?? "").EnumerateRunes())
        {
            if (Rune.IsControl(rune))
            {
                return false;
            }
            count++;
        }
        return count >= min && count <= max;
    }

    /// <summary>
    /// Reports whether the text starts or ends with a Unicode whitespace code point.
    /// </summary>
    /// <param name="text">The text to check.</param>
    /// <returns>True when trimming would change the text.</returns>
    private static bool HasOuterSpace(string? text) => !string.IsNullOrEmpty(text) && TrimGoSpace(text).Length != text.Length;

    /// <summary>
    /// Trims the Unicode White_Space set, which is what the helper trims.
    /// </summary>
    /// <param name="text">The text to trim.</param>
    /// <returns>The trimmed text.</returns>
    private static string TrimGoSpace(string text)
    {
        // char.IsWhiteSpace covers exactly Unicode White_Space, all of which lies in the BMP.
        int start = 0, end = text.Length;
        while (start < end && char.IsWhiteSpace(text[start]))
        {
            start++;
        }
        while (end > start && char.IsWhiteSpace(text[end - 1]))
        {
            end--;
        }
        return text[start..end];
    }

    /// <summary>
    /// Checks an ASCII DNS name's length and letter, digit, and hyphen label boundaries.
    /// </summary>
    /// <param name="host">The candidate name.</param>
    /// <returns>False for schemes, ports, paths, empty labels, trailing dots, or wildcards.</returns>
    internal static bool ValidDnsName(string? host)
    {
        if (string.IsNullOrEmpty(host) || Encoding.UTF8.GetByteCount(host) > 253)
        {
            return false;
        }
        foreach (var label in host.Split('.'))
        {
            if (label.Length is 0 or > 63 || label[0] == '-' || label[^1] == '-')
            {
                return false;
            }
            foreach (var c in label)
            {
                if (!IsLowerAlnum(c) && c is not (>= 'A' and <= 'Z') && c != '-')
                {
                    return false;
                }
            }
        }
        return true;
    }

    /// <summary>
    /// Clears IPv4 host bits below a prefix length.
    /// </summary>
    /// <param name="address">The address as a big-endian integer.</param>
    /// <param name="bits">The prefix length.</param>
    /// <returns>The masked address.</returns>
    private static uint MaskIPv4(uint address, int bits) => bits == 0 ? 0 : address & (uint.MaxValue << (32 - bits));

    /// <summary>
    /// Accepts ASCII lowercase letters and digits.
    /// </summary>
    /// <param name="c">The character to check.</param>
    /// <returns>True for a-z or 0-9.</returns>
    private static bool IsLowerAlnum(char c) => c is (>= 'a' and <= 'z') or (>= '0' and <= '9');
}
