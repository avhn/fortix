using System.Text.Json.Serialization;

namespace Fortix.Core.Profiles;

/// <summary>
/// Schema version 1 VPN configuration without passwords, seeds, or executable options.
/// </summary>
/// <remarks>
/// Field semantics follow the helper: optional strings that are null or empty mean "absent",
/// nullable numbers and lists distinguish omission from explicit values, and numbers are
/// 64-bit so out-of-range input is reported by validation rather than by decoding.
/// </remarks>
public sealed class Profile
{
    /// <summary>Gets or sets the schema version; only 1 is valid.</summary>
    [JsonPropertyName("schema_version")]
    public long SchemaVersion { get; set; }

    /// <summary>Gets or sets the helper-owned profile identifier.</summary>
    [JsonPropertyName("id")]
    public string Id { get; set; } = "";

    /// <summary>Gets or sets the human-readable label.</summary>
    [JsonPropertyName("name")]
    public string Name { get; set; } = "";

    /// <summary>Gets or sets the explicit backend; absent resolves from the MFA mode.</summary>
    [JsonPropertyName("backend")]
    public string? Backend { get; set; }

    /// <summary>Gets or sets the remote TLS endpoint.</summary>
    [JsonPropertyName("gateway")]
    public Gateway Gateway { get; set; } = new();

    /// <summary>Gets or sets the optional authentication realm.</summary>
    [JsonPropertyName("realm")]
    public string? Realm { get; set; }

    /// <summary>Gets or sets the account name, which is part of the credential identity.</summary>
    [JsonPropertyName("username")]
    public string Username { get; set; } = "";

    /// <summary>Gets or sets the helper-owned certificate pin; clients never install trust.</summary>
    [JsonPropertyName("trusted_cert")]
    public string? TrustedCert { get; set; }

    /// <summary>Gets or sets the second-factor interaction settings.</summary>
    [JsonPropertyName("mfa")]
    public Mfa Mfa { get; set; } = new();

    /// <summary>Gets or sets the routing policy.</summary>
    [JsonPropertyName("routes")]
    public Routes Routes { get; set; } = new();

    /// <summary>Gets or sets the DNS policy.</summary>
    [JsonPropertyName("dns")]
    public Dns Dns { get; set; } = new();

    /// <summary>
    /// Returns an independent copy, including list and nested object instances.
    /// </summary>
    /// <returns>A deep copy of this profile.</returns>
    public Profile Clone() => new()
    {
        SchemaVersion = SchemaVersion,
        Id = Id,
        Name = Name,
        Backend = Backend,
        Gateway = new Gateway { Host = Gateway.Host, Port = Gateway.Port },
        Realm = Realm,
        Username = Username,
        TrustedCert = TrustedCert,
        Mfa = new Mfa { Mode = Mfa.Mode, Digits = Mfa.Digits, Period = Mfa.Period, Algorithm = Mfa.Algorithm },
        Routes = new Routes
        {
            Mode = Routes.Mode,
            Include = Routes.Include is null ? null : [.. Routes.Include],
            Exclude = Routes.Exclude is null ? null : [.. Routes.Exclude],
            PreserveLan = Routes.PreserveLan,
        },
        Dns = new Dns { Mode = Dns.Mode, Domains = Dns.Domains is null ? null : [.. Dns.Domains] },
    };
}

/// <summary>
/// A gateway host (DNS name or unscoped IP literal) and TLS port.
/// </summary>
public sealed class Gateway
{
    /// <summary>Gets or sets the host; its spelling is part of the credential identity.</summary>
    [JsonPropertyName("host")]
    public string Host { get; set; } = "";

    /// <summary>Gets or sets the port; zero means the default 443 until defaults are applied.</summary>
    [JsonPropertyName("port")]
    public long Port { get; set; }
}

/// <summary>
/// Second-factor interaction without any stored seed or response.
/// </summary>
public sealed class Mfa
{
    /// <summary>Gets or sets the mode: none, push, prompt, totp, or static.</summary>
    [JsonPropertyName("mode")]
    public string Mode { get; set; } = "";

    /// <summary>Gets or sets the TOTP response length; only allowed for totp.</summary>
    [JsonPropertyName("digits")]
    public long? Digits { get; set; }

    /// <summary>Gets or sets the TOTP interval in seconds; only allowed for totp.</summary>
    [JsonPropertyName("period")]
    public long? Period { get; set; }

    /// <summary>Gets or sets the TOTP hash name; only allowed for totp.</summary>
    [JsonPropertyName("algorithm")]
    public string? Algorithm { get; set; }
}

/// <summary>
/// Gateway, custom, or full routing with optional IPv4 prefixes.
/// </summary>
/// <remarks>
/// Exclude removes ranges from gateway-pushed routes, for example a range another VPN owns,
/// so two gateways that push the same network can be connected together.
/// </remarks>
public sealed class Routes
{
    /// <summary>Gets or sets the mode: gateway, custom, or full.</summary>
    [JsonPropertyName("mode")]
    public string Mode { get; set; } = "";

    /// <summary>Gets or sets the requested prefixes; only allowed for custom.</summary>
    [JsonPropertyName("include")]
    public List<string>? Include { get; set; }

    /// <summary>Gets or sets prefixes removed from pushed routes; gateway or full only.</summary>
    [JsonPropertyName("exclude")]
    public List<string>? Exclude { get; set; }

    /// <summary>Gets or sets whether local networks stay reachable; absent means true.</summary>
    [JsonPropertyName("preserve_lan")]
    public bool? PreserveLan { get; set; }
}

/// <summary>
/// Unmanaged DNS or split DNS for explicitly listed lowercase domains.
/// </summary>
public sealed class Dns
{
    /// <summary>Gets or sets the mode: none or split.</summary>
    [JsonPropertyName("mode")]
    public string Mode { get; set; } = "";

    /// <summary>Gets or sets the split DNS domains; only allowed for split.</summary>
    [JsonPropertyName("domains")]
    public List<string>? Domains { get; set; }
}
