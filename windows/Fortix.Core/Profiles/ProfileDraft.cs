using System.Text.Json.Serialization;

namespace Fortix.Core.Profiles;

/// <summary>
/// Optional shared profile fields; null means the shared document did not supply the field.
/// </summary>
/// <remarks>
/// There is deliberately no username: a shared document can neither carry nor overwrite
/// personal identity. Parsing validates supplied values without filling absent ones.
/// </remarks>
public sealed class ProfileDraft
{
    /// <summary>Gets or sets the per-profile schema version, independent of the document version.</summary>
    [JsonPropertyName("schema_version")]
    public long? SchemaVersion { get; set; }

    /// <summary>Gets or sets the suggested identifier.</summary>
    [JsonPropertyName("id")]
    public string? Id { get; set; }

    /// <summary>Gets or sets the suggested label.</summary>
    [JsonPropertyName("name")]
    public string? Name { get; set; }

    /// <summary>Gets or sets the explicit backend; empty means automatic.</summary>
    [JsonPropertyName("backend")]
    public string? Backend { get; set; }

    /// <summary>Gets or sets the partial gateway.</summary>
    [JsonPropertyName("gateway")]
    public DraftGateway? Gateway { get; set; }

    /// <summary>Gets or sets the authentication realm.</summary>
    [JsonPropertyName("realm")]
    public string? Realm { get; set; }

    /// <summary>Gets or sets the sender's certificate pin, normalized when valid.</summary>
    [JsonPropertyName("trusted_cert")]
    public string? TrustedCert { get; set; }

    /// <summary>Gets or sets the partial MFA settings.</summary>
    [JsonPropertyName("mfa")]
    public DraftMfa? Mfa { get; set; }

    /// <summary>Gets or sets the partial routing policy.</summary>
    [JsonPropertyName("routes")]
    public DraftRoutes? Routes { get; set; }

    /// <summary>Gets or sets the partial DNS policy.</summary>
    [JsonPropertyName("dns")]
    public DraftDns? Dns { get; set; }

    /// <summary>
    /// Returns required fields the document did not supply, in schema order, always with username.
    /// </summary>
    /// <remarks>
    /// Defaultable fields are excluded; an explicit custom or split mode also requires its list.
    /// </remarks>
    /// <returns>The JSON paths the user must complete locally.</returns>
    public IReadOnlyList<string> Missing()
    {
        var fields = new List<string>();
        if (Id is null)
        {
            fields.Add("id");
        }
        if (Name is null)
        {
            fields.Add("name");
        }
        if (Gateway?.Host is null)
        {
            fields.Add("gateway.host");
        }
        fields.Add("username");
        if (Routes is { Mode: "custom", Include: null })
        {
            fields.Add("routes.include");
        }
        if (Dns is { Mode: "split", Domains: null })
        {
            fields.Add("dns.domains");
        }
        return fields;
    }

    /// <summary>
    /// Overlays only supplied fields onto a copy of <paramref name="baseProfile"/>, keeping its username.
    /// </summary>
    /// <remarks>
    /// Supplied lists replace the base lists entirely and are normalized. Nothing is defaulted
    /// or validated, so callers validate the completed result before saving it.
    /// </remarks>
    /// <param name="baseProfile">The profile to overlay; it is not changed.</param>
    /// <returns>The overlaid copy.</returns>
    public Profile Apply(Profile baseProfile)
    {
        ArgumentNullException.ThrowIfNull(baseProfile);
        var p = baseProfile.Clone();
        if (SchemaVersion is { } schemaVersion)
        {
            p.SchemaVersion = schemaVersion;
        }
        if (Id is not null)
        {
            p.Id = Id;
        }
        if (Name is not null)
        {
            p.Name = Name;
        }
        if (Backend is not null)
        {
            p.Backend = Backend;
        }
        if (Gateway?.Host is not null)
        {
            p.Gateway.Host = Gateway.Host;
        }
        if (Gateway?.Port is { } port)
        {
            p.Gateway.Port = port;
        }
        if (Realm is not null)
        {
            p.Realm = Realm;
        }
        if (TrustedCert is not null)
        {
            p.TrustedCert = TrustedCert;
        }
        if (Mfa is not null)
        {
            p.Mfa.Mode = Mfa.Mode ?? p.Mfa.Mode;
            p.Mfa.Digits = Mfa.Digits ?? p.Mfa.Digits;
            p.Mfa.Period = Mfa.Period ?? p.Mfa.Period;
            p.Mfa.Algorithm = Mfa.Algorithm ?? p.Mfa.Algorithm;
        }
        if (Routes is not null)
        {
            p.Routes.Mode = Routes.Mode ?? p.Routes.Mode;
            if (Routes.Include is not null)
            {
                p.Routes.Include = [.. Routes.Include.Select(ProfileRules.NormalizePrefix)];
            }
            if (Routes.Exclude is not null)
            {
                p.Routes.Exclude = [.. Routes.Exclude.Select(ProfileRules.NormalizePrefix)];
            }
            p.Routes.PreserveLan = Routes.PreserveLan ?? p.Routes.PreserveLan;
        }
        if (Dns is not null)
        {
            p.Dns.Mode = Dns.Mode ?? p.Dns.Mode;
            if (Dns.Domains is not null)
            {
                p.Dns.Domains = [.. Dns.Domains.Select(ProfileRules.NormalizeDomain)];
            }
        }
        return p;
    }

    /// <summary>
    /// Overlays supplied fields onto an existing profile while keeping its identifier and username.
    /// </summary>
    /// <remarks>
    /// Keeping the identifier means a merge can only ever update the profile the user picked.
    /// </remarks>
    /// <param name="existing">The profile being updated; it is not changed.</param>
    /// <returns>The merged copy, which still needs validation.</returns>
    public Profile Merge(Profile existing)
    {
        ArgumentNullException.ThrowIfNull(existing);
        var p = Apply(existing);
        p.Id = existing.Id;
        p.Username = existing.Username;
        return p;
    }

    /// <summary>
    /// Reports whether a validation path names a supplied field, including list elements.
    /// </summary>
    /// <param name="field">The problem's JSON path.</param>
    /// <returns>True when the draft supplied that field.</returns>
    internal bool Has(string field) => field switch
    {
        "schema_version" => SchemaVersion is not null,
        "id" => Id is not null,
        "name" => Name is not null,
        "backend" => Backend is not null,
        "gateway.host" => Gateway?.Host is not null,
        "gateway.port" => Gateway?.Port is not null,
        "realm" => Realm is not null,
        "trusted_cert" => TrustedCert is not null,
        "mfa.mode" => Mfa?.Mode is not null,
        "mfa.digits" => Mfa?.Digits is not null,
        "mfa.period" => Mfa?.Period is not null,
        "mfa.algorithm" => Mfa?.Algorithm is not null,
        "routes.mode" => Routes?.Mode is not null,
        "dns.mode" => Dns?.Mode is not null,
        _ when field == "routes.include" || field.StartsWith("routes.include[", StringComparison.Ordinal) => Routes?.Include is not null,
        _ when field == "routes.exclude" || field.StartsWith("routes.exclude[", StringComparison.Ordinal) => Routes?.Exclude is not null,
        _ when field == "dns.domains" || field.StartsWith("dns.domains[", StringComparison.Ordinal) => Dns?.Domains is not null,
        _ => false,
    };

    /// <summary>
    /// Validates with full-profile rules and keeps problems only for supplied fields.
    /// </summary>
    /// <remarks>
    /// An absent mode borrows a compatible temporary mode so supplied lists and TOTP parameters
    /// are still checked; the temporary choice never becomes a draft field or a default.
    /// </remarks>
    /// <returns>The problems for supplied fields in helper order.</returns>
    internal IReadOnlyList<ProfileFieldProblem> SuppliedProblems()
    {
        var p = Apply(new Profile { SchemaVersion = 1 });
        if (Mfa is { Mode: null } && (Mfa.Digits is not null || Mfa.Period is not null || Mfa.Algorithm is not null))
        {
            p.Mfa.Mode = "totp";
        }
        if (Routes is { Mode: null, Include: not null })
        {
            p.Routes.Mode = "custom";
        }
        if (Dns is { Mode: null, Domains: not null })
        {
            p.Dns.Mode = "split";
        }
        ProfileRules.ApplyDefaults(p);
        p = Apply(p);
        return [.. ProfileRules.Problems(p).Where(problem => Has(problem.Field))];
    }

    /// <summary>
    /// Canonicalizes supplied lists and a valid pin without filling absent fields.
    /// </summary>
    internal void Normalize()
    {
        if (Routes?.Include is not null)
        {
            Routes.Include = [.. Routes.Include.Select(ProfileRules.NormalizePrefix)];
        }
        if (Routes?.Exclude is not null)
        {
            Routes.Exclude = [.. Routes.Exclude.Select(ProfileRules.NormalizePrefix)];
        }
        if (Dns?.Domains is not null)
        {
            Dns.Domains = [.. Dns.Domains.Select(ProfileRules.NormalizeDomain)];
        }
        if (TrustedCert is not null && ProfileRules.NormalizedPin(TrustedCert) is { } pin)
        {
            TrustedCert = pin;
        }
    }

    /// <summary>
    /// Builds the draft that represents a validated profile, without any personal field.
    /// </summary>
    /// <param name="p">The profile to represent.</param>
    /// <returns>A draft whose empty optional strings and absent lists stay omitted.</returns>
    internal static ProfileDraft FromProfile(Profile p) => new()
    {
        SchemaVersion = p.SchemaVersion,
        Id = p.Id,
        Name = p.Name,
        Backend = string.IsNullOrEmpty(p.Backend) ? null : p.Backend,
        Gateway = new DraftGateway { Host = p.Gateway.Host, Port = p.Gateway.Port },
        Realm = string.IsNullOrEmpty(p.Realm) ? null : p.Realm,
        TrustedCert = string.IsNullOrEmpty(p.TrustedCert) ? null : p.TrustedCert,
        Mfa = new DraftMfa { Mode = p.Mfa.Mode, Digits = p.Mfa.Digits, Period = p.Mfa.Period, Algorithm = p.Mfa.Algorithm },
        Routes = new DraftRoutes
        {
            Mode = p.Routes.Mode,
            Include = p.Routes.Include is null ? null : [.. p.Routes.Include],
            Exclude = p.Routes.Exclude is null ? null : [.. p.Routes.Exclude],
            PreserveLan = p.Routes.PreserveLan,
        },
        Dns = new DraftDns { Mode = p.Dns.Mode, Domains = p.Dns.Domains is null ? null : [.. p.Dns.Domains] },
    };
}

/// <summary>
/// A partial gateway; an absent host must be completed locally and an absent port defaults to 443.
/// </summary>
public sealed class DraftGateway
{
    /// <summary>Gets or sets the gateway host.</summary>
    [JsonPropertyName("host")]
    public string? Host { get; set; }

    /// <summary>Gets or sets the TLS port.</summary>
    [JsonPropertyName("port")]
    public long? Port { get; set; }
}

/// <summary>
/// Partial MFA settings with each TOTP parameter independent.
/// </summary>
public sealed class DraftMfa
{
    /// <summary>Gets or sets the second-factor mode.</summary>
    [JsonPropertyName("mode")]
    public string? Mode { get; set; }

    /// <summary>Gets or sets the TOTP response length.</summary>
    [JsonPropertyName("digits")]
    public long? Digits { get; set; }

    /// <summary>Gets or sets the TOTP interval in seconds.</summary>
    [JsonPropertyName("period")]
    public long? Period { get; set; }

    /// <summary>Gets or sets the TOTP hash name.</summary>
    [JsonPropertyName("algorithm")]
    public string? Algorithm { get; set; }
}

/// <summary>
/// Partial routing policy; a supplied list replaces the base list, even when empty.
/// </summary>
public sealed class DraftRoutes
{
    /// <summary>Gets or sets the routing mode.</summary>
    [JsonPropertyName("mode")]
    public string? Mode { get; set; }

    /// <summary>Gets or sets the complete requested prefix list.</summary>
    [JsonPropertyName("include")]
    public List<string>? Include { get; set; }

    /// <summary>Gets or sets the complete excluded prefix list.</summary>
    [JsonPropertyName("exclude")]
    public List<string>? Exclude { get; set; }

    /// <summary>Gets or sets local network preservation; explicit false is kept.</summary>
    [JsonPropertyName("preserve_lan")]
    public bool? PreserveLan { get; set; }
}

/// <summary>
/// Partial DNS policy; a supplied domain list replaces the base list.
/// </summary>
public sealed class DraftDns
{
    /// <summary>Gets or sets the DNS mode.</summary>
    [JsonPropertyName("mode")]
    public string? Mode { get; set; }

    /// <summary>Gets or sets the complete split DNS domain list.</summary>
    [JsonPropertyName("domains")]
    public List<string>? Domains { get; set; }
}
