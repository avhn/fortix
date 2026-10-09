using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using System.Text.Unicode;
using Fortix.Core.Json;

namespace Fortix.Core.Profiles;

/// <summary>
/// Identifies a rejected shared document without including any supplied value.
/// </summary>
/// <remarks>
/// Kind is json, size, format, version, count, field, duplicate_key, duplicate_id, or secret.
/// Invalid supplied profile values raise <see cref="ProfileValidationException"/> instead.
/// </remarks>
public sealed class ShareException : Exception
{
    /// <summary>
    /// Creates a failure from fixed strings.
    /// </summary>
    /// <param name="kind">The stable failure category.</param>
    /// <param name="field">A schema path or forbidden key name, never a supplied value.</param>
    /// <param name="message">A fixed explanation.</param>
    public ShareException(string kind, string field, string message)
        : base(field + ": " + message)
    {
        Kind = kind;
        Field = field;
        Detail = message;
    }

    /// <summary>Gets the stable failure category.</summary>
    public string Kind { get; }

    /// <summary>Gets the schema path or forbidden key name.</summary>
    public string Field { get; }

    /// <summary>Gets the fixed explanation without the field prefix.</summary>
    public string Detail { get; }
}

/// <summary>
/// Reads and writes the secret-free fortix-profile exchange format, version 1.
/// </summary>
/// <remarks>
/// Documents are at most 1 MiB with 1 to 32 profiles and never contain usernames or
/// passwords. Export output is byte-identical to the helper's own export.
/// </remarks>
public static class SharedProfiles
{
    /// <summary>The largest accepted document, including whitespace.</summary>
    public const int MaxBytes = 1 << 20;

    /// <summary>The largest number of profiles in one document.</summary>
    public const int MaxProfiles = 32;

    /// <summary>
    /// Credential-like keys rejected anywhere in a document, compared in lowercase.
    /// </summary>
    private static readonly HashSet<string> SecretKeys = new(StringComparer.Ordinal)
    {
        "password", "passwd", "credential", "credentials", "secret", "token", "otp", "cookie", "svpncookie",
    };

    /// <summary>
    /// The top-level document keys.
    /// </summary>
    private static readonly HashSet<string> DocumentFields = new(StringComparer.Ordinal) { "format", "version", "profiles" };

    /// <summary>
    /// Parses a document and returns 1 to 32 normalized, validated partial drafts.
    /// </summary>
    /// <remarks>
    /// A raw token pass rejects secret-like keys at any depth before schema checks and never
    /// echoes values. Unknown keys, nulls, duplicate keys or IDs, and invalid supplied fields
    /// fail; absent fields stay absent and are reported by <see cref="ProfileDraft.Missing"/>.
    /// </remarks>
    /// <param name="data">The UTF-8 document.</param>
    /// <returns>The drafts in document order.</returns>
    /// <exception cref="ShareException">The document is rejected.</exception>
    /// <exception cref="ProfileValidationException">A supplied field is invalid.</exception>
    public static IReadOnlyList<ProfileDraft> Parse(ReadOnlySpan<byte> data)
    {
        if (data.Length > MaxBytes)
        {
            throw new ShareException("size", "$", "exceeds 1 MiB limit");
        }
        if (!Utf8.IsValid(data))
        {
            throw new ShareException("json", "$", "invalid UTF-8");
        }
        Scan(data);
        using var document = JsonDocument.Parse(data.ToArray(), new JsonDocumentOptions { MaxDepth = 10000 });
        var root = document.RootElement;
        CheckObject(root, DocumentFields, nested: false);
        var hasProfiles = root.TryGetProperty("profiles", out var profilesElement);
        if (hasProfiles && profilesElement.ValueKind != JsonValueKind.Array)
        {
            throw new ShareException("json", "$", "invalid document field type");
        }
        if (!root.TryGetProperty("format", out var format) || format.ValueKind != JsonValueKind.String || format.GetString() != "fortix-profile")
        {
            throw new ShareException("format", "format", "must be fortix-profile");
        }
        if (!root.TryGetProperty("version", out var version) || version.ValueKind != JsonValueKind.Number || !version.TryGetInt64(out var number) || number != 1)
        {
            throw new ShareException("version", "version", "must be 1");
        }
        var count = hasProfiles ? profilesElement.GetArrayLength() : 0;
        if (count is < 1 or > MaxProfiles)
        {
            throw new ShareException("count", "profiles", "must contain 1..32 profiles");
        }
        var drafts = new List<ProfileDraft>(count);
        var seen = new HashSet<string>(StringComparer.Ordinal);
        foreach (var entry in profilesElement.EnumerateArray())
        {
            CheckObject(entry, ProfileCodec.ObjectFields["$"], nested: true);
            ProfileDraft draft;
            try
            {
                draft = entry.Deserialize(CoreJsonContext.Default.ProfileDraft)!;
            }
            catch (Exception e) when (e is JsonException or InvalidOperationException)
            {
                throw new ShareException("json", "profiles", "invalid profile field type");
            }
            draft.Normalize();
            var problems = draft.SuppliedProblems();
            if (problems.Count > 0)
            {
                throw new ProfileValidationException(problems);
            }
            if (draft.Id is not null && !seen.Add(draft.Id))
            {
                throw new ShareException("duplicate_id", "profiles.id", "duplicate profile id");
            }
            drafts.Add(draft);
        }
        return drafts;
    }

    /// <summary>
    /// Validates normalized copies and returns indented JSON with a final newline.
    /// </summary>
    /// <remarks>
    /// Order and per-profile schema versions are preserved, route prefixes and domains are
    /// canonicalized, and username is never written. Defaults are not applied, so callers
    /// export stored profiles, which the helper has already completed.
    /// </remarks>
    /// <param name="profiles">The profiles to export; they are not changed.</param>
    /// <returns>The UTF-8 document.</returns>
    /// <exception cref="ShareException">Count, duplicate, or size limits fail.</exception>
    /// <exception cref="ProfileValidationException">A profile is invalid.</exception>
    public static byte[] Export(IReadOnlyList<Profile> profiles)
    {
        ArgumentNullException.ThrowIfNull(profiles);
        if (profiles.Count is < 1 or > MaxProfiles)
        {
            throw new ShareException("count", "profiles", "must contain 1..32 profiles");
        }
        var entries = new JsonArray();
        var seen = new HashSet<string>(StringComparer.Ordinal);
        foreach (var original in profiles)
        {
            // Normalize a private copy so export never changes the caller's lists or pin.
            var p = ProfileDraft.FromProfile(original).Apply(original);
            var problems = ProfileRules.Validate(p);
            if (problems.Count > 0)
            {
                throw new ProfileValidationException(problems);
            }
            if (!seen.Add(p.Id))
            {
                throw new ShareException("duplicate_id", "profiles.id", "duplicate profile id");
            }
            entries.Add((JsonNode)ToNode(ProfileDraft.FromProfile(p)));
        }
        var document = new JsonObject
        {
            ["format"] = "fortix-profile",
            ["version"] = JsonValue.Create(1L),
            ["profiles"] = entries,
        };
        var data = Encoding.UTF8.GetBytes(GoJson.Indent(document) + "\n");
        if (data.Length > MaxBytes)
        {
            throw new ShareException("size", "$", "exceeds 1 MiB limit");
        }
        return data;
    }

    /// <summary>
    /// Completes a draft with defaults, schema version 1, and local username and id overrides.
    /// </summary>
    /// <remarks>
    /// Explicit invalid draft values are never replaced by defaults. A non-empty
    /// <paramref name="id"/> overrides the shared id; an empty one keeps it.
    /// </remarks>
    /// <param name="draft">The parsed draft; it is not changed.</param>
    /// <param name="username">The local username, or empty to leave it unset.</param>
    /// <param name="id">The local identifier, or empty to keep the shared one.</param>
    /// <returns>The validated profile.</returns>
    /// <exception cref="ProfileValidationException">The completed profile is invalid.</exception>
    public static Profile Complete(ProfileDraft draft, string username, string id)
    {
        ArgumentNullException.ThrowIfNull(draft);
        var p = draft.Apply(new Profile { SchemaVersion = 1 });
        ProfileRules.ApplyDefaults(p);
        // Reapply after defaulting so explicit zero ports and empty modes stay invalid.
        p = draft.Apply(p);
        if (!string.IsNullOrEmpty(username))
        {
            p.Username = username;
        }
        if (!string.IsNullOrEmpty(id))
        {
            p.Id = id;
        }
        var problems = ProfileRules.Validate(p);
        if (problems.Count > 0)
        {
            throw new ProfileValidationException(problems);
        }
        return p;
    }

    /// <summary>
    /// Builds an ordered node for one draft in schema order, omitting absent fields.
    /// </summary>
    /// <param name="d">The draft built from a validated profile.</param>
    /// <returns>The ordered object node.</returns>
    private static JsonObject ToNode(ProfileDraft d)
    {
        var node = new JsonObject
        {
            ["schema_version"] = JsonValue.Create(d.SchemaVersion!.Value),
            ["id"] = d.Id,
            ["name"] = d.Name,
        };
        if (d.Backend is not null)
        {
            node["backend"] = d.Backend;
        }
        node["gateway"] = new JsonObject { ["host"] = d.Gateway!.Host, ["port"] = JsonValue.Create(d.Gateway.Port!.Value) };
        if (d.Realm is not null)
        {
            node["realm"] = d.Realm;
        }
        if (d.TrustedCert is not null)
        {
            node["trusted_cert"] = d.TrustedCert;
        }
        var mfa = new JsonObject { ["mode"] = d.Mfa!.Mode };
        if (d.Mfa.Digits is { } digits)
        {
            mfa["digits"] = JsonValue.Create(digits);
        }
        if (d.Mfa.Period is { } period)
        {
            mfa["period"] = JsonValue.Create(period);
        }
        if (d.Mfa.Algorithm is not null)
        {
            mfa["algorithm"] = d.Mfa.Algorithm;
        }
        node["mfa"] = mfa;
        var routes = new JsonObject { ["mode"] = d.Routes!.Mode };
        if (d.Routes.Include is not null)
        {
            routes["include"] = new JsonArray([.. d.Routes.Include.Select(value => (JsonNode)JsonValue.Create(value))]);
        }
        if (d.Routes.Exclude is not null)
        {
            routes["exclude"] = new JsonArray([.. d.Routes.Exclude.Select(value => (JsonNode)JsonValue.Create(value))]);
        }
        if (d.Routes.PreserveLan is { } preserveLan)
        {
            routes["preserve_lan"] = preserveLan;
        }
        node["routes"] = routes;
        var dns = new JsonObject { ["mode"] = d.Dns!.Mode };
        if (d.Dns.Domains is not null)
        {
            dns["domains"] = new JsonArray([.. d.Dns.Domains.Select(value => (JsonNode)JsonValue.Create(value))]);
        }
        node["dns"] = dns;
        return node;
    }

    /// <summary>
    /// Scans raw tokens before any typed decoding, including inside unknown objects.
    /// </summary>
    /// <remarks>
    /// Secret keys take precedence over a remembered duplicate key or null, so an overwritten
    /// object cannot hide a credential. Syntax errors and trailing data fail first.
    /// </remarks>
    /// <param name="data">Valid UTF-8 input.</param>
    private static void Scan(ReadOnlySpan<byte> data)
    {
        ShareException? problem = null;
        var reader = new Utf8JsonReader(data, new JsonReaderOptions { MaxDepth = 10000 });
        try
        {
            var keys = new Stack<HashSet<string>?>();
            do
            {
                if (!reader.Read())
                {
                    throw new ShareException("json", "$", "invalid JSON");
                }
                switch (reader.TokenType)
                {
                    case JsonTokenType.PropertyName:
                        var key = reader.GetString()!;
                        var lower = key.ToLowerInvariant();
                        if (SecretKeys.Contains(lower))
                        {
                            throw new ShareException("secret", lower, "secret fields are forbidden");
                        }
                        if (!keys.Peek()!.Add(key))
                        {
                            problem ??= new ShareException("duplicate_key", "$", "duplicate object key");
                        }
                        break;
                    case JsonTokenType.Null:
                        problem ??= new ShareException("field", "$", "null is not allowed");
                        break;
                    case JsonTokenType.StartObject:
                        keys.Push(new HashSet<string>(StringComparer.Ordinal));
                        break;
                    case JsonTokenType.StartArray:
                        keys.Push(null);
                        break;
                    case JsonTokenType.EndObject:
                    case JsonTokenType.EndArray:
                        keys.Pop();
                        break;
                }
            }
            while (keys.Count > 0);
        }
        catch (Exception e) when (e is JsonException or InvalidOperationException)
        {
            throw new ShareException("json", "$", "invalid JSON");
        }
        if (!StrictJson.IsWhitespace(data[(int)reader.BytesConsumed..]))
        {
            throw new ShareException("json", "$", "trailing data after document");
        }
        if (problem is not null)
        {
            throw problem;
        }
    }

    /// <summary>
    /// Requires an object with only allowed keys, recursing into nested profile objects.
    /// </summary>
    /// <param name="value">The element to check.</param>
    /// <param name="allowed">The exact allowed keys; username is always rejected.</param>
    /// <param name="nested">True to check gateway, mfa, routes, and dns members recursively.</param>
    private static void CheckObject(JsonElement value, IReadOnlySet<string> allowed, bool nested)
    {
        if (value.ValueKind != JsonValueKind.Object)
        {
            throw new ShareException("field", "$", "must be an object");
        }
        foreach (var member in value.EnumerateObject())
        {
            if (!allowed.Contains(member.Name) || member.Name == "username")
            {
                throw new ShareException("field", "$", "unknown field in shared configuration");
            }
            if (nested && ProfileCodec.ObjectFields.TryGetValue("$." + member.Name, out var fields))
            {
                CheckObject(member.Value, fields, nested: false);
            }
        }
    }
}
