using System.Globalization;
using System.Text;
using System.Text.Json;
using System.Text.Unicode;
using Fortix.Core.Json;

namespace Fortix.Core.Profiles;

/// <summary>
/// Thrown when profile JSON is malformed or ambiguous before any field is validated.
/// </summary>
/// <remarks>
/// Messages for unknown fields, duplicate keys, nulls, size, encoding, top-level shape, and
/// trailing data match the helper exactly; syntax and type errors use fixed wording instead.
/// </remarks>
public sealed class ProfileDecodeException : Exception
{
    /// <summary>
    /// Creates an exception with a fixed message that never includes field values.
    /// </summary>
    /// <param name="message">The failure description.</param>
    public ProfileDecodeException(string message)
        : base(message)
    {
    }
}

/// <summary>
/// Strict profile decoding and helper-compatible encoding.
/// </summary>
public static class ProfileCodec
{
    /// <summary>The largest accepted profile document, including whitespace.</summary>
    public const int MaxBytes = 64 * 1024;

    /// <summary>
    /// Exact field spellings per schema object; case variants are unknown fields.
    /// </summary>
    internal static readonly IReadOnlyDictionary<string, IReadOnlySet<string>> ObjectFields = new Dictionary<string, IReadOnlySet<string>>
    {
        ["$"] = new HashSet<string>(StringComparer.Ordinal) { "schema_version", "id", "name", "backend", "gateway", "realm", "username", "trusted_cert", "mfa", "routes", "dns" },
        ["$.gateway"] = new HashSet<string>(StringComparer.Ordinal) { "host", "port" },
        ["$.mfa"] = new HashSet<string>(StringComparer.Ordinal) { "mode", "digits", "period", "algorithm" },
        ["$.routes"] = new HashSet<string>(StringComparer.Ordinal) { "mode", "include", "exclude", "preserve_lan" },
        ["$.dns"] = new HashSet<string>(StringComparer.Ordinal) { "mode", "domains" },
    };

    /// <summary>
    /// Decodes, defaults, and validates one profile document exactly as the helper does.
    /// </summary>
    /// <param name="data">At most 64 KiB of UTF-8 JSON.</param>
    /// <returns>The defaulted, validated profile with a normalized certificate pin.</returns>
    /// <exception cref="ProfileDecodeException">The document is malformed or ambiguous.</exception>
    /// <exception cref="ProfileValidationException">One or more fields are invalid.</exception>
    public static Profile Decode(ReadOnlySpan<byte> data)
    {
        if (data.Length > MaxBytes)
        {
            throw new ProfileDecodeException("profile: exceeds 64 KiB limit");
        }
        if (!Utf8.IsValid(data))
        {
            throw new ProfileDecodeException("profile: invalid UTF-8");
        }
        Walk(data);
        Profile profile;
        try
        {
            profile = JsonSerializer.Deserialize(data, CoreJsonContext.Default.Profile)
                ?? throw new ProfileDecodeException("profile: top level must be an object");
        }
        catch (JsonException)
        {
            throw new ProfileDecodeException("decode profile: invalid field type");
        }
        catch (InvalidOperationException)
        {
            throw new ProfileDecodeException("decode profile: invalid field type");
        }
        ProfileRules.ApplyDefaults(profile);
        var problems = ProfileRules.Validate(profile);
        if (problems.Count > 0)
        {
            throw new ProfileValidationException(problems);
        }
        return profile;
    }

    /// <summary>
    /// Encodes a profile for profile.put the way the helper's own encoder would.
    /// </summary>
    /// <remarks>
    /// Empty optional strings and empty lists are omitted, matching the helper's omitempty
    /// fields, and absent values are omitted rather than written as null, which it rejects.
    /// </remarks>
    /// <param name="profile">The profile to encode.</param>
    /// <returns>Compact UTF-8 JSON.</returns>
    public static byte[] Encode(Profile profile)
    {
        ArgumentNullException.ThrowIfNull(profile);
        return JsonSerializer.SerializeToUtf8Bytes(ForWire(profile), CoreJsonContext.Wire.Profile);
    }

    /// <summary>
    /// Returns a copy with omitempty fields cleared to null so they are left out of the JSON.
    /// </summary>
    /// <param name="profile">The profile to copy.</param>
    /// <returns>The wire-ready copy.</returns>
    internal static Profile ForWire(Profile profile)
    {
        var copy = profile.Clone();
        copy.Backend = string.IsNullOrEmpty(copy.Backend) ? null : copy.Backend;
        copy.Realm = string.IsNullOrEmpty(copy.Realm) ? null : copy.Realm;
        copy.TrustedCert = string.IsNullOrEmpty(copy.TrustedCert) ? null : copy.TrustedCert;
        copy.Routes.Include = copy.Routes.Include is { Count: > 0 } ? copy.Routes.Include : null;
        copy.Routes.Exclude = copy.Routes.Exclude is { Count: > 0 } ? copy.Routes.Exclude : null;
        copy.Dns.Domains = copy.Dns.Domains is { Count: > 0 } ? copy.Dns.Domains : null;
        return copy;
    }

    /// <summary>
    /// Walks every token, checking exact keys at schema paths, duplicates, nulls, and trailing data.
    /// </summary>
    /// <param name="data">Valid UTF-8 input.</param>
    private static void Walk(ReadOnlySpan<byte> data)
    {
        if (StrictJson.IsWhitespace(data))
        {
            throw new ProfileDecodeException("decode profile: EOF");
        }
        var reader = new Utf8JsonReader(data, new JsonReaderOptions { MaxDepth = 10000 });
        try
        {
            if (!reader.Read())
            {
                throw new ProfileDecodeException("decode profile: EOF");
            }
            if (reader.TokenType != JsonTokenType.StartObject)
            {
                throw new ProfileDecodeException("profile: top level must be an object");
            }
            WalkObject(ref reader, "$");
        }
        catch (JsonException)
        {
            throw new ProfileDecodeException("decode profile: invalid JSON");
        }
        catch (InvalidOperationException)
        {
            throw new ProfileDecodeException("decode profile: invalid JSON");
        }
        if (!StrictJson.IsWhitespace(data[(int)reader.BytesConsumed..]))
        {
            throw new ProfileDecodeException("profile: trailing data after object");
        }
    }

    /// <summary>
    /// Consumes an opened object, failing on the first duplicate or unknown key at path.
    /// </summary>
    /// <param name="reader">A reader positioned on StartObject.</param>
    /// <param name="path">The JSON path of the object.</param>
    private static void WalkObject(ref Utf8JsonReader reader, string path)
    {
        var seen = new HashSet<string>(StringComparer.Ordinal);
        ObjectFields.TryGetValue(path, out var fields);
        while (reader.Read() && reader.TokenType != JsonTokenType.EndObject)
        {
            var key = reader.GetString()!;
            if (!seen.Add(key))
            {
                throw new ProfileDecodeException($"{path}.{key}: duplicate key");
            }
            if (fields is not null && !fields.Contains(key))
            {
                throw new ProfileDecodeException($"{path}: unknown field {GoQuote(key)}");
            }
            reader.Read();
            WalkValue(ref reader, path + "." + key);
        }
    }

    /// <summary>
    /// Consumes one value at path, recursing into objects and arrays and rejecting null.
    /// </summary>
    /// <param name="reader">A reader positioned on the value's first token.</param>
    /// <param name="path">The JSON path of the value.</param>
    private static void WalkValue(ref Utf8JsonReader reader, string path)
    {
        switch (reader.TokenType)
        {
            case JsonTokenType.Null:
                throw new ProfileDecodeException(path + ": null is not allowed");
            case JsonTokenType.StartObject:
                WalkObject(ref reader, path);
                break;
            case JsonTokenType.StartArray:
                for (var i = 0; reader.Read() && reader.TokenType != JsonTokenType.EndArray; i++)
                {
                    WalkValue(ref reader, $"{path}[{i.ToString(CultureInfo.InvariantCulture)}]");
                }
                break;
        }
    }

    /// <summary>
    /// Quotes a key the way Go's %q verb does, so unknown-field messages match the helper.
    /// </summary>
    /// <param name="text">The key to quote.</param>
    /// <returns>The double-quoted, escaped key.</returns>
    internal static string GoQuote(string text)
    {
        var output = new StringBuilder("\"");
        foreach (var rune in text.EnumerateRunes())
        {
            switch (rune.Value)
            {
                case '"': output.Append("\\\""); break;
                case '\\': output.Append("\\\\"); break;
                case '\a': output.Append("\\a"); break;
                case '\b': output.Append("\\b"); break;
                case '\f': output.Append("\\f"); break;
                case '\n': output.Append("\\n"); break;
                case '\r': output.Append("\\r"); break;
                case '\t': output.Append("\\t"); break;
                case '\v': output.Append("\\v"); break;
                default:
                    if (IsGoPrintable(rune))
                    {
                        output.Append(rune.ToString());
                    }
                    else if (rune.Value < 0x80)
                    {
                        output.Append("\\x").Append(rune.Value.ToString("x2", CultureInfo.InvariantCulture));
                    }
                    else if (rune.Value <= 0xFFFF)
                    {
                        output.Append("\\u").Append(rune.Value.ToString("x4", CultureInfo.InvariantCulture));
                    }
                    else
                    {
                        output.Append("\\U").Append(rune.Value.ToString("x8", CultureInfo.InvariantCulture));
                    }
                    break;
            }
        }
        return output.Append('"').ToString();
    }

    /// <summary>
    /// Approximates Go's unicode.IsPrint: letters, marks, numbers, punctuation, symbols, and ASCII space.
    /// </summary>
    /// <param name="rune">The code point to classify.</param>
    /// <returns>True when Go prints the code point unescaped.</returns>
    private static bool IsGoPrintable(Rune rune)
    {
        if (rune.Value == ' ')
        {
            return true;
        }
        return Rune.GetUnicodeCategory(rune) switch
        {
            UnicodeCategory.SpaceSeparator or UnicodeCategory.LineSeparator or UnicodeCategory.ParagraphSeparator
                or UnicodeCategory.Control or UnicodeCategory.Format or UnicodeCategory.Surrogate
                or UnicodeCategory.PrivateUse or UnicodeCategory.OtherNotAssigned => false,
            _ => true,
        };
    }
}
