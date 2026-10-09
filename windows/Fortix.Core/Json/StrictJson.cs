using System.Text.Json;
using System.Text.Unicode;

namespace Fortix.Core.Json;

/// <summary>
/// Structural checks that run before typed decoding, mirroring the helper's protocol decoder.
/// </summary>
/// <remarks>
/// Typed deserializers accept duplicate keys and nulls silently, which would let an ambiguous
/// record mean different things to the helper and to this client. These checks reject them.
/// </remarks>
internal static class StrictJson
{
    /// <summary>
    /// The deepest value nesting the helper accepts; the top-level object's members are depth 1.
    /// </summary>
    internal const int MaxDepth = 32;

    /// <summary>
    /// Reports whether <paramref name="data"/> is one UTF-8 JSON object with only allowed
    /// top-level keys, no duplicate keys at any depth, no nulls, and nesting of at most 32.
    /// </summary>
    /// <param name="data">The record without its terminating newline.</param>
    /// <param name="allowed">The exact, case-sensitive top-level key spellings.</param>
    /// <returns>True when the record is structurally unambiguous.</returns>
    internal static bool IsStrictObject(ReadOnlySpan<byte> data, IReadOnlySet<string> allowed)
    {
        if (!Utf8.IsValid(data))
        {
            return false;
        }
        try
        {
            var reader = new Utf8JsonReader(data, new JsonReaderOptions { MaxDepth = MaxDepth + 2 });
            if (!reader.Read() || reader.TokenType != JsonTokenType.StartObject)
            {
                return false;
            }
            var keys = new Stack<HashSet<string>>();
            keys.Push(new HashSet<string>(StringComparer.Ordinal));
            while (keys.Count > 0)
            {
                if (!reader.Read())
                {
                    return false;
                }
                switch (reader.TokenType)
                {
                    case JsonTokenType.PropertyName:
                        var key = reader.GetString()!;
                        if (!keys.Peek().Add(key) || (keys.Count == 1 && reader.CurrentDepth == 1 && !allowed.Contains(key)))
                        {
                            return false;
                        }
                        break;
                    case JsonTokenType.Null:
                        return false;
                    case JsonTokenType.StartObject:
                        if (reader.CurrentDepth > MaxDepth)
                        {
                            return false;
                        }
                        keys.Push(new HashSet<string>(StringComparer.Ordinal));
                        break;
                    case JsonTokenType.StartArray:
                        if (reader.CurrentDepth > MaxDepth)
                        {
                            return false;
                        }
                        // Arrays carry no keys; a null set keeps the stack aligned with nesting.
                        keys.Push(null!);
                        break;
                    case JsonTokenType.EndObject:
                    case JsonTokenType.EndArray:
                        keys.Pop();
                        break;
                    default:
                        if (reader.CurrentDepth > MaxDepth)
                        {
                            return false;
                        }
                        break;
                }
            }
            return IsWhitespace(data[(int)reader.BytesConsumed..]);
        }
        catch (JsonException)
        {
            return false;
        }
        catch (InvalidOperationException)
        {
            // Invalid escapes such as lone surrogates surface from GetString.
            return false;
        }
    }

    /// <summary>
    /// Reports whether <paramref name="rest"/> holds only the four JSON whitespace bytes.
    /// </summary>
    /// <param name="rest">The bytes after the first complete value.</param>
    /// <returns>True when nothing but whitespace remains.</returns>
    internal static bool IsWhitespace(ReadOnlySpan<byte> rest)
    {
        foreach (var b in rest)
        {
            if (b is not ((byte)' ' or (byte)'\t' or (byte)'\n' or (byte)'\r'))
            {
                return false;
            }
        }
        return true;
    }
}
