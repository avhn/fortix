using System.Globalization;
using System.Text;
using System.Text.Json.Nodes;

namespace Fortix.Core.Json;

/// <summary>
/// Reproduces the byte output of Go's encoding/json for the values the helper hashes or exports.
/// </summary>
/// <remarks>
/// System.Text.Json escapes a different character set, so any output that must be byte
/// identical to the Go helper (credential tuples, exported share documents) goes through here.
/// </remarks>
public static class GoJson
{
    /// <summary>
    /// Returns <paramref name="text"/> as a quoted JSON string exactly as Go's json.Marshal writes it.
    /// </summary>
    /// <remarks>
    /// Go escapes quote, backslash, the short control escapes, other C0 controls as lowercase
    /// \u00xx, the HTML characters &lt; &gt; &amp;, and U+2028/U+2029; everything else stays raw
    /// UTF-8. A lone surrogate becomes a raw U+FFFD, which is what the helper sees after Go
    /// decodes the same text, so hashes computed here match hashes computed there.
    /// </remarks>
    /// <param name="text">The string to quote.</param>
    /// <returns>The quoted JSON string.</returns>
    public static string Quote(string text)
    {
        ArgumentNullException.ThrowIfNull(text);
        var output = new StringBuilder(text.Length + 2);
        AppendQuoted(output, text);
        return output.ToString();
    }

    /// <summary>
    /// Appends <paramref name="text"/> to <paramref name="output"/> as a Go-escaped JSON string.
    /// </summary>
    /// <param name="output">The destination builder.</param>
    /// <param name="text">The string to quote.</param>
    internal static void AppendQuoted(StringBuilder output, string text)
    {
        output.Append('"');
        foreach (var rune in text.EnumerateRunes())
        {
            // EnumerateRunes already maps lone surrogates to U+FFFD.
            switch (rune.Value)
            {
                case '"': output.Append("\\\""); break;
                case '\\': output.Append("\\\\"); break;
                case '\b': output.Append("\\b"); break;
                case '\f': output.Append("\\f"); break;
                case '\n': output.Append("\\n"); break;
                case '\r': output.Append("\\r"); break;
                case '\t': output.Append("\\t"); break;
                case < 0x20 or '<' or '>' or '&' or 0x2028 or 0x2029:
                    output.Append("\\u").Append(rune.Value.ToString("x4", CultureInfo.InvariantCulture));
                    break;
                default:
                    output.Append(rune.ToString());
                    break;
            }
        }
        output.Append('"');
    }

    /// <summary>
    /// Writes <paramref name="node"/> the way Go's json.MarshalIndent does with a two-space indent.
    /// </summary>
    /// <remarks>
    /// Only strings, integers, booleans, arrays and objects are supported, which covers every
    /// share document field. Empty arrays and objects are written as [] and {} like Go.
    /// </remarks>
    /// <param name="node">The ordered document to write; members keep insertion order.</param>
    /// <returns>The indented JSON text without a trailing newline.</returns>
    public static string Indent(JsonNode node)
    {
        ArgumentNullException.ThrowIfNull(node);
        var output = new StringBuilder();
        Write(output, node, 0);
        return output.ToString();
    }

    /// <summary>
    /// Writes one node at the given nesting depth.
    /// </summary>
    /// <param name="output">The destination builder.</param>
    /// <param name="node">The node to write.</param>
    /// <param name="depth">The current nesting depth used for indentation.</param>
    private static void Write(StringBuilder output, JsonNode node, int depth)
    {
        switch (node)
        {
            case JsonObject members:
                if (members.Count == 0)
                {
                    output.Append("{}");
                    return;
                }
                output.Append('{');
                var firstMember = true;
                foreach (var (key, value) in members)
                {
                    output.Append(firstMember ? "\n" : ",\n");
                    firstMember = false;
                    output.Append(' ', (depth + 1) * 2);
                    AppendQuoted(output, key);
                    output.Append(": ");
                    Write(output, value ?? throw new ArgumentException("null values are not supported", nameof(node)), depth + 1);
                }
                output.Append('\n').Append(' ', depth * 2).Append('}');
                return;
            case JsonArray items:
                if (items.Count == 0)
                {
                    output.Append("[]");
                    return;
                }
                output.Append('[');
                var firstItem = true;
                foreach (var item in items)
                {
                    output.Append(firstItem ? "\n" : ",\n");
                    firstItem = false;
                    output.Append(' ', (depth + 1) * 2);
                    Write(output, item ?? throw new ArgumentException("null values are not supported", nameof(node)), depth + 1);
                }
                output.Append('\n').Append(' ', depth * 2).Append(']');
                return;
            case JsonValue value when value.TryGetValue(out string? text):
                AppendQuoted(output, text);
                return;
            case JsonValue value when value.TryGetValue(out bool flag):
                output.Append(flag ? "true" : "false");
                return;
            case JsonValue value when value.TryGetValue(out long number):
                output.Append(number.ToString(CultureInfo.InvariantCulture));
                return;
            default:
                throw new ArgumentException("unsupported JSON value", nameof(node));
        }
    }
}
