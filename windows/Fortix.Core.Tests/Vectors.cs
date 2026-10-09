using System.Text.Json;
using System.Text.Json.Nodes;

namespace Fortix.Core.Tests;

/// <summary>
/// Loads the golden vectors the Go helper generates under testdata/interop.
/// </summary>
internal static class Vectors
{
    /// <summary>
    /// Parses one vector file copied next to the test assembly.
    /// </summary>
    /// <param name="name">The file name, such as protocol-frames.json.</param>
    /// <returns>The parsed document; the caller disposes it.</returns>
    internal static JsonDocument Load(string name) =>
        JsonDocument.Parse(File.ReadAllBytes(Path.Combine(AppContext.BaseDirectory, "interop", name)));

    /// <summary>
    /// Returns the named entries of an array, keyed by their name member.
    /// </summary>
    /// <param name="file">The vector file name.</param>
    /// <param name="path">Member names leading to the array; empty for a top-level array.</param>
    /// <returns>The entry names in file order.</returns>
    internal static TheoryData<string> Names(string file, params string[] path)
    {
        using var document = Load(file);
        var data = new TheoryData<string>();
        foreach (var entry in Array(document.RootElement, path).EnumerateArray())
        {
            data.Add(entry.GetProperty("name").GetString()!);
        }
        return data;
    }

    /// <summary>
    /// Returns a detached copy of the entry with the given name.
    /// </summary>
    /// <param name="file">The vector file name.</param>
    /// <param name="name">The entry name.</param>
    /// <param name="path">Member names leading to the array; empty for a top-level array.</param>
    /// <returns>The entry element, valid after the document is disposed.</returns>
    internal static JsonElement Entry(string file, string name, params string[] path)
    {
        using var document = Load(file);
        return Array(document.RootElement, path).EnumerateArray().Single(entry => entry.GetProperty("name").GetString() == name).Clone();
    }

    /// <summary>
    /// Compares two JSON values structurally, ignoring member order and formatting.
    /// </summary>
    /// <param name="expected">The expected JSON text or element.</param>
    /// <param name="actual">The actual JSON text.</param>
    /// <returns>True when both describe the same value.</returns>
    internal static bool SameJson(string expected, string actual) =>
        JsonNode.DeepEquals(JsonNode.Parse(expected), JsonNode.Parse(actual));

    /// <summary>
    /// Follows member names from a root element to an array.
    /// </summary>
    /// <param name="root">The document root.</param>
    /// <param name="path">The member names.</param>
    /// <returns>The array element.</returns>
    private static JsonElement Array(JsonElement root, string[] path)
    {
        foreach (var member in path)
        {
            root = root.GetProperty(member);
        }
        return root;
    }
}
