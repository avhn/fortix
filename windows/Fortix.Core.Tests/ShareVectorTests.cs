using System.Text;
using System.Text.Json;
using Fortix.Core.Json;
using Fortix.Core.Profiles;

namespace Fortix.Core.Tests;

/// <summary>
/// Checks share export, parsing, and completion against the Go helper's results.
/// </summary>
public sealed class ShareVectorTests
{
    /// <summary>The vector file name.</summary>
    private const string File = "share-format.json";

    /// <summary>Gets the export case names.</summary>
    public static TheoryData<string> Exports => Vectors.Names(File, "export");

    /// <summary>Gets the parse case names.</summary>
    public static TheoryData<string> Parses => Vectors.Names(File, "parse");

    /// <summary>Gets the completion case names.</summary>
    public static TheoryData<string> Completes => Vectors.Names(File, "complete");

    /// <summary>
    /// Export output is byte-identical to the helper's, or fails the same way.
    /// </summary>
    /// <param name="name">The vector name.</param>
    [Theory]
    [MemberData(nameof(Exports))]
    public void Export(string name)
    {
        var entry = Vectors.Entry(File, name, "export");
        var profiles = entry.GetProperty("profiles").EnumerateArray()
            .Select(p => p.Deserialize(CoreJsonContext.Default.Profile)!).ToList();
        var snapshot = profiles.Select(p => Encoding.UTF8.GetString(ProfileCodec.Encode(p))).ToList();
        if (entry.TryGetProperty("document", out var document))
        {
            Assert.Equal(document.GetString(), Encoding.UTF8.GetString(SharedProfiles.Export(profiles)));
        }
        else
        {
            AssertFailure(entry.GetProperty("error"), () => SharedProfiles.Export(profiles));
        }
        // Export works on copies, so the caller's profiles keep their unnormalized values.
        Assert.Equal(snapshot, profiles.Select(p => Encoding.UTF8.GetString(ProfileCodec.Encode(p))));
    }

    /// <summary>
    /// Parsing yields the same drafts and missing fields, or fails the same way.
    /// </summary>
    /// <param name="name">The vector name.</param>
    [Theory]
    [MemberData(nameof(Parses))]
    public void Parse(string name)
    {
        var entry = Vectors.Entry(File, name, "parse");
        var data = Encoding.UTF8.GetBytes(entry.GetProperty("document").GetString()!);
        if (entry.TryGetProperty("error", out var error))
        {
            AssertFailure(error, () => SharedProfiles.Parse(data));
            return;
        }
        var drafts = SharedProfiles.Parse(data);
        var expected = entry.GetProperty("drafts").EnumerateArray().ToList();
        Assert.Equal(expected.Count, drafts.Count);
        var missing = entry.GetProperty("missing").EnumerateArray().ToList();
        for (var i = 0; i < drafts.Count; i++)
        {
            var actual = JsonSerializer.Serialize(drafts[i], CoreJsonContext.Default.ProfileDraft);
            Assert.True(Vectors.SameJson(expected[i].GetRawText(), actual), actual);
            Assert.Equal(missing[i].EnumerateArray().Select(m => m.GetString()!), drafts[i].Missing());
        }
    }

    /// <summary>
    /// Completion yields the same profile, or fails the same way.
    /// </summary>
    /// <param name="name">The vector name.</param>
    [Theory]
    [MemberData(nameof(Completes))]
    public void Complete(string name)
    {
        var entry = Vectors.Entry(File, name, "complete");
        var data = Encoding.UTF8.GetBytes(entry.GetProperty("document").GetString()!);
        var username = entry.GetProperty("username").GetString()!;
        var id = entry.GetProperty("id").GetString()!;
        if (entry.TryGetProperty("error", out var error))
        {
            AssertFailure(error, () => SharedProfiles.Complete(SharedProfiles.Parse(data)[0], username, id));
            return;
        }
        var profile = SharedProfiles.Complete(SharedProfiles.Parse(data)[0], username, id);
        var actual = Encoding.UTF8.GetString(ProfileCodec.Encode(profile));
        Assert.True(Vectors.SameJson(entry.GetProperty("profile").GetRawText(), actual), actual);
    }

    /// <summary>
    /// Merging keeps the existing identifier and username while overlaying supplied fields.
    /// </summary>
    [Fact]
    public void MergeKeepsIdentity()
    {
        var existing = ProfileCodec.Decode("{\"schema_version\":1,\"id\":\"work\",\"name\":\"Work\",\"gateway\":{\"host\":\"vpn.example.com\"},\"username\":\"alice\"}"u8);
        var draft = SharedProfiles.Parse("{\"format\":\"fortix-profile\",\"version\":1,\"profiles\":[{\"id\":\"other\",\"name\":\"Office\",\"dns\":{\"mode\":\"split\",\"domains\":[\"*.Corp.example.com\"]}}]}"u8)[0];
        var merged = draft.Merge(existing);
        Assert.Equal(("work", "alice", "Office"), (merged.Id, merged.Username, merged.Name));
        Assert.Equal(["corp.example.com"], merged.Dns.Domains!);
        Assert.Equal("Work", existing.Name);
    }

    /// <summary>
    /// Oversized and non-UTF-8 documents fail before parsing.
    /// </summary>
    [Fact]
    public void SizeAndEncoding()
    {
        var e = Assert.Throws<ShareException>(() => SharedProfiles.Parse(new byte[SharedProfiles.MaxBytes + 1]));
        Assert.Equal(("size", "$", "exceeds 1 MiB limit"), (e.Kind, e.Field, e.Detail));
        e = Assert.Throws<ShareException>(() => SharedProfiles.Parse([(byte)'{', 0xc3, (byte)'}']));
        Assert.Equal(("json", "$", "invalid UTF-8"), (e.Kind, e.Field, e.Detail));
    }

    /// <summary>
    /// Asserts that an action fails with the vector's share error or validation problems.
    /// </summary>
    /// <param name="error">The vector's error object.</param>
    /// <param name="action">The failing action.</param>
    private static void AssertFailure(JsonElement error, Action action)
    {
        if (error.TryGetProperty("errors", out var errors))
        {
            var e = Assert.Throws<ProfileValidationException>(action);
            Assert.Equal(ProfileVectorTests.Problems(errors), e.Problems);
            return;
        }
        var share = Assert.Throws<ShareException>(action);
        Assert.Equal(
            (error.GetProperty("kind").GetString(), error.GetProperty("field").GetString(), error.GetProperty("message").GetString()),
            (share.Kind, share.Field, share.Detail));
    }
}
