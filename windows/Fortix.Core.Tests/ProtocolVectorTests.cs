using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using Fortix.Core.Json;
using Fortix.Core.Protocol;

namespace Fortix.Core.Tests;

/// <summary>
/// Checks request, result, and event shapes against frames the Go helper encoded.
/// </summary>
public sealed class ProtocolVectorTests
{
    /// <summary>The vector file name.</summary>
    private const string File = "protocol-frames.json";

    /// <summary>Gets the valid request names.</summary>
    public static TheoryData<string> Requests => Vectors.Names(File, "requests");

    /// <summary>Gets the invalid request names.</summary>
    public static TheoryData<string> InvalidRequests => Vectors.Names(File, "invalid_requests");

    /// <summary>Gets the result names.</summary>
    public static TheoryData<string> Results => Vectors.Names(File, "results");

    /// <summary>Gets the event names.</summary>
    public static TheoryData<string> Events => Vectors.Names(File, "events");

    /// <summary>Gets the structurally valid but semantically invalid result names.</summary>
    public static TheoryData<string> InvalidResults => Vectors.Names(File, "invalid_results");

    /// <summary>Gets the malformed record names.</summary>
    public static TheoryData<string> Malformed => Vectors.Names(File, "malformed");

    /// <summary>
    /// Limits, version, and error codes match the helper's constants.
    /// </summary>
    [Fact]
    public void ConstantsMatch()
    {
        using var document = Vectors.Load(File);
        var root = document.RootElement;
        Assert.Equal(HelperProtocol.MaxLine, root.GetProperty("max_line").GetInt32());
        Assert.Equal(HelperProtocol.Version, root.GetProperty("version").GetInt32());
        Assert.Equal(root.GetProperty("codes").EnumerateArray().Select(c => c.GetString()!), HelperErrorCodes.All);
    }

    /// <summary>
    /// Every helper-accepted request validates here and re-encodes to the same JSON value.
    /// </summary>
    /// <param name="name">The vector name.</param>
    [Theory]
    [MemberData(nameof(Requests))]
    public void RequestRoundTrips(string name)
    {
        var frame = Frame("requests", name);
        Assert.EndsWith("\n", frame, StringComparison.Ordinal);
        var request = JsonSerializer.Deserialize(frame, CoreJsonContext.Default.HelperRequest)!;
        Assert.True(request.IsValid());
        var encoded = FrameCodec.Encode(request);
        Assert.Equal((byte)'\n', encoded[^1]);
        Assert.True(Vectors.SameJson(frame, Encoding.UTF8.GetString(encoded)), Encoding.UTF8.GetString(encoded));
    }

    /// <summary>
    /// Requests the helper rejects are rejected before any byte would be written.
    /// </summary>
    /// <param name="name">The vector name.</param>
    [Theory]
    [MemberData(nameof(InvalidRequests))]
    public void InvalidRequestRejected(string name)
    {
        var request = JsonSerializer.Deserialize(Frame("invalid_requests", name), CoreJsonContext.Default.HelperRequest)!;
        Assert.False(request.IsValid());
        Assert.Throws<HelperProtocolException>(() => FrameCodec.Encode(request));
    }

    /// <summary>
    /// Every helper result decodes with all fields preserved, and typed payloads parse.
    /// </summary>
    /// <param name="name">The vector name.</param>
    [Theory]
    [MemberData(nameof(Results))]
    public void ResultDecodes(string name)
    {
        var frame = Frame("results", name);
        var result = FrameCodec.Decode(Encoding.UTF8.GetBytes(frame)).Result!;
        var node = new JsonObject { ["type"] = "result", ["id"] = result.Id, ["ok"] = result.Ok };
        if (result.Error is { } error)
        {
            node["error"] = new JsonObject { ["code"] = error.Code, ["message"] = error.Message };
        }
        if (result.Data is { } data)
        {
            node["data"] = JsonNode.Parse(data.GetRawText());
        }
        Assert.True(Vectors.SameJson(frame, node.ToJsonString()));
        switch (name)
        {
            case "hello":
                Assert.Equal(1, result.Data!.Value.Deserialize(CoreJsonContext.Default.HelloResponse)!.Protocol);
                break;
            case "up":
                Assert.Equal(ulong.MaxValue, result.Data!.Value.Deserialize(CoreJsonContext.Default.UpResponse)!.Attempt);
                break;
            case "status":
                var status = result.Data!.Value.Deserialize(CoreJsonContext.Default.ListSessionStatus)!;
                Assert.Equal(["work", "home"], status.Select(s => s.Profile));
                Assert.Equal("198.51.100.10", status[0].LocalIp);
                Assert.Equal("0001-01-01T00:00:00Z", status[1].Since);
                break;
            case "profile-list":
                Assert.Equal(2, result.Data!.Value.Deserialize(CoreJsonContext.Default.ListProfileState)!.Count);
                break;
            case "profile-get":
                Assert.Equal("work", result.Data!.Value.Deserialize(CoreJsonContext.Default.Profile)!.Id);
                break;
            case "logs":
                Assert.Equal("sanitized <&> 東京", result.Data!.Value.Deserialize(CoreJsonContext.Default.ListString)![1]);
                break;
            case "unauthorized-before-request":
                Assert.Equal("", result.Id);
                break;
        }
    }

    /// <summary>
    /// Every helper event decodes with exactly the fields of its type.
    /// </summary>
    /// <param name="name">The vector name.</param>
    [Theory]
    [MemberData(nameof(Events))]
    public void EventDecodes(string name)
    {
        var frame = Frame("events", name);
        var e = FrameCodec.Decode(Encoding.UTF8.GetBytes(frame)).Event!;
        var node = new JsonObject { ["type"] = e.Type, ["profile"] = e.Profile, ["attempt"] = e.Attempt };
        switch (e.Type)
        {
            case "state":
                node["state"] = e.State;
                node["detail"] = e.Detail;
                node["wanted"] = e.Wanted;
                node["initiated"] = e.Initiated;
                node["cleanup_pending"] = e.CleanupPending;
                if (e.Code.Length > 0)
                {
                    node["code"] = e.Code;
                }
                break;
            case "challenge":
                node["challenge_id"] = e.ChallengeId;
                node["kind"] = e.Kind;
                node["prompt"] = e.Prompt;
                break;
            case "cert":
                node["digest"] = e.Digest;
                node["subject"] = e.Subject;
                node["issuer"] = e.Issuer;
                break;
            case "log":
                node["line"] = e.Line;
                break;
        }
        Assert.True(Vectors.SameJson(frame, node.ToJsonString()));
    }

    /// <summary>
    /// Results with inconsistent ok and error fields, a missing id, or an unknown type are rejected.
    /// </summary>
    /// <param name="name">The vector name.</param>
    [Theory]
    [MemberData(nameof(InvalidResults))]
    public void InvalidResultRejected(string name)
    {
        var e = Assert.Throws<HelperProtocolException>(() => FrameCodec.Decode(Encoding.UTF8.GetBytes(Frame("invalid_results", name))));
        Assert.Contains(e.Message, new[] { "helper returned invalid result", "helper returned unknown message type" });
    }

    /// <summary>
    /// Records the helper's strict decoder rejects are rejected here with a fixed message.
    /// </summary>
    /// <param name="name">The vector name.</param>
    [Theory]
    [MemberData(nameof(Malformed))]
    public void MalformedRejected(string name)
    {
        var e = Assert.Throws<HelperProtocolException>(() => FrameCodec.Decode(Encoding.UTF8.GetBytes(Frame("malformed", name))));
        Assert.Equal("protocol: invalid object", e.Message);
    }

    /// <summary>
    /// An event missing a required field, or carrying another type's field, is rejected.
    /// </summary>
    /// <param name="frame">The record.</param>
    [Theory]
    [InlineData("{\"type\":\"log\",\"profile\":\"work\",\"attempt\":1}")]
    [InlineData("{\"type\":\"log\",\"profile\":\"work\",\"attempt\":1,\"line\":\"\",\"state\":\"connected\"}")]
    [InlineData("{\"type\":\"cert\",\"profile\":\"work\",\"attempt\":1,\"digest\":\"\",\"subject\":\"\",\"issuer\":\"\",\"code\":\"BUSY\"}")]
    [InlineData("{\"type\":\"state\",\"attempt\":1,\"state\":\"\",\"detail\":\"\",\"wanted\":true,\"initiated\":true,\"cleanup_pending\":false}")]
    [InlineData("{\"type\":\"result\",\"id\":\"1\",\"ok\":true,\"line\":\"\"}")]
    [InlineData("{\"type\":\"result\",\"id\":\"1\",\"ok\":false,\"error\":{\"code\":\"BUSY\",\"message\":\"x\",\"extra\":1}}")]
    public void InconsistentFramesRejected(string frame) =>
        Assert.Throws<HelperProtocolException>(() => FrameCodec.Decode(Encoding.UTF8.GetBytes(frame)));

    /// <summary>
    /// A record of exactly the limit including its newline decodes; one byte more is rejected.
    /// </summary>
    [Fact]
    public void RecordLimit()
    {
        var exact = PaddedResult(HelperProtocol.MaxLine);
        Assert.Equal(HelperProtocol.MaxLine, exact.Length);
        Assert.NotNull(FrameCodec.Decode(exact).Result);
        var e = Assert.Throws<HelperProtocolException>(() => FrameCodec.Decode(PaddedResult(HelperProtocol.MaxLine + 1)));
        Assert.Equal("protocol: record exceeds limit", e.Message);
    }

    /// <summary>
    /// Invalid UTF-8 is rejected before parsing.
    /// </summary>
    [Fact]
    public void InvalidUtf8Rejected()
    {
        var frame = Encoding.UTF8.GetBytes("{\"type\":\"log\",\"profile\":\"work\",\"attempt\":1,\"line\":\"x\"}\n");
        frame[Array.IndexOf(frame, (byte)'x')] = 0xff;
        Assert.Throws<HelperProtocolException>(() => FrameCodec.Decode(frame));
    }

    /// <summary>
    /// A request whose encoding exceeds the record limit is refused before any write.
    /// </summary>
    [Fact]
    public void OversizedRequestRefused()
    {
        using var document = JsonDocument.Parse("{\"name\":\"" + new string('n', HelperProtocol.MaxLine) + "\"}");
        var request = new HelperRequest { Id = "1", Op = "profile.put", ProfileJson = document.RootElement.Clone() };
        var e = Assert.Throws<HelperProtocolException>(() => FrameCodec.Encode(request));
        Assert.Equal("protocol: record exceeds limit", e.Message);
    }

    /// <summary>
    /// Builds a valid result record padded to the given total length including its newline.
    /// </summary>
    /// <param name="length">The total record length.</param>
    /// <returns>The record bytes.</returns>
    internal static byte[] PaddedResult(int length)
    {
        const string Prefix = "{\"type\":\"result\",\"id\":\"1\",\"ok\":true,\"data\":[\"";
        const string Suffix = "\"]}\n";
        return Encoding.UTF8.GetBytes(Prefix + new string('x', length - Prefix.Length - Suffix.Length) + Suffix);
    }

    /// <summary>
    /// Returns the frame text of a named vector.
    /// </summary>
    /// <param name="group">The vector group.</param>
    /// <param name="name">The vector name.</param>
    /// <returns>The frame, including its newline.</returns>
    private static string Frame(string group, string name) => Vectors.Entry(File, name, group).GetProperty("frame").GetString()!;
}
