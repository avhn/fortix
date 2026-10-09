using System.Text.Json;
using Fortix.Core.Credentials;
using Fortix.Core.Json;
using Fortix.Core.Profiles;
using Fortix.Core.Protocol;

namespace Fortix.Core.Tests;

/// <summary>
/// Checks credential target names and Go JSON quoting against the Go-generated vectors.
/// </summary>
public sealed class CredentialTargetTests
{
    /// <summary>Gets the credential vector names.</summary>
    public static TheoryData<string> Credentials => Vectors.Names("credential-targets.json");

    /// <summary>Gets the aggregate status vector names.</summary>
    public static TheoryData<string> Aggregates => Vectors.Names("aggregate-status.json");

    /// <summary>
    /// The hashed tuple and the target equal what the command-line client stores.
    /// </summary>
    /// <param name="name">The vector name.</param>
    [Theory]
    [MemberData(nameof(Credentials))]
    public void MatchesGo(string name)
    {
        var v = Vectors.Entry("credential-targets.json", name);
        var target = new CredentialTarget(v.GetProperty("id").GetString()!, v.GetProperty("host").GetString()!, v.GetProperty("port").GetInt64(), v.GetProperty("username").GetString()!);
        Assert.Equal(v.GetProperty("tuple_json").GetString(), target.TupleJson);
        Assert.Equal(v.GetProperty("target").GetString(), target.Target);
    }

    /// <summary>
    /// A stored profile without a port uses the default 443, like the helper.
    /// </summary>
    [Fact]
    public void ProfileDefaultsPort()
    {
        var profile = new Profile { Id = "office", Gateway = new Gateway { Host = "vpn.example.com" }, Username = "alice" };
        Assert.Equal("fortix:office:1e37db253af678a3c9010637555e6a96fb5a3a71ed566bc4abf79ce423186bc7:password", CredentialTarget.For(profile).Target);
    }

    /// <summary>
    /// Invalid identities fail before any credential store access.
    /// </summary>
    /// <param name="id">The profile identifier.</param>
    /// <param name="host">The gateway host.</param>
    /// <param name="port">The gateway port.</param>
    /// <param name="username">The username.</param>
    [Theory]
    [InlineData("Office", "vpn.example.com", 443, "alice")]
    [InlineData("office", "", 443, "alice")]
    [InlineData("office", "vpn.example.com", 0, "alice")]
    [InlineData("office", "vpn.example.com", 65536, "alice")]
    [InlineData("office", "vpn.example.com", 443, "")]
    public void InvalidIdentity(string id, string host, long port, string username) =>
        Assert.Throws<ArgumentException>(() => new CredentialTarget(id, host, port, username));

    /// <summary>
    /// Quoting follows Go: short escapes, lowercase \u00xx controls, HTML and line separators escaped.
    /// </summary>
    /// <param name="input">The raw string.</param>
    /// <param name="expected">Go's encoding.</param>
    [Theory]
    [InlineData("a\"b\\c", "\"a\\\"b\\\\c\"")]
    [InlineData("\b\f\n\r\t", "\"\\b\\f\\n\\r\\t\"")]
    [InlineData("\u0001\u001f\u007f", "\"\\u0001\\u001f\u007f\"")]
    [InlineData("<&>", "\"\\u003c\\u0026\\u003e\"")]
    [InlineData("\u2028\u2029\u2027", "\"\\u2028\\u2029\u2027\"")]
    [InlineData("東京 \U0001F600", "\"東京 \U0001F600\"")]
    public void QuoteMatchesGo(string input, string expected) => Assert.Equal(expected, GoJson.Quote(input));

    /// <summary>
    /// A lone surrogate becomes a raw U+FFFD, which is what the helper holds after decoding the same text.
    /// </summary>
    /// <remarks>
    /// This is a fact rather than inline data because test discovery cannot carry a lone surrogate intact.
    /// </remarks>
    [Fact]
    public void QuoteReplacesLoneSurrogate() => Assert.Equal("\"\uFFFDx\uFFFD\"", GoJson.Quote("\uD800x\uDC00"));

    /// <summary>
    /// Aggregate status precedence matches the shared presentation fixtures.
    /// </summary>
    /// <param name="name">The vector name.</param>
    [Theory]
    [MemberData(nameof(Aggregates))]
    public void AggregateStatusMatches(string name)
    {
        var v = Vectors.Entry("aggregate-status.json", name);
        var profiles = v.GetProperty("profiles").Deserialize(CoreJsonContext.Default.ListAggregateProfile)!;
        var status = AggregateStatusBuilder.Build(profiles, v.GetProperty("reachable").GetBoolean());
        Assert.Equal(v.GetProperty("status").GetString(), status.ToString());
    }
}
