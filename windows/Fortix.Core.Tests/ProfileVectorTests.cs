using System.Text;
using System.Text.Json;
using Fortix.Core.Profiles;

namespace Fortix.Core.Tests;

/// <summary>
/// Checks profile decoding, defaults, and validation against the Go helper's results.
/// </summary>
public sealed class ProfileVectorTests
{
    /// <summary>The vector file name.</summary>
    private const string File = "profile-validation.json";

    /// <summary>Gets the case names.</summary>
    public static TheoryData<string> Cases => Vectors.Names(File);

    /// <summary>
    /// Each input yields the same profile, the same problems in order, or the same decode error.
    /// </summary>
    /// <param name="name">The vector name.</param>
    [Theory]
    [MemberData(nameof(Cases))]
    public void MatchesHelper(string name)
    {
        var entry = Vectors.Entry(File, name);
        var input = Encoding.UTF8.GetBytes(entry.GetProperty("input").GetString()!);
        if (entry.TryGetProperty("profile", out var expected))
        {
            var profile = ProfileCodec.Decode(input);
            Assert.True(Vectors.SameJson(expected.GetRawText(), Encoding.UTF8.GetString(ProfileCodec.Encode(profile))), Encoding.UTF8.GetString(ProfileCodec.Encode(profile)));
            Assert.Null(ProfileRules.Problems(profile).FirstOrDefault());
        }
        else if (entry.TryGetProperty("errors", out var errors))
        {
            var e = Assert.Throws<ProfileValidationException>(() => ProfileCodec.Decode(input));
            Assert.Equal(Problems(errors), e.Problems);
        }
        else
        {
            var e = Assert.Throws<ProfileDecodeException>(() => ProfileCodec.Decode(input));
            Assert.Equal(entry.GetProperty("decode_error").GetString(), e.Message);
        }
    }

    /// <summary>
    /// The size limit counts whitespace: exactly 64 KiB decodes and one byte more fails.
    /// </summary>
    [Fact]
    public void SizeLimit()
    {
        const string Profile = "{\"schema_version\":1,\"id\":\"work\",\"name\":\"Work\",\"gateway\":{\"host\":\"vpn.example.com\"},\"username\":\"alice\"}";
        var exact = new string(' ', ProfileCodec.MaxBytes - Profile.Length) + Profile;
        Assert.Equal("work", ProfileCodec.Decode(Encoding.UTF8.GetBytes(exact)).Id);
        var e = Assert.Throws<ProfileDecodeException>(() => ProfileCodec.Decode(Encoding.UTF8.GetBytes(exact + " ")));
        Assert.Equal("profile: exceeds 64 KiB limit", e.Message);
    }

    /// <summary>
    /// Invalid UTF-8 and empty input fail with the helper's messages.
    /// </summary>
    [Fact]
    public void EncodingAndEmptyInput()
    {
        var e = Assert.Throws<ProfileDecodeException>(() => ProfileCodec.Decode([(byte)'{', 0xff, (byte)'}']));
        Assert.Equal("profile: invalid UTF-8", e.Message);
        e = Assert.Throws<ProfileDecodeException>(() => ProfileCodec.Decode("  "u8));
        Assert.Equal("decode profile: EOF", e.Message);
    }

    /// <summary>
    /// Type mismatches fail as decode errors rather than being coerced.
    /// </summary>
    /// <param name="input">The profile JSON.</param>
    [Theory]
    [InlineData("{\"gateway\":{\"port\":\"443\"}}")]
    [InlineData("{\"gateway\":{\"port\":443.5}}")]
    [InlineData("{\"gateway\":5}")]
    [InlineData("{\"routes\":{\"preserve_lan\":\"true\"}}")]
    [InlineData("{\"dns\":{\"domains\":[1]}}")]
    [InlineData("{\"schema_version\":1e0}")]
    public void TypeMismatchFails(string input) =>
        Assert.Throws<ProfileDecodeException>(() => ProfileCodec.Decode(Encoding.UTF8.GetBytes(input)));

    /// <summary>
    /// The Windows helper refuses MFA first, then any backend other than native.
    /// </summary>
    [Fact]
    public void WindowsAvailability()
    {
        var profile = ProfileCodec.Decode("{\"schema_version\":1,\"id\":\"work\",\"name\":\"Work\",\"gateway\":{\"host\":\"vpn.example.com\"},\"username\":\"alice\"}"u8);
        Assert.Null(ProfileRules.WindowsUnavailableReason(profile));
        profile.Backend = "openfortivpn";
        Assert.Equal("openfortivpn is not available on Windows; use the native backend", ProfileRules.WindowsUnavailableReason(profile));
        profile.Mfa.Mode = "prompt";
        Assert.Equal("MFA profiles are not available on Windows", ProfileRules.WindowsUnavailableReason(profile));
    }

    /// <summary>
    /// Problems leaves the profile untouched while Validate stores a normalized valid pin.
    /// </summary>
    [Fact]
    public void PinNormalization()
    {
        var profile = ProfileCodec.Decode("{\"schema_version\":1,\"id\":\"work\",\"name\":\"Work\",\"gateway\":{\"host\":\"vpn.example.com\"},\"username\":\"alice\"}"u8);
        var pin = string.Join(':', Enumerable.Repeat("AB", 32));
        profile.TrustedCert = pin;
        Assert.Empty(ProfileRules.Problems(profile));
        Assert.Equal(pin, profile.TrustedCert);
        Assert.Empty(ProfileRules.Validate(profile));
        Assert.Equal(string.Concat(Enumerable.Repeat("ab", 32)), profile.TrustedCert);
    }

    /// <summary>
    /// Prefix normalization trims, masks, and canonicalizes like the helper, including IPv6.
    /// </summary>
    /// <param name="input">The entered prefix.</param>
    /// <param name="expected">The normalized prefix.</param>
    [Theory]
    [InlineData(" 192.0.2.7/24\t", "192.0.2.0/24")]
    [InlineData("10.1.2.3/8", "10.0.0.0/8")]
    [InlineData("192.0.2.0/0", "0.0.0.0/0")]
    [InlineData("2001:DB8:0:0:1::1/32", "2001:db8::/32")]
    [InlineData("::ffff:192.0.2.7/120", "::ffff:192.0.2.0/120")]
    [InlineData("1:0:0:2:0:0:0:3/128", "1:0:0:2::3/128")]
    [InlineData("1:0:0:2:0:0:3:4/128", "1::2:0:0:3:4/128")]
    [InlineData("not a prefix ", "not a prefix")]
    [InlineData("192.0.2.0/08", "192.0.2.0/08")]
    [InlineData("fe80::1%eth0/64", "fe80::1%eth0/64")]
    public void NormalizePrefix(string input, string expected) => Assert.Equal(expected, ProfileRules.NormalizePrefix(input));

    /// <summary>
    /// Domain normalization lowercases and strips exactly one leading wildcard.
    /// </summary>
    /// <param name="input">The entered domain.</param>
    /// <param name="expected">The normalized domain.</param>
    [Theory]
    [InlineData("*.Corp.Example.com", "corp.example.com")]
    [InlineData("*.*.example.com", "*.*.example.com")]
    [InlineData(" example.com", " example.com")]
    public void NormalizeDomain(string input, string expected) => Assert.Equal(expected, ProfileRules.NormalizeDomain(input));

    /// <summary>
    /// Converts vector error entries to problems.
    /// </summary>
    /// <param name="errors">The vector's errors array.</param>
    /// <returns>The expected problems in order.</returns>
    internal static List<ProfileFieldProblem> Problems(JsonElement errors) =>
        [.. errors.EnumerateArray().Select(e => new ProfileFieldProblem(e.GetProperty("field").GetString()!, e.GetProperty("message").GetString()!))];
}
