using System.Text.Json;
using System.Text.Json.Serialization;

namespace Fortix.Core.Protocol;

/// <summary>
/// A public operation failure with a stable code and a secret-free message.
/// </summary>
/// <param name="Code">One of <see cref="HelperErrorCodes"/>, or a future code.</param>
/// <param name="Message">The helper's redacted explanation.</param>
[JsonUnmappedMemberHandling(JsonUnmappedMemberHandling.Disallow)]
public sealed record HelperError(
    [property: JsonPropertyName("code")] string Code,
    [property: JsonPropertyName("message")] string Message);

/// <summary>
/// The single reply to one request.
/// </summary>
/// <param name="Id">The request identifier; empty only for a pre-request rejection.</param>
/// <param name="Ok">Whether the operation succeeded.</param>
/// <param name="Error">The failure, present exactly when <paramref name="Ok"/> is false.</param>
/// <param name="Data">The operation-specific payload, absent on failure.</param>
public sealed record HelperResult(string Id, bool Ok, HelperError? Error, JsonElement? Data);

/// <summary>
/// A state, challenge, certificate, or redacted log notification.
/// </summary>
/// <remarks>
/// Attempt distinguishes successive tunnels for the same profile. Fields that do not belong to
/// the event type are empty; the decoder rejects events carrying fields of another type.
/// </remarks>
public sealed record HelperEvent
{
    /// <summary>Gets the event type: state, challenge, cert, or log.</summary>
    public string Type { get; init; } = "";

    /// <summary>Gets the affected profile.</summary>
    public string Profile { get; init; } = "";

    /// <summary>Gets the tunnel generation.</summary>
    public ulong Attempt { get; init; }

    /// <summary>Gets the public session phase of a state event.</summary>
    public string State { get; init; } = "";

    /// <summary>Gets the redacted transition explanation of a state event.</summary>
    public string Detail { get; init; } = "";

    /// <summary>Gets the optional failure category of a state event.</summary>
    public string Code { get; init; } = "";

    /// <summary>Gets whether connectivity is wanted, for state events.</summary>
    public bool Wanted { get; init; }

    /// <summary>Gets whether this connection initiated the attempt, for state events.</summary>
    public bool Initiated { get; init; }

    /// <summary>Gets whether network cleanup is still pending, for state events.</summary>
    public bool CleanupPending { get; init; }

    /// <summary>Gets the challenge identifier of a challenge event.</summary>
    public string ChallengeId { get; init; } = "";

    /// <summary>Gets the challenge kind, such as password or code.</summary>
    public string Kind { get; init; } = "";

    /// <summary>Gets the bounded prompt text of a challenge event.</summary>
    public string Prompt { get; init; } = "";

    /// <summary>Gets the rejected certificate's SHA-256 digest.</summary>
    public string Digest { get; init; } = "";

    /// <summary>Gets the certificate subject.</summary>
    public string Subject { get; init; } = "";

    /// <summary>Gets the certificate issuer.</summary>
    public string Issuer { get; init; } = "";

    /// <summary>Gets one already-redacted log line.</summary>
    public string Line { get; init; } = "";
}

/// <summary>
/// The wire envelope shared by results and events, decoded before classification.
/// </summary>
[JsonUnmappedMemberHandling(JsonUnmappedMemberHandling.Disallow)]
internal sealed class HelperFrame
{
    /// <summary>Gets or sets the frame type.</summary>
    [JsonPropertyName("type")]
    public string? Type { get; set; }

    /// <summary>Gets or sets the event failure category.</summary>
    [JsonPropertyName("code")]
    public string? Code { get; set; }

    /// <summary>Gets or sets the wanted flag.</summary>
    [JsonPropertyName("wanted")]
    public bool? Wanted { get; set; }

    /// <summary>Gets or sets the initiated flag.</summary>
    [JsonPropertyName("initiated")]
    public bool? Initiated { get; set; }

    /// <summary>Gets or sets the cleanup flag.</summary>
    [JsonPropertyName("cleanup_pending")]
    public bool? CleanupPending { get; set; }

    /// <summary>Gets or sets the result identifier.</summary>
    [JsonPropertyName("id")]
    public string? Id { get; set; }

    /// <summary>Gets or sets the result success flag.</summary>
    [JsonPropertyName("ok")]
    public bool? Ok { get; set; }

    /// <summary>Gets or sets the result failure.</summary>
    [JsonPropertyName("error")]
    public HelperError? Error { get; set; }

    /// <summary>Gets or sets the result payload.</summary>
    [JsonPropertyName("data")]
    public JsonElement? Data { get; set; }

    /// <summary>Gets or sets the event profile.</summary>
    [JsonPropertyName("profile")]
    public string? Profile { get; set; }

    /// <summary>Gets or sets the event attempt.</summary>
    [JsonPropertyName("attempt")]
    public ulong? Attempt { get; set; }

    /// <summary>Gets or sets the state phase.</summary>
    [JsonPropertyName("state")]
    public string? State { get; set; }

    /// <summary>Gets or sets the state detail.</summary>
    [JsonPropertyName("detail")]
    public string? Detail { get; set; }

    /// <summary>Gets or sets the challenge identifier.</summary>
    [JsonPropertyName("challenge_id")]
    public string? ChallengeId { get; set; }

    /// <summary>Gets or sets the challenge kind.</summary>
    [JsonPropertyName("kind")]
    public string? Kind { get; set; }

    /// <summary>Gets or sets the challenge prompt.</summary>
    [JsonPropertyName("prompt")]
    public string? Prompt { get; set; }

    /// <summary>Gets or sets the certificate digest.</summary>
    [JsonPropertyName("digest")]
    public string? Digest { get; set; }

    /// <summary>Gets or sets the certificate subject.</summary>
    [JsonPropertyName("subject")]
    public string? Subject { get; set; }

    /// <summary>Gets or sets the certificate issuer.</summary>
    [JsonPropertyName("issuer")]
    public string? Issuer { get; set; }

    /// <summary>Gets or sets the log line.</summary>
    [JsonPropertyName("line")]
    public string? Line { get; set; }
}
