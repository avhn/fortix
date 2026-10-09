using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace Fortix.Core.Protocol;

/// <summary>
/// Protocol constants shared with the helper.
/// </summary>
public static class HelperProtocol
{
    /// <summary>The largest encoded record, including its terminating newline.</summary>
    public const int MaxLine = 64 * 1024;

    /// <summary>The protocol version negotiated during hello.</summary>
    public const int Version = 1;

    /// <summary>The largest log tail a logs request may ask for.</summary>
    public const int MaxLogLines = 500;

    /// <summary>The largest credential answer after pinentry escaping, in UTF-8 bytes.</summary>
    public const int MaxEscapedSecret = 997;
}

/// <summary>
/// Stable failure categories shared by clients and the helper; none contain caller input.
/// </summary>
public static class HelperErrorCodes
{
    /// <summary>The caller is not allowed to use the helper.</summary>
    public const string Unauthorized = "UNAUTHORIZED";

    /// <summary>The profile or challenge does not exist.</summary>
    public const string NotFound = "NOT_FOUND";

    /// <summary>The request or profile is invalid.</summary>
    public const string Invalid = "INVALID";

    /// <summary>The request conflicts with current state.</summary>
    public const string Conflict = "CONFLICT";

    /// <summary>The helper is busy with a conflicting operation.</summary>
    public const string Busy = "BUSY";

    /// <summary>The helper failed internally.</summary>
    public const string Internal = "INTERNAL";

    /// <summary>The tunnel interface did not match the expected identity.</summary>
    public const string InterfaceMismatch = "INTERFACE_MISMATCH";

    /// <summary>Gets every code in protocol declaration order.</summary>
    public static IReadOnlyList<string> All { get; } = [Unauthorized, NotFound, Invalid, Conflict, Busy, Internal, InterfaceMismatch];
}

/// <summary>
/// One request with inline, operation-specific arguments.
/// </summary>
/// <remarks>
/// <see cref="ProfileJson"/> is a JSON object, not a JSON-encoded string. The client replaces
/// <see cref="Id"/> with its own correlation identifier. <see cref="Secret"/> is a managed
/// string, so releasing it cannot erase its memory; encoded frame buffers are cleared.
/// </remarks>
public sealed record HelperRequest
{
    /// <summary>Gets the correlation identifier, 1 to 128 UTF-8 bytes.</summary>
    [JsonPropertyName("id")]
    public string Id { get; init; } = "";

    /// <summary>Gets the operation name.</summary>
    [JsonPropertyName("op")]
    public string Op { get; init; } = "";

    /// <summary>Gets the client version sent with hello.</summary>
    [JsonPropertyName("version")]
    public string? Version { get; init; }

    /// <summary>Gets the target profile identifier.</summary>
    [JsonPropertyName("profile")]
    public string? Profile { get; init; }

    /// <summary>Gets the profile object for profile.put.</summary>
    [JsonPropertyName("profile_json")]
    public JsonElement? ProfileJson { get; init; }

    /// <summary>Gets whether down applies to every profile.</summary>
    [JsonPropertyName("all")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingDefault)]
    public bool All { get; init; }

    /// <summary>Gets the challenge an answer or cancel refers to.</summary>
    [JsonPropertyName("challenge_id")]
    public string? ChallengeId { get; init; }

    /// <summary>Gets the transient credential answer; it never enters logs.</summary>
    [JsonPropertyName("secret")]
    public string? Secret { get; init; }

    /// <summary>Gets the accepted certificate digest for trust.</summary>
    [JsonPropertyName("digest")]
    public string? Digest { get; init; }

    /// <summary>Gets the log tail length; zero means the helper default.</summary>
    [JsonPropertyName("lines")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingDefault)]
    public int Lines { get; init; }

    /// <summary>Gets whether a subscription also receives log events.</summary>
    [JsonPropertyName("logs")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingDefault)]
    public bool Logs { get; init; }

    /// <summary>
    /// Arguments each operation accepts, as space-separated wire names.
    /// </summary>
    private static readonly Dictionary<string, string> Allowed = new(StringComparer.Ordinal)
    {
        ["hello"] = "version",
        ["subscribe"] = "logs",
        ["profile.list"] = "",
        ["profile.get"] = "profile",
        ["profile.put"] = "profile_json",
        ["profile.delete"] = "profile",
        ["up"] = "profile",
        ["down"] = "profile all",
        ["status"] = "",
        ["answer"] = "challenge_id secret",
        ["cancel"] = "challenge_id",
        ["trust"] = "profile digest",
        ["logs"] = "profile lines",
    };

    /// <summary>
    /// Reports whether the arguments fit the operation exactly as the helper checks them.
    /// </summary>
    /// <remarks>
    /// Arguments belonging to other operations are rejected, and a credential answer must fit
    /// one pinentry data record after escaping, so an accepted answer is never dropped later.
    /// </remarks>
    /// <returns>True when the helper would accept the arguments.</returns>
    public bool IsValid()
    {
        var secret = Secret ?? "";
        var idBytes = Encoding.UTF8.GetByteCount(Id ?? "");
        if (idBytes is 0 or > 128 || EscapedSecretLength(secret) > HelperProtocol.MaxEscapedSecret || !Allowed.TryGetValue(Op ?? "", out var args))
        {
            return false;
        }
        var accepted = args.Split(' ', StringSplitOptions.RemoveEmptyEntries);
        var present = new (string Name, bool Has)[]
        {
            ("version", !string.IsNullOrEmpty(Version)), ("profile", !string.IsNullOrEmpty(Profile)),
            ("profile_json", ProfileJson is not null), ("logs", Logs), ("all", All),
            ("challenge_id", !string.IsNullOrEmpty(ChallengeId)), ("secret", secret.Length > 0),
            ("digest", !string.IsNullOrEmpty(Digest)), ("lines", Lines != 0),
        };
        if (present.Any(field => field.Has && !accepted.Contains(field.Name)))
        {
            return false;
        }
        if (accepted.Contains("profile") && Op != "profile.put" && string.IsNullOrEmpty(Profile) && (Op != "down" || !All))
        {
            return false;
        }
        if (Op == "down" && All && !string.IsNullOrEmpty(Profile))
        {
            return false;
        }
        if (Op == "profile.put" && ProfileJson?.ValueKind != JsonValueKind.Object)
        {
            return false;
        }
        if (accepted.Contains("challenge_id") && string.IsNullOrEmpty(ChallengeId))
        {
            return false;
        }
        if (Op == "trust" && Encoding.UTF8.GetByteCount(Digest ?? "") != 64)
        {
            return false;
        }
        return Op != "logs" || Lines is >= 0 and <= HelperProtocol.MaxLogLines;
    }

    /// <summary>
    /// Returns the UTF-8 length of a secret after pinentry escapes percent, CR, LF, and NUL.
    /// </summary>
    /// <param name="secret">The credential answer.</param>
    /// <returns>The escaped length in bytes.</returns>
    private static int EscapedSecretLength(string secret)
    {
        var bytes = Encoding.UTF8.GetBytes(secret);
        try
        {
            return bytes.Length + (2 * bytes.Count(b => b is (byte)'%' or (byte)'\r' or (byte)'\n' or 0));
        }
        finally
        {
            CryptographicOperations.ZeroMemory(bytes);
        }
    }

    /// <summary>
    /// Returns a copy with empty optional strings cleared so they are omitted like the helper's omitempty fields.
    /// </summary>
    /// <returns>The wire-ready copy.</returns>
    internal HelperRequest ForWire() => this with
    {
        Version = string.IsNullOrEmpty(Version) ? null : Version,
        Profile = string.IsNullOrEmpty(Profile) ? null : Profile,
        ChallengeId = string.IsNullOrEmpty(ChallengeId) ? null : ChallengeId,
        Secret = string.IsNullOrEmpty(Secret) ? null : Secret,
        Digest = string.IsNullOrEmpty(Digest) ? null : Digest,
    };
}
