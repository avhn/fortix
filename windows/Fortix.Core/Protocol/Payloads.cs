using System.Text.Json.Serialization;

namespace Fortix.Core.Protocol;

/// <summary>
/// The hello reply: the helper's version and protocol number.
/// </summary>
public sealed class HelloResponse
{
    /// <summary>Gets or sets the helper build version.</summary>
    [JsonPropertyName("helper_version")]
    public string HelperVersion { get; set; } = "";

    /// <summary>Gets or sets the helper protocol number; it must equal <see cref="HelperProtocol.Version"/>.</summary>
    [JsonPropertyName("protocol")]
    public long Protocol { get; set; }
}

/// <summary>
/// The up reply: the attempt the helper started.
/// </summary>
public sealed class UpResponse
{
    /// <summary>Gets or sets the started tunnel generation.</summary>
    [JsonPropertyName("attempt")]
    public ulong Attempt { get; set; }
}

/// <summary>
/// One entry of the lightweight profile.list reply.
/// </summary>
public sealed class ProfileState
{
    /// <summary>Gets or sets the profile identifier.</summary>
    [JsonPropertyName("profile")]
    public string Profile { get; set; } = "";

    /// <summary>Gets or sets the current public phase.</summary>
    [JsonPropertyName("state")]
    public string State { get; set; } = "";
}

/// <summary>
/// One authoritative, secret-free session snapshot from the status reply, including idle profiles.
/// </summary>
public sealed class SessionStatus
{
    /// <summary>Gets or sets whether connectivity is wanted rather than merely the link state.</summary>
    [JsonPropertyName("wanted")]
    public bool Wanted { get; set; }

    /// <summary>Gets or sets whether this connection initiated the attempt.</summary>
    [JsonPropertyName("initiated")]
    public bool Initiated { get; set; }

    /// <summary>Gets or sets whether network cleanup is unresolved, which is never a clean disconnect.</summary>
    [JsonPropertyName("cleanup_pending")]
    public bool CleanupPending { get; set; }

    /// <summary>Gets or sets the profile identifier.</summary>
    [JsonPropertyName("profile")]
    public string Profile { get; set; } = "";

    /// <summary>Gets or sets the public session phase, kept as text for future phases.</summary>
    [JsonPropertyName("state")]
    public string State { get; set; } = "";

    /// <summary>Gets or sets the redacted state explanation.</summary>
    [JsonPropertyName("detail")]
    public string Detail { get; set; } = "";

    /// <summary>Gets or sets the tunnel generation.</summary>
    [JsonPropertyName("attempt")]
    public ulong Attempt { get; set; }

    /// <summary>Gets or sets the tunnel interface name, empty before setup.</summary>
    [JsonPropertyName("interface")]
    public string Interface { get; set; } = "";

    /// <summary>Gets or sets the assigned IPv4 address, empty before negotiation.</summary>
    [JsonPropertyName("local_ip")]
    public string LocalIp { get; set; } = "";

    /// <summary>Gets or sets the helper timestamp text, including the zero time for idle profiles.</summary>
    [JsonPropertyName("since")]
    public string Since { get; set; } = "";
}

/// <summary>
/// Session phases the helper reports; unknown future phases are kept as text.
/// </summary>
public static class SessionPhases
{
    /// <summary>No tunnel and nothing pending.</summary>
    public const string Disconnected = "disconnected";

    /// <summary>An attempt is starting.</summary>
    public const string Starting = "starting";

    /// <summary>The helper waits for a password answer.</summary>
    public const string WaitingPassword = "waiting_password";

    /// <summary>The helper waits for a second-factor code.</summary>
    public const string WaitingCode = "waiting_code";

    /// <summary>The gateway is authenticating the user.</summary>
    public const string Authenticating = "authenticating";

    /// <summary>The tunnel is negotiating.</summary>
    public const string Negotiating = "negotiating";

    /// <summary>Routes and DNS are being configured.</summary>
    public const string Configuring = "configuring";

    /// <summary>The tunnel is up.</summary>
    public const string Connected = "connected";

    /// <summary>The gateway certificate needs explicit trust.</summary>
    public const string WaitingTrust = "waiting_trust";

    /// <summary>The helper waits before retrying.</summary>
    public const string Backoff = "backoff";

    /// <summary>The tunnel is stopping.</summary>
    public const string Stopping = "stopping";

    /// <summary>The attempt failed.</summary>
    public const string Failed = "failed";
}
