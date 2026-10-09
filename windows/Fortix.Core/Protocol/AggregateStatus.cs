using System.Text.Json.Serialization;

namespace Fortix.Core.Protocol;

/// <summary>
/// Presentation input for one profile, shared by tray and window status rendering.
/// </summary>
public sealed class AggregateProfile
{
    /// <summary>Gets or sets the profile identifier.</summary>
    [JsonPropertyName("id")]
    public string Id { get; set; } = "";

    /// <summary>Gets or sets the helper's public phase.</summary>
    [JsonPropertyName("state")]
    public string State { get; set; } = "";

    /// <summary>Gets or sets whether the profile counts toward wanted connectivity.</summary>
    [JsonPropertyName("wanted")]
    public bool Wanted { get; set; }

    /// <summary>Gets or sets whether a human password prompt is pending.</summary>
    [JsonPropertyName("pending_password")]
    public bool PendingPassword { get; set; }

    /// <summary>Gets or sets whether network cleanup is unresolved.</summary>
    [JsonPropertyName("cleanup_pending")]
    public bool CleanupPending { get; set; }
}

/// <summary>
/// The overall connectivity summary, named independently of icon color, shape, or animation.
/// </summary>
public enum AggregateStatus
{
    /// <summary>Nothing is connected, which also covers an unreachable helper.</summary>
    NotConnected,

    /// <summary>A profile is in a transitional phase.</summary>
    Connecting,

    /// <summary>Every wanted profile is connected and at least one is wanted.</summary>
    Connected,

    /// <summary>Some, but not all, wanted profiles are connected.</summary>
    Partial,

    /// <summary>A failure, a certificate decision, or a password prompt needs the user.</summary>
    Attention,
}

/// <summary>
/// Computes <see cref="AggregateStatus"/> with the same precedence as the command-line tray.
/// </summary>
public static class AggregateStatusBuilder
{
    /// <summary>
    /// Phases that count as progress for the Connecting status.
    /// </summary>
    private static readonly HashSet<string> Progress = new(StringComparer.Ordinal)
    {
        SessionPhases.Starting, SessionPhases.WaitingPassword, SessionPhases.WaitingCode, SessionPhases.Authenticating,
        SessionPhases.Negotiating, SessionPhases.Configuring, SessionPhases.Stopping, SessionPhases.Backoff,
    };

    /// <summary>
    /// Applies wanted connectivity before attention and progress; stale snapshots never prove success.
    /// </summary>
    /// <param name="profiles">The current presentation inputs.</param>
    /// <param name="reachable">Whether the helper is connected and its snapshots are current.</param>
    /// <returns>The summary status.</returns>
    public static AggregateStatus Build(IReadOnlyList<AggregateProfile> profiles, bool reachable)
    {
        ArgumentNullException.ThrowIfNull(profiles);
        if (!reachable)
        {
            return AggregateStatus.NotConnected;
        }
        var wanted = profiles.Count(p => p.Wanted);
        var up = profiles.Count(p => p.Wanted && p.State == SessionPhases.Connected);
        if (up > 0 && up < wanted)
        {
            return AggregateStatus.Partial;
        }
        if (wanted > 0 && up == wanted)
        {
            return AggregateStatus.Connected;
        }
        if (profiles.Any(p => p.PendingPassword || p.State is SessionPhases.Failed or SessionPhases.WaitingTrust))
        {
            return AggregateStatus.Attention;
        }
        return profiles.Any(p => Progress.Contains(p.State)) ? AggregateStatus.Connecting : AggregateStatus.NotConnected;
    }
}
