using Fortix.Core.Protocol;

namespace Fortix.App.ViewModels;

/// <summary>
/// The public state of one helper-owned profile; it never holds credentials.
/// </summary>
/// <param name="Attempt">The tunnel generation, which keeps late events from changing a newer connection.</param>
/// <param name="State">The textual phase, never a color-only indicator.</param>
/// <param name="Detail">The helper's redacted explanation of the last transition.</param>
/// <param name="Wanted">Whether the helper is asked to keep the profile connected.</param>
/// <param name="CleanupPending">Whether network cleanup is unresolved, which is never a clean disconnect.</param>
public sealed record ProfilePresentation(ulong Attempt, string State, string Detail, bool Wanted, bool CleanupPending);

/// <summary>
/// A request for human input bound to the exact helper event that asked for it.
/// </summary>
public sealed class PendingPrompt
{
    /// <summary>
    /// Creates the prompt for a challenge or certificate event.
    /// </summary>
    /// <param name="helperEvent">The event.</param>
    public PendingPrompt(HelperEvent helperEvent)
    {
        ArgumentNullException.ThrowIfNull(helperEvent);
        Event = helperEvent;
        Id = $"{helperEvent.Profile}:{helperEvent.Attempt}:{(helperEvent.ChallengeId.Length > 0 ? helperEvent.ChallengeId : helperEvent.Digest)}";
    }

    /// <summary>Gets the event, including profile, attempt, challenge, and certificate identity.</summary>
    public HelperEvent Event { get; }

    /// <summary>Gets the identity that separates successive requests, even for one profile.</summary>
    public string Id { get; }

    /// <summary>Gets whether this asks for certificate verification rather than a credential.</summary>
    public bool IsCertificate => Event.Type == "cert";

    /// <summary>Gets whether this asks for the account password, the only answer that may be saved.</summary>
    public bool IsPassword => !IsCertificate && Event.Kind == "password";
}

/// <summary>
/// One failed connection attempt to report to the user.
/// </summary>
/// <param name="ProfileId">The profile identifier.</param>
/// <param name="Name">The profile's display name.</param>
/// <param name="Detail">The helper's plain failure reason, possibly empty.</param>
public sealed record ConnectionFailure(string ProfileId, string Name, string Detail);

/// <summary>
/// Thrown when a disconnect did not reach a clean, stopped state.
/// </summary>
public sealed class StopFailedException : Exception
{
    /// <summary>
    /// Creates the exception with a fixed message.
    /// </summary>
    public StopFailedException()
        : base("disconnect did not finish cleanly")
    {
    }
}

/// <summary>
/// Thrown when a new profile reuses the identifier of a stored one.
/// </summary>
public sealed class DuplicateProfileException : Exception
{
    /// <summary>
    /// Creates the exception with a fixed message.
    /// </summary>
    public DuplicateProfileException()
        : base("a profile with this identifier already exists")
    {
    }
}

/// <summary>
/// Thrown when a prompt was answered after the helper moved on.
/// </summary>
public sealed class StalePromptException : Exception
{
    /// <summary>
    /// Creates the exception with a fixed message.
    /// </summary>
    public StalePromptException()
        : base("the request is no longer current")
    {
    }
}

/// <summary>
/// Shared presentation helpers for profiles.
/// </summary>
public static class ProfileText
{
    /// <summary>
    /// Returns the backend the helper will use, resolving an automatic choice from the MFA mode.
    /// </summary>
    /// <param name="profile">The profile.</param>
    /// <returns>native or openfortivpn.</returns>
    public static string ResolvedBackend(Fortix.Core.Profiles.Profile profile)
    {
        ArgumentNullException.ThrowIfNull(profile);
        if (!string.IsNullOrEmpty(profile.Backend))
        {
            return profile.Backend;
        }
        return profile.Mfa.Mode is "" or "none" ? "native" : "openfortivpn";
    }

    /// <summary>
    /// Returns the Windows helper's refusal for a profile, or null when it can connect.
    /// </summary>
    /// <param name="profile">The profile, defaulted or not.</param>
    /// <returns>The exact helper message, or null.</returns>
    public static string? WindowsUnavailableReason(Fortix.Core.Profiles.Profile profile)
    {
        ArgumentNullException.ThrowIfNull(profile);
        var copy = profile.Clone();
        Fortix.Core.Profiles.ProfileRules.ApplyDefaults(copy);
        return Fortix.Core.Profiles.ProfileRules.WindowsUnavailableReason(copy);
    }

    /// <summary>
    /// Renders a phase for display, such as "waiting password" for waiting_password.
    /// </summary>
    /// <param name="state">The phase.</param>
    /// <returns>The readable phase.</returns>
    public static string Phase(string state) => string.IsNullOrEmpty(state) ? "unknown" : state.Replace('_', ' ');
}
