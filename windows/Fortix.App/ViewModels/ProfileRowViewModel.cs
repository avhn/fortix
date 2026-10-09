using System.Globalization;
using Fortix.Core.Profiles;

namespace Fortix.App.ViewModels;

/// <summary>
/// One row of the profile list: identity, textual phase, warnings, and its actions.
/// </summary>
public sealed class ProfileRowViewModel : ObservableObject
{
    /// <summary>The textual phase.</summary>
    private string stateText = "unknown";

    /// <summary>The helper's redacted explanation.</summary>
    private string detail = "";

    /// <summary>Whether network cleanup is pending.</summary>
    private bool cleanupPending;

    /// <summary>Whether connecting is available.</summary>
    private bool canConnect;

    /// <summary>Whether disconnecting and other helper actions are available.</summary>
    private bool canManage;

    /// <summary>Whether the profile is idle enough to edit.</summary>
    private bool canEdit;

    /// <summary>
    /// Creates a row for a stored profile.
    /// </summary>
    /// <param name="profile">The stored profile.</param>
    /// <param name="owner">The coordinator that runs this row's actions.</param>
    internal ProfileRowViewModel(Profile profile, AppViewModel owner)
    {
        Profile = profile;
        var port = profile.Gateway.Port == 0 ? 443 : profile.Gateway.Port;
        Endpoint = $"{profile.Gateway.Host}:{port.ToString(CultureInfo.InvariantCulture)} | {ProfileText.ResolvedBackend(profile)}";
        UnavailableReason = ProfileText.WindowsUnavailableReason(profile);
        ConnectCommand = new RelayCommand(_ => owner.Perform(() => owner.ConnectAsync(Id)), _ => CanConnect);
        DisconnectCommand = new RelayCommand(_ => owner.Perform(() => owner.DisconnectAsync(Id)), _ => CanManage);
        ForgetPasswordCommand = new RelayCommand(_ => owner.Perform(() => owner.ForgetAsync(Id)), _ => CanManage);
    }

    /// <summary>Gets the stored profile.</summary>
    public Profile Profile { get; }

    /// <summary>Gets the profile identifier.</summary>
    public string Id => Profile.Id;

    /// <summary>Gets the display name.</summary>
    public string Name => Profile.Name;

    /// <summary>Gets the gateway and backend summary.</summary>
    public string Endpoint { get; }

    /// <summary>Gets why Windows cannot connect this profile, or null when it can.</summary>
    public string? UnavailableReason { get; }

    /// <summary>Gets the textual phase.</summary>
    public string StateText
    {
        get => stateText;
        private set => Set(ref stateText, value);
    }

    /// <summary>Gets the helper's explanation of the last transition.</summary>
    public string Detail
    {
        get => detail;
        private set => Set(ref detail, value);
    }

    /// <summary>Gets whether network cleanup is pending, which is shown as a warning.</summary>
    public bool CleanupPending
    {
        get => cleanupPending;
        private set => Set(ref cleanupPending, value);
    }

    /// <summary>Gets whether the profile can be connected now.</summary>
    public bool CanConnect
    {
        get => canConnect;
        private set => Set(ref canConnect, value);
    }

    /// <summary>Gets whether helper actions for this profile are available now.</summary>
    public bool CanManage
    {
        get => canManage;
        private set => Set(ref canManage, value);
    }

    /// <summary>Gets whether the profile is idle and may be edited or deleted.</summary>
    public bool CanEdit
    {
        get => canEdit;
        private set => Set(ref canEdit, value);
    }

    /// <summary>Gets the connect action.</summary>
    public RelayCommand ConnectCommand { get; }

    /// <summary>Gets the disconnect action.</summary>
    public RelayCommand DisconnectCommand { get; }

    /// <summary>Gets the action that removes this profile's saved password.</summary>
    public RelayCommand ForgetPasswordCommand { get; }

    /// <summary>
    /// Applies the latest state and availability.
    /// </summary>
    /// <param name="state">The profile's presentation, or null when unknown.</param>
    /// <param name="reachable">Whether the helper is connected.</param>
    /// <param name="busy">Whether another operation is running.</param>
    internal void Update(ProfilePresentation? state, bool reachable, bool busy)
    {
        StateText = reachable ? ProfileText.Phase(state?.State ?? "") : "Status unavailable";
        Detail = state?.Detail ?? "";
        CleanupPending = state?.CleanupPending == true;
        CanManage = reachable && !busy;
        CanConnect = CanManage && state?.Wanted != true && UnavailableReason is null;
        CanEdit = CanManage && (state is null || state.State is "disconnected" or "failed") && !CleanupPending;
        ConnectCommand.Refresh();
        DisconnectCommand.Refresh();
        ForgetPasswordCommand.Refresh();
    }
}
