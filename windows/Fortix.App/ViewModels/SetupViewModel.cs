using Fortix.App.Model;

namespace Fortix.App.ViewModels;

/// <summary>
/// The first-run page: explains the helper service and installs it with one administrator prompt.
/// </summary>
public sealed class SetupViewModel : ObservableObject
{
    /// <summary>Reads the service state.</summary>
    private readonly IHelperServiceProbe probe;

    /// <summary>Starts the elevated installer.</summary>
    private readonly IHelperInstaller installer;

    /// <summary>Checks the session's group membership after installing.</summary>
    private readonly IGroupMembership membership;

    /// <summary>The directory holding FortixApp.exe.</summary>
    private readonly string appDirectory;

    /// <summary>The account to enroll.</summary>
    private readonly string user;

    /// <summary>The last observed service state.</summary>
    private HelperServiceState state = HelperServiceState.Unknown;

    /// <summary>Whether the installer is running.</summary>
    private bool installing;

    /// <summary>The last installer result.</summary>
    private string? result;

    /// <summary>Whether the user must sign out before the helper accepts them.</summary>
    private bool signOutRequired;

    /// <summary>
    /// Creates the page model.
    /// </summary>
    /// <param name="probe">Reads the service state.</param>
    /// <param name="installer">Starts the elevated installer.</param>
    /// <param name="membership">Checks the session's group membership.</param>
    /// <param name="appDirectory">The directory holding FortixApp.exe.</param>
    /// <param name="installDirectory">Program Files\Fortix.</param>
    /// <param name="user">The account to enroll, DOMAIN\name.</param>
    public SetupViewModel(IHelperServiceProbe probe, IHelperInstaller installer, IGroupMembership membership, string appDirectory, string installDirectory, string user)
    {
        ArgumentNullException.ThrowIfNull(probe);
        ArgumentNullException.ThrowIfNull(installer);
        ArgumentNullException.ThrowIfNull(membership);
        ArgumentNullException.ThrowIfNull(appDirectory);
        ArgumentNullException.ThrowIfNull(installDirectory);
        this.probe = probe;
        this.installer = installer;
        this.membership = membership;
        this.appDirectory = appDirectory;
        this.user = user ?? "";
        RunsFromInstalledCopy = HelperSetup.RunsFromInstalledCopy(appDirectory, installDirectory);
        InstallCommand = new RelayCommand(_ => _ = InstallAsync(), _ => CanInstall);
        RefreshCommand = new RelayCommand(_ => Refresh(), _ => !installing);
        DismissResultCommand = new RelayCommand(_ => DismissResult(), _ => CanDismissResult);
    }

    /// <summary>Raised after the installer succeeded, so the app reconnects at once.</summary>
    public event EventHandler? Installed;

    /// <summary>Gets or sets the longest wait for the installer.</summary>
    public TimeSpan InstallTimeout { get; init; } = TimeSpan.FromMinutes(5);

    /// <summary>Gets the last observed service state.</summary>
    public HelperServiceState State
    {
        get => state;
        private set
        {
            if (Set(ref state, value))
            {
                OnPropertyChanged(nameof(NeedsSetup));
                OnPropertyChanged(nameof(Explanation));
            }
        }
    }

    /// <summary>Gets whether the setup page should be shown.</summary>
    public bool NeedsSetup => State != HelperServiceState.Running;

    /// <summary>Gets whether the app runs from Program Files\Fortix, where installing is refused.</summary>
    public bool RunsFromInstalledCopy { get; }

    /// <summary>Gets the explanation for the current state.</summary>
    public string Explanation => RunsFromInstalledCopy && State != HelperServiceState.Running
        ? "This copy of Fortix runs from the installed helper folder, which cannot install itself. Extract the release archive to a folder of your choice and start FortixApp.exe from there to install or repair the helper."
        : State switch
        {
            HelperServiceState.Missing => "Fortix needs its helper service. The helper runs in the background as a Windows service, owns the VPN tunnels, and keeps them up when this window is closed. Installing it asks for administrator approval once.",
            HelperServiceState.Stopped => "The Fortix helper service is installed but not running. Install again to repair and start it.",
            HelperServiceState.Pending => "The Fortix helper service is starting or stopping. Wait a moment, then refresh.",
            HelperServiceState.Running => "The Fortix helper service is running. Installing again updates it from this release.",
            _ => "The state of the Fortix helper service could not be read. Install the helper to make sure it is present.",
        };

    /// <summary>Gets the last installer result, or null.</summary>
    /// <remarks>
    /// The result outlives the setup page: a successful install starts the service, which hides
    /// the page, and the result is still shown until it is dismissed.
    /// </remarks>
    public string? Result
    {
        get => result;
        private set
        {
            if (Set(ref result, value))
            {
                OnPropertyChanged(nameof(ShowsResult));
                ResultChanged();
            }
        }
    }

    /// <summary>Gets whether the installer result banner should be shown, independent of the service state.</summary>
    public bool ShowsResult => !string.IsNullOrEmpty(Result);

    /// <summary>Gets whether the user must sign out and back in before connecting.</summary>
    public bool SignOutRequired
    {
        get => signOutRequired;
        private set
        {
            if (Set(ref signOutRequired, value))
            {
                ResultChanged();
            }
        }
    }

    /// <summary>
    /// Gets whether the result may be dismissed: not while installing, and never while the
    /// sign-out instruction still applies, because the helper refuses this session until then.
    /// </summary>
    public bool CanDismissResult => ShowsResult && !Installing && !SignOutRequired;

    /// <summary>Gets the action that hides the installer result.</summary>
    public RelayCommand DismissResultCommand { get; }

    /// <summary>Gets whether the installer is running.</summary>
    public bool Installing
    {
        get => installing;
        private set
        {
            if (Set(ref installing, value))
            {
                OnPropertyChanged(nameof(CanInstall));
                InstallCommand.Refresh();
                RefreshCommand.Refresh();
                ResultChanged();
            }
        }
    }

    /// <summary>Gets whether installing is possible now.</summary>
    public bool CanInstall => !Installing && !RunsFromInstalledCopy && HelperSetup.ValidUser(user);

    /// <summary>Gets the install action.</summary>
    public RelayCommand InstallCommand { get; }

    /// <summary>Gets the action that reads the service state again.</summary>
    public RelayCommand RefreshCommand { get; }

    /// <summary>
    /// Reads the service state again.
    /// </summary>
    public void Refresh() => State = probe.Query();

    /// <summary>
    /// Hides the installer result once it was read; a pending sign-out instruction stays.
    /// </summary>
    public void DismissResult()
    {
        if (CanDismissResult)
        {
            Result = null;
        }
    }

    /// <summary>
    /// Announces that the result banner's dismiss availability may have changed.
    /// </summary>
    private void ResultChanged()
    {
        OnPropertyChanged(nameof(CanDismissResult));
        DismissResultCommand?.Refresh();
    }

    /// <summary>
    /// Runs the bundled installer elevated, waits for it, and reports the result.
    /// </summary>
    /// <returns>A task that completes when the result is shown.</returns>
    public async Task InstallAsync()
    {
        if (!CanInstall)
        {
            return;
        }
        Installing = true;
        Result = "Waiting for administrator approval and the installer...";
        SignOutRequired = false;
        try
        {
            using var timeout = new CancellationTokenSource(InstallTimeout);
            var run = await installer.RunElevatedAsync(Path.Combine(appDirectory, HelperSetup.HelperExecutable), HelperSetup.InstallArguments(user), timeout.Token);
            Result = HelperSetup.Describe(run, user);
            if (HelperSetup.Classify(run) == InstallOutcome.Installed)
            {
                if (!membership.SessionHasFortixGroup())
                {
                    SignOutRequired = true;
                    Result += " Your account was added to the fortix group. Sign out of Windows and back in, then start Fortix again, so the new membership takes effect.";
                }
                Installed?.Invoke(this, EventArgs.Empty);
            }
        }
        finally
        {
            Refresh();
            Installing = false;
        }
    }
}
