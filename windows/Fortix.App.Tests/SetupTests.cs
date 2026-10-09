using Fortix.App.Model;
using Fortix.App.ViewModels;

namespace Fortix.App.Tests;

/// <summary>
/// Covers helper installation: arguments, exit-code mapping, and the setup page states.
/// </summary>
public sealed class SetupTests
{
    /// <summary>
    /// A scripted service probe, installer, and group check.
    /// </summary>
    private sealed class FakeSystem : IHelperServiceProbe, IHelperInstaller, IGroupMembership
    {
        /// <summary>Gets or sets the reported service state.</summary>
        public HelperServiceState State { get; set; } = HelperServiceState.Missing;

        /// <summary>Gets or sets the installer result.</summary>
        public InstallRun Run { get; set; } = new(0, 0);

        /// <summary>Gets or sets the state the service reaches after a successful install.</summary>
        public HelperServiceState AfterInstall { get; set; } = HelperServiceState.Running;

        /// <summary>Gets or sets whether the session token already has the group.</summary>
        public bool HasGroup { get; set; }

        /// <summary>Gets the launched executable and arguments.</summary>
        public List<(string Exe, string Args)> Launches { get; } = [];

        /// <inheritdoc/>
        public HelperServiceState Query() => State;

        /// <inheritdoc/>
        public Task<InstallRun> RunElevatedAsync(string executable, string arguments, CancellationToken cancellationToken)
        {
            Launches.Add((executable, arguments));
            if (Run is { LaunchError: 0, ExitCode: 0 })
            {
                State = AfterInstall;
            }
            return Task.FromResult(Run);
        }

        /// <inheritdoc/>
        public bool SessionHasFortixGroup() => HasGroup;
    }

    /// <summary>
    /// Creates a setup page for an extracted release folder.
    /// </summary>
    /// <param name="system">The fakes.</param>
    /// <param name="appDirectory">The app directory.</param>
    /// <param name="user">The account.</param>
    /// <returns>The view model.</returns>
    private static SetupViewModel Create(FakeSystem system, string appDirectory = @"C:\Users\jane\Downloads\fortix", string user = @"EXAMPLE\jane.doe") =>
        new(system, system, system, appDirectory, @"C:\Program Files\Fortix", user);

    /// <summary>
    /// Launch errors and exit codes map to fixed outcomes.
    /// </summary>
    /// <param name="launchError">The ShellExecuteEx error.</param>
    /// <param name="exitCode">The installer exit code, or null when unknown.</param>
    /// <param name="outcome">The expected outcome.</param>
    [Theory]
    [InlineData(0, 0, InstallOutcome.Installed)]
    [InlineData(0, 1, InstallOutcome.Failed)]
    [InlineData(0, -1, InstallOutcome.Failed)]
    [InlineData(0, null, InstallOutcome.TimedOut)]
    [InlineData(1223, null, InstallOutcome.Cancelled)]
    [InlineData(2, null, InstallOutcome.InstallerMissing)]
    [InlineData(3, null, InstallOutcome.InstallerMissing)]
    [InlineData(5, null, InstallOutcome.LaunchFailed)]
    public void ClassifiesRuns(int launchError, int? exitCode, InstallOutcome outcome) =>
        Assert.Equal(outcome, HelperSetup.Classify(new InstallRun(launchError, exitCode)));

    /// <summary>
    /// A failed run explains how to see the installer's own message.
    /// </summary>
    [Fact]
    public void FailedRunNamesManualCommand()
    {
        var text = HelperSetup.Describe(new InstallRun(0, 1), @"EXAMPLE\jane.doe");
        Assert.Contains("exit code 1", text, StringComparison.Ordinal);
        Assert.EndsWith("fortix-helper.exe install --user \"EXAMPLE\\jane.doe\"", text, StringComparison.Ordinal);
        Assert.Contains("Windows error 5", HelperSetup.Describe(new InstallRun(5, null), "jane"), StringComparison.Ordinal);
    }

    /// <summary>
    /// Arguments are quoted with the standard command-line rules, and unsafe names are refused.
    /// </summary>
    [Fact]
    public void BuildsInstallArguments()
    {
        Assert.Equal("install --user \"EXAMPLE\\jane.doe\"", HelperSetup.InstallArguments(@"EXAMPLE\jane.doe"));
        Assert.Equal("install --user \"PC\\Jane Doe\"", HelperSetup.InstallArguments(@"PC\Jane Doe"));
        Assert.Equal("\"a\\\\\"", HelperSetup.QuoteArgument("a\\"));
        Assert.Equal("\"a\\\\\\\"b\"", HelperSetup.QuoteArgument("a\\\"b"));
        foreach (var bad in new[] { "", " ", "-x", "a\"b", "a\nb", new string('a', 257) })
        {
            Assert.False(HelperSetup.ValidUser(bad));
            Assert.Throws<ArgumentException>(() => HelperSetup.InstallArguments(bad));
        }
    }

    /// <summary>
    /// The installed copy cannot install itself, regardless of case or trailing separator.
    /// </summary>
    [Fact]
    public void DetectsInstalledCopy()
    {
        Assert.True(HelperSetup.RunsFromInstalledCopy(@"c:\program files\fortix\", @"C:\Program Files\Fortix"));
        Assert.False(HelperSetup.RunsFromInstalledCopy(@"C:\Users\jane\Downloads\fortix", @"C:\Program Files\Fortix"));
        var system = new FakeSystem();
        var model = Create(system, appDirectory: @"C:\Program Files\Fortix");
        Assert.True(model.RunsFromInstalledCopy);
        Assert.False(model.CanInstall);
    }

    /// <summary>
    /// A successful install for an account without the group asks to sign out and back in.
    /// </summary>
    [Fact]
    public async Task InstallRequiresSignOutForNewGroup()
    {
        var system = new FakeSystem();
        var model = Create(system);
        var installed = 0;
        model.Installed += (_, _) => installed++;
        Assert.True(model.NeedsSetup);
        await model.InstallAsync();
        var launch = Assert.Single(system.Launches);
        Assert.Equal(Path.Combine(@"C:\Users\jane\Downloads\fortix", "fortix-helper.exe"), launch.Exe);
        Assert.Equal("install --user \"EXAMPLE\\jane.doe\"", launch.Args);
        Assert.True(model.SignOutRequired);
        Assert.Contains("Sign out of Windows and back in", model.Result, StringComparison.Ordinal);
        Assert.Equal(HelperServiceState.Running, model.State);
        Assert.False(model.NeedsSetup);
        Assert.False(model.Installing);
        Assert.Equal(1, installed);
    }

    /// <summary>
    /// The result outlives the setup page: after a successful install the service runs, yet the
    /// result and its sign-out instruction stay visible and cannot be dismissed.
    /// </summary>
    [Fact]
    public async Task ResultStaysVisibleOnceServiceRuns()
    {
        var system = new FakeSystem();
        var model = Create(system);
        await model.InstallAsync();
        Assert.False(model.NeedsSetup);
        Assert.True(model.ShowsResult);
        Assert.True(model.SignOutRequired);
        Assert.False(model.CanDismissResult);
        Assert.False(model.DismissResultCommand.CanExecute(null));
        model.DismissResult();
        Assert.True(model.ShowsResult);
        Assert.Contains("Sign out of Windows and back in", model.Result, StringComparison.Ordinal);
    }

    /// <summary>
    /// Updating an already running service shows the result, failures included, until dismissed.
    /// </summary>
    [Fact]
    public async Task UpdateResultShownWhileRunning()
    {
        var system = new FakeSystem { State = HelperServiceState.Running, Run = new InstallRun(0, 1), HasGroup = true };
        var model = Create(system);
        model.Refresh();
        Assert.False(model.NeedsSetup);
        await model.InstallAsync();
        Assert.False(model.NeedsSetup);
        Assert.True(model.ShowsResult);
        Assert.Contains("exit code 1", model.Result, StringComparison.Ordinal);
        Assert.True(model.DismissResultCommand.CanExecute(null));
        model.DismissResultCommand.Execute(null);
        Assert.False(model.ShowsResult);
        Assert.Null(model.Result);
    }

    /// <summary>
    /// An account already in the group needs no sign-out.
    /// </summary>
    [Fact]
    public async Task InstallWithGroupNeedsNoSignOut()
    {
        var system = new FakeSystem { HasGroup = true };
        var model = Create(system);
        await model.InstallAsync();
        Assert.False(model.SignOutRequired);
        Assert.Equal("The Fortix helper service is installed.", model.Result);
    }

    /// <summary>
    /// A cancelled elevation leaves the service missing and says why.
    /// </summary>
    [Fact]
    public async Task CancelledInstallIsExplained()
    {
        var system = new FakeSystem { Run = new InstallRun(HelperSetup.ErrorCancelled, null) };
        var model = Create(system);
        var installed = 0;
        model.Installed += (_, _) => installed++;
        await model.InstallAsync();
        Assert.StartsWith("Installation was cancelled.", model.Result, StringComparison.Ordinal);
        Assert.True(model.NeedsSetup);
        Assert.Equal(0, installed);
        Assert.True(model.CanInstall);
    }
}
