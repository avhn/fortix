using System.Text;

namespace Fortix.App.Model;

/// <summary>
/// The helper service's state as the service manager reports it.
/// </summary>
public enum HelperServiceState
{
    /// <summary>The state could not be read.</summary>
    Unknown,

    /// <summary>No FortixHelper service is registered.</summary>
    Missing,

    /// <summary>The service is registered but stopped.</summary>
    Stopped,

    /// <summary>The service is starting, stopping, or paused.</summary>
    Pending,

    /// <summary>The service is running.</summary>
    Running,
}

/// <summary>
/// Reads the helper service state without any rights beyond status queries.
/// </summary>
public interface IHelperServiceProbe
{
    /// <summary>
    /// Returns the current helper service state.
    /// </summary>
    /// <returns>The state.</returns>
    HelperServiceState Query();
}

/// <summary>
/// How an elevated installer launch ended.
/// </summary>
/// <param name="LaunchError">The Win32 error from starting the installer, or 0 when it started.</param>
/// <param name="ExitCode">The installer's exit code, or null when it did not finish.</param>
public readonly record struct InstallRun(int LaunchError, int? ExitCode);

/// <summary>
/// Starts the bundled helper installer elevated and waits for it.
/// </summary>
public interface IHelperInstaller
{
    /// <summary>
    /// Runs <c>fortix-helper.exe install --user NAME</c> elevated and waits for it to exit.
    /// </summary>
    /// <param name="executable">The installer path next to the app.</param>
    /// <param name="arguments">The complete, quoted argument string.</param>
    /// <param name="cancellationToken">Stops waiting; the elevated process keeps running.</param>
    /// <returns>The launch result.</returns>
    Task<InstallRun> RunElevatedAsync(string executable, string arguments, CancellationToken cancellationToken);
}

/// <summary>
/// The user-facing result of an installer run.
/// </summary>
public enum InstallOutcome
{
    /// <summary>The service is installed and the account is enrolled.</summary>
    Installed,

    /// <summary>The user declined the administrator prompt.</summary>
    Cancelled,

    /// <summary>fortix-helper.exe is not next to the app.</summary>
    InstallerMissing,

    /// <summary>The installer ran and failed.</summary>
    Failed,

    /// <summary>The installer could not be started for another reason.</summary>
    LaunchFailed,

    /// <summary>The installer did not finish in time.</summary>
    TimedOut,
}

/// <summary>
/// Builds the installer command and explains its result, independent of the system calls.
/// </summary>
/// <remarks>
/// The helper exits 0 on success and 1 on any failure, printing the reason to an elevated
/// console the app cannot read, so a failure points the user at the same command in an
/// administrator terminal where the reason is visible.
/// </remarks>
public static class HelperSetup
{
    /// <summary>The installer and service executable shipped next to the app.</summary>
    public const string HelperExecutable = "fortix-helper.exe";

    /// <summary>The Win32 error for a missing file.</summary>
    public const int ErrorFileNotFound = 2;

    /// <summary>The Win32 error for a missing path.</summary>
    public const int ErrorPathNotFound = 3;

    /// <summary>The Win32 error when the user declines elevation.</summary>
    public const int ErrorCancelled = 1223;

    /// <summary>
    /// Reports whether the app runs from the installed helper directory, where install refuses to run.
    /// </summary>
    /// <remarks>
    /// The installer must run from the extracted release directory: replacing the installed
    /// image with itself is refused, so the setup page explains this instead of failing.
    /// </remarks>
    /// <param name="appDirectory">The directory holding FortixApp.exe.</param>
    /// <param name="installDirectory">Program Files\Fortix.</param>
    /// <returns>True when both name the same directory.</returns>
    public static bool RunsFromInstalledCopy(string appDirectory, string installDirectory)
    {
        ArgumentNullException.ThrowIfNull(appDirectory);
        ArgumentNullException.ThrowIfNull(installDirectory);
        return string.Equals(appDirectory.TrimEnd('\\'), installDirectory.TrimEnd('\\'), StringComparison.OrdinalIgnoreCase);
    }

    /// <summary>
    /// Builds the argument string <c>install --user "DOMAIN\name"</c>.
    /// </summary>
    /// <param name="user">The account to enroll, normally DOMAIN\name of the signed-in user.</param>
    /// <returns>The quoted arguments.</returns>
    /// <exception cref="ArgumentException">The account name cannot be passed safely.</exception>
    public static string InstallArguments(string user)
    {
        if (!ValidUser(user))
        {
            throw new ArgumentException("the account name cannot be used for installation", nameof(user));
        }
        return "install --user " + QuoteArgument(user);
    }

    /// <summary>
    /// Accepts an account name that is non-empty, bounded, free of control characters and quotes, and not an option.
    /// </summary>
    /// <param name="user">The account name.</param>
    /// <returns>True when the name is safe to pass.</returns>
    public static bool ValidUser(string? user) =>
        !string.IsNullOrWhiteSpace(user) && user.Length <= 256 && user[0] != '-' &&
        !user.Contains('"', StringComparison.Ordinal) && !user.Any(char.IsControl);

    /// <summary>
    /// Quotes one argument so the standard Windows command-line parser returns it unchanged.
    /// </summary>
    /// <param name="value">The argument.</param>
    /// <returns>The quoted argument.</returns>
    public static string QuoteArgument(string value)
    {
        ArgumentNullException.ThrowIfNull(value);
        var builder = new StringBuilder("\"");
        var backslashes = 0;
        foreach (var c in value)
        {
            if (c == '\\')
            {
                backslashes++;
                continue;
            }
            // Backslashes are literal unless they precede a quote, where each must be doubled.
            builder.Append('\\', c == '"' ? (backslashes * 2) + 1 : backslashes);
            backslashes = 0;
            builder.Append(c);
        }
        builder.Append('\\', backslashes * 2).Append('"');
        return builder.ToString();
    }

    /// <summary>
    /// Classifies an installer run.
    /// </summary>
    /// <param name="run">The launch result.</param>
    /// <returns>The outcome.</returns>
    public static InstallOutcome Classify(InstallRun run) => run switch
    {
        { LaunchError: ErrorCancelled } => InstallOutcome.Cancelled,
        { LaunchError: ErrorFileNotFound or ErrorPathNotFound } => InstallOutcome.InstallerMissing,
        { LaunchError: not 0 } => InstallOutcome.LaunchFailed,
        { ExitCode: null } => InstallOutcome.TimedOut,
        { ExitCode: 0 } => InstallOutcome.Installed,
        _ => InstallOutcome.Failed,
    };

    /// <summary>
    /// Explains an installer run in plain language.
    /// </summary>
    /// <param name="run">The launch result.</param>
    /// <param name="user">The account that was enrolled.</param>
    /// <returns>The message for the setup page.</returns>
    public static string Describe(InstallRun run, string user) => Classify(run) switch
    {
        InstallOutcome.Installed => "The Fortix helper service is installed.",
        InstallOutcome.Cancelled => "Installation was cancelled. Installing the helper service needs administrator approval.",
        InstallOutcome.InstallerMissing => "fortix-helper.exe was not found next to FortixApp.exe. Extract the complete release archive and start FortixApp.exe from that folder.",
        InstallOutcome.LaunchFailed => $"The installer could not be started (Windows error {run.LaunchError}).",
        InstallOutcome.TimedOut => "The installer did not finish in time. Check whether an installer window is still open.",
        _ => $"The installation failed (exit code {run.ExitCode}). To see the reason, open an administrator terminal in the extracted release folder and run: fortix-helper.exe install --user {QuoteArgument(user)}",
    };
}

/// <summary>
/// Reports whether the signed-in session already carries the fortix group.
/// </summary>
/// <remarks>
/// Group membership is fixed when Windows creates the sign-in token, so an account the installer
/// has just added gains helper access only after signing out and back in.
/// </remarks>
public interface IGroupMembership
{
    /// <summary>
    /// Returns whether the current process token includes the local fortix group.
    /// </summary>
    /// <returns>True when the group is present, false when it is absent or does not exist.</returns>
    bool SessionHasFortixGroup();
}
