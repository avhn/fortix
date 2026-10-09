using System.ComponentModel;
using Fortix.Core.Client;

namespace Fortix.App.Model;

/// <summary>
/// A connected helper pipe whose server process the system can name.
/// </summary>
public interface IHelperPipe
{
    /// <summary>
    /// Returns the process identifier of the pipe's server end, as reported by the system.
    /// </summary>
    /// <returns>The server process identifier.</returns>
    uint ServerProcessId();
}

/// <summary>
/// The status the service manager reports for the helper service's process.
/// </summary>
/// <param name="ProcessId">The service process identifier, zero when stopped.</param>
/// <param name="State">The current service state.</param>
/// <param name="ServiceType">The reported service type.</param>
public readonly record struct ServiceProcessStatus(uint ProcessId, uint State, uint ServiceType);

/// <summary>
/// The stored helper service configuration fields that verification depends on.
/// </summary>
/// <param name="Binary">The configured command, possibly quoted.</param>
/// <param name="ServiceType">The configured service type.</param>
/// <param name="Account">The configured service account, such as LocalSystem.</param>
public sealed record ServiceConfiguration(string Binary, uint ServiceType, string Account);

/// <summary>
/// Facts read from an inspected process; the handle pins the process identifier until disposal.
/// </summary>
public sealed class InspectedProcess : IDisposable
{
    /// <summary>The open process handle, or null when inspection used no handle.</summary>
    private readonly IDisposable? handle;

    /// <summary>
    /// Creates the facts and takes ownership of the optional process handle.
    /// </summary>
    /// <param name="image">The full image path.</param>
    /// <param name="localSystem">Whether the process token user is LocalSystem.</param>
    /// <param name="handle">The process handle to release on disposal, if any.</param>
    public InspectedProcess(string image, bool localSystem, IDisposable? handle)
    {
        Image = image;
        LocalSystem = localSystem;
        this.handle = handle;
    }

    /// <summary>Gets the full image path.</summary>
    public string Image { get; }

    /// <summary>Gets whether the process runs as LocalSystem.</summary>
    public bool LocalSystem { get; }

    /// <summary>Releases the process handle.</summary>
    public void Dispose() => handle?.Dispose();
}

/// <summary>
/// A least-access query handle for the helper service.
/// </summary>
public interface IHelperServiceQuery : IDisposable
{
    /// <summary>
    /// Reads the service's current process status.
    /// </summary>
    /// <returns>The status.</returns>
    ServiceProcessStatus QueryStatus();

    /// <summary>
    /// Reads the stored service configuration.
    /// </summary>
    /// <returns>The configuration.</returns>
    ServiceConfiguration QueryConfig();
}

/// <summary>
/// The operating system queries pipe server verification needs, injectable for tests.
/// </summary>
/// <remarks>
/// Every method throws <see cref="Win32Exception"/> on failure so the verifier can single out
/// an access-denied process inspection, the only failure that has a fallback.
/// </remarks>
public interface IServiceInspector
{
    /// <summary>
    /// Opens the helper service with status and configuration query rights only.
    /// </summary>
    /// <returns>The query handle.</returns>
    IHelperServiceQuery OpenHelperService();

    /// <summary>
    /// Returns the trusted installation directory, Program Files\Fortix.
    /// </summary>
    /// <returns>The directory path.</returns>
    string InstallationDirectory();

    /// <summary>
    /// Opens the process with limited query rights and reads its image and token user.
    /// </summary>
    /// <param name="processId">The process to inspect.</param>
    /// <returns>The facts with the open process handle.</returns>
    InspectedProcess InspectProcess(uint processId);

    /// <summary>
    /// Returns the kernel's device-form image name for a process without opening it.
    /// </summary>
    /// <param name="processId">The process to query.</param>
    /// <returns>The image name, such as \Device\HarddiskVolume3\Program Files\Fortix\fortix-helper.exe.</returns>
    string KernelImageName(uint processId);

    /// <summary>
    /// Returns the first device a drive letter maps to.
    /// </summary>
    /// <param name="drive">The drive, such as C:.</param>
    /// <returns>The device path.</returns>
    string DosDeviceTarget(string drive);
}

/// <summary>
/// Proves the pipe server is the running FortixHelper service before any byte is exchanged.
/// </summary>
/// <remarks>
/// The sequence matches the command-line client: the pipe's server process must be the
/// service's process, the service must be running in its own process, the image must be the
/// configured binary inside Program Files\Fortix, and the process must run as LocalSystem.
/// If the process denies inspection, the configured account must name LocalSystem and the
/// kernel must confirm the image independently. The status is read again at the end so a
/// service that stopped or restarted during the checks is rejected.
/// </remarks>
public sealed class PipeServerVerifier : IServerVerifier
{
    /// <summary>The service manager name of the helper.</summary>
    public const string ServiceName = "FortixHelper";

    /// <summary>The system queries.</summary>
    private readonly IServiceInspector inspector;

    /// <summary>
    /// Creates a verifier over the given system queries.
    /// </summary>
    /// <param name="inspector">The system queries.</param>
    public PipeServerVerifier(IServiceInspector inspector)
    {
        ArgumentNullException.ThrowIfNull(inspector);
        this.inspector = inspector;
    }

    /// <inheritdoc/>
    public ValueTask VerifyAsync(IHelperTransport transport, CancellationToken cancellationToken)
    {
        try
        {
            Verify(transport, cancellationToken);
            return ValueTask.CompletedTask;
        }
        catch (Exception e)
        {
            return ValueTask.FromException(e);
        }
    }

    /// <summary>
    /// Runs the verification sequence synchronously.
    /// </summary>
    /// <param name="transport">The connected, unused transport.</param>
    /// <param name="cancellationToken">Checked before and after the system queries.</param>
    /// <exception cref="HelperIdentityException">A check failed.</exception>
    public void Verify(IHelperTransport transport, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        if (transport is not IHelperPipe pipe)
        {
            throw new HelperIdentityException("transport has no verifiable pipe handle");
        }
        var pipeProcessId = pipe.ServerProcessId();
        using var service = inspector.OpenHelperService();
        var status = service.QueryStatus();
        if (pipeProcessId == 0 || pipeProcessId != status.ProcessId || status.State != ServiceIdentityRules.ServiceRunning ||
            status.ServiceType != ServiceIdentityRules.ServiceWin32OwnProcess)
        {
            throw new HelperIdentityException("pipe owner is not the running helper service");
        }
        var config = service.QueryConfig();
        var directory = inspector.InstallationDirectory();
        using var process = InspectWithFallback(pipeProcessId, config);
        // Recheck after either inspection path so a stopped or replaced service cannot be accepted.
        if (service.QueryStatus() != status)
        {
            throw new HelperIdentityException("helper service changed during verification");
        }
        cancellationToken.ThrowIfCancellationRequested();
        ServiceIdentityRules.Validate(new ServiceIdentity(
            pipeProcessId, status.ProcessId, status.State, status.ServiceType, config.ServiceType,
            process.Image, config.Binary, directory, process.LocalSystem));
    }

    /// <summary>
    /// Inspects the process, falling back to configured facts only when inspection is denied.
    /// </summary>
    /// <remarks>
    /// Any other failure, and any observed non-System token, stays a failure; the configured
    /// account is trusted only when the process cannot be opened at all.
    /// </remarks>
    /// <param name="processId">The server process.</param>
    /// <param name="config">The stored service configuration.</param>
    /// <returns>The process facts.</returns>
    private InspectedProcess InspectWithFallback(uint processId, ServiceConfiguration config)
    {
        try
        {
            return inspector.InspectProcess(processId);
        }
        catch (Win32Exception e) when (e.NativeErrorCode == ServiceIdentityRules.ErrorAccessDenied)
        {
            // Handled below without a process handle.
        }
        if (!string.Equals(config.Account, "LocalSystem", StringComparison.OrdinalIgnoreCase))
        {
            throw new HelperIdentityException("unexpected helper service account");
        }
        var binary = ServiceIdentityRules.UnquotedServiceBinary(config.Binary);
        if (processId == 0 || !ServiceIdentityRules.ValidPath(binary))
        {
            throw new HelperIdentityException("unexpected helper service image");
        }
        var image = ServiceIdentityRules.MatchKernelImage(inspector.KernelImageName(processId), inspector.DosDeviceTarget(binary[..2]), binary);
        return new InspectedProcess(image, localSystem: true, handle: null);
    }
}
