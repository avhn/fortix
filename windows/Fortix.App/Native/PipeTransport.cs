using System.ComponentModel;
using System.IO.Pipes;
using System.Runtime.InteropServices;
using Fortix.App.Model;
using Fortix.Core.Client;
using Microsoft.Win32.SafeHandles;
using Windows.Win32;
using Windows.Win32.Storage.FileSystem;

namespace Fortix.App.Native;

/// <summary>
/// The local control pipe to the helper service, opened with identification-only impersonation.
/// </summary>
/// <remarks>
/// The handle asks for read access and FILE_WRITE_DATA rather than generic write: generic write
/// also requests pipe-instance creation and attribute rights, which the helper deliberately
/// withholds from members. SECURITY_IDENTIFICATION lets the helper identify the caller without
/// being able to act as the caller. A busy pipe is retried for at most ten seconds.
/// </remarks>
internal sealed class PipeTransport : IHelperTransport, IHelperPipe
{
    /// <summary>The fixed control pipe; the app never connects anywhere else.</summary>
    public const string PipeName = @"\\.\pipe\Fortix.Control.v1";

    /// <summary>GENERIC_READ, which also includes synchronization.</summary>
    private const uint GenericRead = 0x80000000;

    /// <summary>FILE_WRITE_DATA, enough to write requests to the pipe.</summary>
    private const uint FileWriteData = 0x2;

    /// <summary>FILE_FLAG_OVERLAPPED, for cancellable asynchronous I/O.</summary>
    private const uint FileFlagOverlapped = 0x40000000;

    /// <summary>SECURITY_SQOS_PRESENT, which makes the impersonation level below apply.</summary>
    private const uint SecuritySqosPresent = 0x00100000;

    /// <summary>SECURITY_IDENTIFICATION, so the server can identify but not impersonate the caller.</summary>
    private const uint SecurityIdentification = 0x00010000;

    /// <summary>ERROR_PIPE_BUSY: every instance is in use.</summary>
    private const int ErrorPipeBusy = 231;

    /// <summary>ERROR_SEM_TIMEOUT: the wait for a free instance ran out.</summary>
    private const int ErrorSemTimeout = 121;

    /// <summary>The stream over the pipe handle.</summary>
    private readonly NamedPipeClientStream stream;

    /// <summary>
    /// Wraps an opened pipe handle.
    /// </summary>
    /// <param name="handle">The pipe handle; ownership passes to the stream.</param>
    private PipeTransport(SafePipeHandle handle) =>
        stream = new NamedPipeClientStream(PipeDirection.InOut, isAsync: true, isConnected: true, handle);

    /// <summary>
    /// Opens the control pipe, retrying a busy pipe within a ten-second budget.
    /// </summary>
    /// <param name="cancellationToken">Cancels the attempt.</param>
    /// <returns>The connected, unverified transport.</returns>
    /// <exception cref="Win32Exception">The pipe is missing or access is denied.</exception>
    /// <exception cref="TimeoutException">Every instance stayed busy.</exception>
    public static async Task<PipeTransport> OpenAsync(CancellationToken cancellationToken)
    {
        using var budget = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        budget.CancelAfter(TimeSpan.FromSeconds(10));
        var deadline = DateTime.UtcNow + TimeSpan.FromSeconds(10);
        try
        {
            while (true)
            {
                budget.Token.ThrowIfCancellationRequested();
                var file = PInvoke.CreateFile(
                    PipeName, GenericRead | FileWriteData, FILE_SHARE_MODE.FILE_SHARE_NONE, null, FILE_CREATION_DISPOSITION.OPEN_EXISTING,
                    (FILE_FLAGS_AND_ATTRIBUTES)(FileFlagOverlapped | SecuritySqosPresent | SecurityIdentification), null);
                if (!file.IsInvalid)
                {
                    var pipe = new SafePipeHandle(file.DangerousGetHandle(), ownsHandle: true);
                    file.SetHandleAsInvalid();
                    return new PipeTransport(pipe);
                }
                var error = Marshal.GetLastPInvokeError();
                file.Dispose();
                if (error != ErrorPipeBusy)
                {
                    throw new Win32Exception(error);
                }
                var remaining = (long)(deadline - DateTime.UtcNow).TotalMilliseconds;
                if (remaining <= 0)
                {
                    throw new TimeoutException("the Fortix helper service is busy");
                }
                if (!PInvoke.WaitNamedPipe(PipeName, (uint)Math.Clamp(remaining, 1, 50)))
                {
                    var waitError = Marshal.GetLastPInvokeError();
                    if (waitError is not (ErrorSemTimeout or ErrorPipeBusy))
                    {
                        throw new Win32Exception(waitError);
                    }
                }
                // Availability is advisory, so back off even when another client wins the instance.
                await Task.Delay(TimeSpan.FromMilliseconds(10), budget.Token).ConfigureAwait(false);
            }
        }
        catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
        {
            throw new TimeoutException("the Fortix helper service is busy");
        }
    }

    /// <inheritdoc/>
    public uint ServerProcessId()
    {
        if (!PInvoke.GetNamedPipeServerProcessId(stream.SafePipeHandle, out var processId))
        {
            throw new Win32Exception(Marshal.GetLastPInvokeError());
        }
        return processId;
    }

    /// <inheritdoc/>
    public ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken) =>
        stream.ReadAsync(buffer, cancellationToken);

    /// <inheritdoc/>
    public ValueTask WriteAsync(ReadOnlyMemory<byte> buffer, CancellationToken cancellationToken) =>
        stream.WriteAsync(buffer, cancellationToken);

    /// <inheritdoc/>
    public ValueTask DisposeAsync() => stream.DisposeAsync();
}
