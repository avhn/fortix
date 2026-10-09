using System.Runtime.InteropServices;
using Fortix.App.Model;
using Microsoft.Win32.SafeHandles;
using Windows.Win32;
using Windows.Win32.Foundation;
using Windows.Win32.UI.Shell;

namespace Fortix.App.Native;

/// <summary>
/// Starts the helper installer through the shell's runas verb and waits for its exit code.
/// </summary>
/// <remarks>
/// The administrator prompt is shown by Windows, so the app itself never runs elevated. The
/// shell call runs on its own single-threaded apartment thread because shell execution may load
/// COM extensions, and so the window stays responsive while the prompt is open.
/// </remarks>
internal sealed class ElevatedInstaller : IHelperInstaller
{
    /// <summary>SEE_MASK_NOCLOSEPROCESS: return the process handle to wait on.</summary>
    private const uint MaskNoCloseProcess = 0x40;

    /// <summary>SEE_MASK_NOASYNC: finish launching before returning.</summary>
    private const uint MaskNoAsync = 0x100;

    /// <summary>SEE_MASK_FLAG_NO_UI: report errors to the app instead of showing shell dialogs.</summary>
    private const uint MaskFlagNoUi = 0x400;

    /// <summary>SW_HIDE: the installer's console window stays hidden.</summary>
    private const int ShowHide = 0;

    /// <inheritdoc/>
    public async Task<InstallRun> RunElevatedAsync(string executable, string arguments, CancellationToken cancellationToken)
    {
        if (!File.Exists(executable))
        {
            return new InstallRun(HelperSetup.ErrorFileNotFound, null);
        }
        var (error, process) = await OnStaThread(() => Launch(executable, arguments)).ConfigureAwait(false);
        if (process is null)
        {
            return new InstallRun(error, null);
        }
        using (process)
        {
            while (true)
            {
                if (cancellationToken.IsCancellationRequested)
                {
                    return new InstallRun(0, null);
                }
                if (PInvoke.WaitForSingleObject(process, 0) == WAIT_EVENT.WAIT_OBJECT_0)
                {
                    break;
                }
                try
                {
                    await Task.Delay(TimeSpan.FromMilliseconds(250), cancellationToken).ConfigureAwait(false);
                }
                catch (OperationCanceledException)
                {
                    return new InstallRun(0, null);
                }
            }
            return PInvoke.GetExitCodeProcess(process, out var code) ? new InstallRun(0, unchecked((int)code)) : new InstallRun(Marshal.GetLastPInvokeError(), null);
        }
    }

    /// <summary>
    /// Calls ShellExecuteEx with the runas verb.
    /// </summary>
    /// <param name="executable">The installer path.</param>
    /// <param name="arguments">The quoted arguments.</param>
    /// <returns>The launch error and, on success, the process handle.</returns>
    private static unsafe (int Error, SafeFileHandle? Process) Launch(string executable, string arguments)
    {
        var directory = Path.GetDirectoryName(executable) ?? "";
        fixed (char* verb = "runas")
        fixed (char* file = executable)
        fixed (char* parameters = arguments)
        fixed (char* folder = directory)
        {
            var info = new SHELLEXECUTEINFOW
            {
                cbSize = (uint)sizeof(SHELLEXECUTEINFOW),
                fMask = MaskNoCloseProcess | MaskNoAsync | MaskFlagNoUi,
                lpVerb = verb,
                lpFile = file,
                lpParameters = parameters,
                lpDirectory = folder,
                nShow = ShowHide,
            };
            if (!PInvoke.ShellExecuteEx(ref info))
            {
                return (Marshal.GetLastPInvokeError(), null);
            }
            return info.hProcess.IsNull ? (0, null) : (0, new SafeFileHandle((nint)info.hProcess.Value, ownsHandle: true));
        }
    }

    /// <summary>
    /// Runs a function on a new single-threaded apartment thread.
    /// </summary>
    /// <typeparam name="T">The result type.</typeparam>
    /// <param name="function">The function.</param>
    /// <returns>The result.</returns>
    private static Task<T> OnStaThread<T>(Func<T> function)
    {
        var completion = new TaskCompletionSource<T>(TaskCreationOptions.RunContinuationsAsynchronously);
        var thread = new Thread(() =>
        {
            try
            {
                completion.SetResult(function());
            }
            catch (Exception e)
            {
                completion.SetException(e);
            }
        })
        {
            IsBackground = true,
            Name = "Fortix installer launch",
        };
        thread.SetApartmentState(ApartmentState.STA);
        thread.Start();
        return completion.Task;
    }
}
