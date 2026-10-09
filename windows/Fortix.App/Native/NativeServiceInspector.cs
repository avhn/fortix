using System.ComponentModel;
using System.Runtime.InteropServices;
using Fortix.App.Model;
using Microsoft.Win32.SafeHandles;
using Windows.Wdk.System.SystemInformation;
using Windows.Win32;
using Windows.Win32.Foundation;
using Windows.Win32.Security;
using Windows.Win32.System.Services;
using Windows.Win32.System.Threading;

namespace Fortix.App.Native;

/// <summary>
/// Reads helper service and process facts with the least access each query needs.
/// </summary>
/// <remarks>
/// Every handle is opened for queries only and closed before the verifier returns. Failures
/// keep the Win32 error code so the verifier can recognize an access-denied inspection.
/// </remarks>
internal sealed unsafe class NativeServiceInspector : IServiceInspector, IHelperServiceProbe
{
    /// <summary>SC_MANAGER_CONNECT, the only service manager right needed.</summary>
    private const uint ScManagerConnect = 0x1;

    /// <summary>SERVICE_QUERY_CONFIG.</summary>
    private const uint ServiceQueryConfig = 0x1;

    /// <summary>SERVICE_QUERY_STATUS.</summary>
    private const uint ServiceQueryStatus = 0x4;

    /// <summary>ERROR_INSUFFICIENT_BUFFER.</summary>
    private const int ErrorInsufficientBuffer = 122;

    /// <summary>ERROR_SERVICE_DOES_NOT_EXIST.</summary>
    private const int ErrorServiceDoesNotExist = 1060;

    /// <summary>SystemProcessIdInformation, which names a process image without opening the process.</summary>
    private const int SystemProcessIdInformation = 88;

    /// <summary>The service state of a stopped service.</summary>
    private const uint ServiceStopped = 1;

    /// <inheritdoc/>
    public IHelperServiceQuery OpenHelperService() => Open(ServiceQueryStatus | ServiceQueryConfig);

    /// <inheritdoc/>
    public HelperServiceState Query()
    {
        try
        {
            using var service = Open(ServiceQueryStatus);
            var status = service.QueryStatus();
            return status.State switch
            {
                ServiceIdentityRules.ServiceRunning => HelperServiceState.Running,
                ServiceStopped => HelperServiceState.Stopped,
                _ => HelperServiceState.Pending,
            };
        }
        catch (Win32Exception e) when (e.NativeErrorCode == ErrorServiceDoesNotExist)
        {
            return HelperServiceState.Missing;
        }
        catch (Win32Exception)
        {
            return HelperServiceState.Unknown;
        }
    }

    /// <inheritdoc/>
    public string InstallationDirectory()
    {
        var directory = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles, Environment.SpecialFolderOption.DoNotVerify), "Fortix");
        if (!ServiceIdentityRules.ValidPath(directory))
        {
            throw new HelperIdentityException("installation directory is not a canonical local path");
        }
        return directory;
    }

    /// <inheritdoc/>
    public InspectedProcess InspectProcess(uint processId)
    {
        var raw = PInvoke.OpenProcess(PROCESS_ACCESS_RIGHTS.PROCESS_QUERY_LIMITED_INFORMATION, false, processId);
        if (raw.IsNull)
        {
            throw new Win32Exception(Marshal.GetLastPInvokeError());
        }
        var process = new SafeFileHandle((nint)raw.Value, ownsHandle: true);
        try
        {
            var image = new char[32768];
            var length = (uint)image.Length;
            if (!PInvoke.QueryFullProcessImageName(process, PROCESS_NAME_FORMAT.PROCESS_NAME_WIN32, image, ref length))
            {
                throw new Win32Exception(Marshal.GetLastPInvokeError());
            }
            var path = new string(image, 0, (int)Math.Min(length, (uint)image.Length));
            if (!PInvoke.OpenProcessToken(process, TOKEN_ACCESS_MASK.TOKEN_QUERY, out var token))
            {
                throw new Win32Exception(Marshal.GetLastPInvokeError());
            }
            using (token)
            {
                return new InspectedProcess(path, IsLocalSystem(token), process);
            }
        }
        catch
        {
            process.Dispose();
            throw;
        }
    }

    /// <inheritdoc/>
    public string KernelImageName(uint processId)
    {
        // The caller owns the name buffer, so no kernel allocation is trusted or freed.
        var buffer = new char[32767];
        fixed (char* start = buffer)
        {
            var info = new ProcessIdInformation
            {
                ProcessId = (nint)processId,
                ImageName = new UnicodeString { Length = 0, MaximumLength = (ushort)(buffer.Length * 2), Buffer = start },
            };
            var status = Windows.Wdk.PInvoke.NtQuerySystemInformation((SYSTEM_INFORMATION_CLASS)SystemProcessIdInformation, &info, (uint)sizeof(ProcessIdInformation), (uint*)null);
            if (status.Value < 0)
            {
                throw new HelperIdentityException("helper process image unavailable");
            }
            if (info.ImageName.Buffer != start || info.ImageName.Length == 0 || info.ImageName.Length % 2 != 0 || info.ImageName.Length > buffer.Length * 2)
            {
                throw new HelperIdentityException("invalid helper process image length");
            }
            return new string(start, 0, info.ImageName.Length / 2);
        }
    }

    /// <inheritdoc/>
    public string DosDeviceTarget(string drive)
    {
        var device = new char[32768];
        var count = PInvoke.QueryDosDevice(drive, device);
        if (count == 0)
        {
            throw new Win32Exception(Marshal.GetLastPInvokeError());
        }
        if (count > device.Length)
        {
            throw new HelperIdentityException("invalid helper image drive mapping");
        }
        var text = device.AsSpan(0, (int)count);
        var end = text.IndexOf('\0');
        return new string(end < 0 ? text : text[..end]);
    }

    /// <summary>
    /// Opens the helper service with the given rights.
    /// </summary>
    /// <param name="access">The service rights.</param>
    /// <returns>The query handle.</returns>
    private static ServiceQuery Open(uint access)
    {
        var manager = PInvoke.OpenSCManager((string?)null, null, ScManagerConnect);
        if (manager.IsInvalid)
        {
            var error = Marshal.GetLastPInvokeError();
            manager.Dispose();
            throw new Win32Exception(error);
        }
        var service = PInvoke.OpenService(manager, PipeServerVerifier.ServiceName, access);
        if (service.IsInvalid)
        {
            var error = Marshal.GetLastPInvokeError();
            service.Dispose();
            manager.Dispose();
            throw new Win32Exception(error);
        }
        return new ServiceQuery(manager, service);
    }

    /// <summary>
    /// Reports whether a token's user is LocalSystem.
    /// </summary>
    /// <param name="token">A token opened for query.</param>
    /// <returns>True for LocalSystem.</returns>
    private static bool IsLocalSystem(SafeHandle token)
    {
        PInvoke.GetTokenInformation(token, TOKEN_INFORMATION_CLASS.TokenUser, null, 0, out var needed);
        var error = Marshal.GetLastPInvokeError();
        if (error != ErrorInsufficientBuffer || needed < sizeof(TOKEN_USER) || needed > 4096)
        {
            throw new Win32Exception(error);
        }
        var buffer = new byte[needed];
        fixed (byte* data = buffer)
        {
            if (!PInvoke.GetTokenInformation(token, TOKEN_INFORMATION_CLASS.TokenUser, data, needed, out _))
            {
                throw new Win32Exception(Marshal.GetLastPInvokeError());
            }
            return PInvoke.IsWellKnownSid(((TOKEN_USER*)data)->User.Sid, WELL_KNOWN_SID_TYPE.WinLocalSystemSid);
        }
    }

    /// <summary>
    /// The native counted string layout used by the system information query.
    /// </summary>
    [StructLayout(LayoutKind.Sequential)]
    private struct UnicodeString
    {
        /// <summary>The used length in bytes.</summary>
        public ushort Length;

        /// <summary>The buffer size in bytes.</summary>
        public ushort MaximumLength;

        /// <summary>The caller-owned characters.</summary>
        public char* Buffer;
    }

    /// <summary>
    /// The SystemProcessIdInformation query layout: a process identifier and its image name.
    /// </summary>
    [StructLayout(LayoutKind.Sequential)]
    private struct ProcessIdInformation
    {
        /// <summary>The process to query.</summary>
        public nint ProcessId;

        /// <summary>The image name, written into caller-owned storage.</summary>
        public UnicodeString ImageName;
    }

    /// <summary>
    /// An open service manager and helper service pair, closed together.
    /// </summary>
    /// <param name="manager">The service manager handle.</param>
    /// <param name="service">The helper service handle.</param>
    private sealed class ServiceQuery(SafeHandle manager, SafeHandle service) : IHelperServiceQuery
    {
        /// <inheritdoc/>
        public ServiceProcessStatus QueryStatus()
        {
            Span<byte> buffer = stackalloc byte[sizeof(SERVICE_STATUS_PROCESS)];
            if (!PInvoke.QueryServiceStatusEx(service, SC_STATUS_TYPE.SC_STATUS_PROCESS_INFO, buffer, out _))
            {
                throw new Win32Exception(Marshal.GetLastPInvokeError());
            }
            var status = MemoryMarshal.Read<SERVICE_STATUS_PROCESS>(buffer);
            return new ServiceProcessStatus(status.dwProcessId, (uint)status.dwCurrentState, (uint)status.dwServiceType);
        }

        /// <inheritdoc/>
        public ServiceConfiguration QueryConfig()
        {
            // The size query must fail with a bounded, plausible size before anything is allocated.
            PInvoke.QueryServiceConfig(service, Span<byte>.Empty, out var needed);
            var error = Marshal.GetLastPInvokeError();
            if (error != ErrorInsufficientBuffer || needed < sizeof(QUERY_SERVICE_CONFIGW) || needed > 64 * 1024)
            {
                throw new HelperIdentityException("helper service configuration unavailable");
            }
            var buffer = new byte[needed];
            if (!PInvoke.QueryServiceConfig(service, buffer, out _))
            {
                throw new Win32Exception(Marshal.GetLastPInvokeError());
            }
            fixed (byte* data = buffer)
            {
                var config = (QUERY_SERVICE_CONFIGW*)data;
                return new ServiceConfiguration(config->lpBinaryPathName.ToString() ?? "", (uint)config->dwServiceType, config->lpServiceStartName.ToString() ?? "");
            }
        }

        /// <summary>Closes both handles.</summary>
        public void Dispose()
        {
            service.Dispose();
            manager.Dispose();
        }
    }
}
