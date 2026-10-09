using System.Text;

namespace Fortix.App.Model;

/// <summary>
/// Operating-system facts about the pipe server and the helper service, never claims made by the peer.
/// </summary>
/// <param name="PipeProcessId">The process that owns the server end of the pipe.</param>
/// <param name="ServiceProcessId">The process the service manager reports for the helper service.</param>
/// <param name="State">The service state reported with that process.</param>
/// <param name="ServiceType">The service type reported with that process.</param>
/// <param name="ConfigType">The service type in the stored service configuration.</param>
/// <param name="Image">The image path of the pipe server process.</param>
/// <param name="Binary">The configured service command, possibly quoted.</param>
/// <param name="Directory">The trusted installation directory under Program Files.</param>
/// <param name="LocalSystem">Whether the server process runs as LocalSystem.</param>
public sealed record ServiceIdentity(
    uint PipeProcessId,
    uint ServiceProcessId,
    uint State,
    uint ServiceType,
    uint ConfigType,
    string Image,
    string Binary,
    string Directory,
    bool LocalSystem);

/// <summary>
/// The decision rules that accept a pipe server as the installed helper service.
/// </summary>
/// <remarks>
/// These mirror the command-line client check by check. An unrelated process that wins the
/// pipe name, a service started from another directory, or a service with extra arguments
/// is rejected before the app writes a single byte to it.
/// </remarks>
public static class ServiceIdentityRules
{
    /// <summary>The service state of a running service.</summary>
    public const uint ServiceRunning = 4;

    /// <summary>The service type of a service that owns its process.</summary>
    public const uint ServiceWin32OwnProcess = 0x10;

    /// <summary>The Win32 error the system returns when a handle is denied.</summary>
    public const int ErrorAccessDenied = 5;

    /// <summary>
    /// Removes one pair of surrounding quotes without touching arguments or path aliases.
    /// </summary>
    /// <param name="binary">The configured service command.</param>
    /// <returns>The command without its enclosing quotes.</returns>
    public static string UnquotedServiceBinary(string binary)
    {
        ArgumentNullException.ThrowIfNull(binary);
        return binary.Length >= 2 && binary[0] == '"' && binary[^1] == '"' ? binary[1..^1] : binary;
    }

    /// <summary>
    /// Rejects an unrelated process even when it owns the expected pipe name.
    /// </summary>
    /// <param name="identity">The observed facts.</param>
    /// <exception cref="HelperIdentityException">The process is not the installed, running helper service.</exception>
    public static void Validate(ServiceIdentity identity)
    {
        ArgumentNullException.ThrowIfNull(identity);
        if (identity.PipeProcessId == 0 || identity.PipeProcessId != identity.ServiceProcessId ||
            identity.State != ServiceRunning || identity.ServiceType != ServiceWin32OwnProcess ||
            identity.ConfigType != ServiceWin32OwnProcess || !identity.LocalSystem)
        {
            throw new HelperIdentityException("unexpected helper service identity");
        }
        var binary = UnquotedServiceBinary(identity.Binary);
        if (!ValidPath(binary) || !ValidPath(identity.Image) || !ValidPath(identity.Directory) ||
            !string.Equals(binary, identity.Image, StringComparison.OrdinalIgnoreCase))
        {
            throw new HelperIdentityException("unexpected helper service image");
        }
        var prefix = identity.Directory.TrimEnd('\\') + "\\";
        if (!identity.Image.StartsWith(prefix, StringComparison.OrdinalIgnoreCase) ||
            string.Equals(identity.Image, identity.Directory, StringComparison.OrdinalIgnoreCase))
        {
            throw new HelperIdentityException("helper image is outside the installation directory");
        }
    }

    /// <summary>
    /// Compares the kernel's device-form image with the configured drive path.
    /// </summary>
    /// <remarks>
    /// Used only when the service process denies inspection. The kernel reports the image as
    /// <c>\Device\HarddiskVolumeN\...</c>, so the configured path's drive is mapped to its
    /// device and the rest must match exactly, ignoring case.
    /// </remarks>
    /// <param name="kernelImage">The kernel image name for the process.</param>
    /// <param name="volumeDevice">The device the configured drive maps to.</param>
    /// <param name="binary">The configured service command.</param>
    /// <returns>The configured image, now confirmed by the kernel.</returns>
    /// <exception cref="HelperIdentityException">The mapping is ambiguous or does not match.</exception>
    public static string MatchKernelImage(string kernelImage, string volumeDevice, string binary)
    {
        ArgumentNullException.ThrowIfNull(kernelImage);
        ArgumentNullException.ThrowIfNull(volumeDevice);
        binary = UnquotedServiceBinary(binary ?? "");
        if (!ValidPath(binary))
        {
            throw new HelperIdentityException("unexpected helper service image");
        }
        if (!volumeDevice.StartsWith(@"\device\", StringComparison.OrdinalIgnoreCase) ||
            !string.Equals(kernelImage, volumeDevice + binary[2..], StringComparison.OrdinalIgnoreCase))
        {
            throw new HelperIdentityException("unexpected helper service image");
        }
        return binary;
    }

    /// <summary>
    /// Accepts canonical local drive paths, excluding devices, streams, and traversal.
    /// </summary>
    /// <param name="path">The candidate path.</param>
    /// <returns>True for a path such as <c>C:\Program Files\Fortix\fortix-helper.exe</c>.</returns>
    public static bool ValidPath(string? path)
    {
        if (path is null || path.Length < 3 || !char.IsAsciiLetter(path[0]) || path[1] != ':' || path[2] != '\\' ||
            path.AsSpan(2).IndexOfAny(':', '/') >= 0 || HasControl(path) || !IsWellFormedUtf16(path))
        {
            return false;
        }
        if (path.Length == 3)
        {
            return true;
        }
        foreach (var part in path[3..].Split('\\'))
        {
            if (!ValidName(part))
            {
                return false;
            }
        }
        return true;
    }

    /// <summary>
    /// Accepts one ordinary path component without normalization aliases or reserved device names.
    /// </summary>
    /// <param name="name">The component.</param>
    /// <returns>True for an ordinary file or directory name.</returns>
    internal static bool ValidName(string name)
    {
        // An empty component also rejects doubled or trailing separators, which Clean would remove.
        if (name.Length == 0 || name is "." or ".." || name.AsSpan().IndexOfAny("\\/:*?\"<>|") >= 0 ||
            HasControl(name) || name.TrimEnd('.', ' ').Length != name.Length)
        {
            return false;
        }
        var dot = name.IndexOf('.', StringComparison.Ordinal);
        var stem = (dot < 0 ? name : name[..dot]).ToUpperInvariant();
        if (stem is "CON" or "PRN" or "AUX" or "NUL" or "CONIN$" or "CONOUT$")
        {
            return false;
        }
        var runes = stem.EnumerateRunes().ToArray();
        return !(runes.Length == 4 && (stem.StartsWith("COM", StringComparison.Ordinal) || stem.StartsWith("LPT", StringComparison.Ordinal)) &&
            "123456789\u00b9\u00b2\u00b3".Contains(runes[3].ToString(), StringComparison.Ordinal));
    }

    /// <summary>
    /// Reports whether the text contains a Unicode control character.
    /// </summary>
    /// <param name="text">The text to check.</param>
    /// <returns>True when any code point is a control character.</returns>
    private static bool HasControl(string text)
    {
        foreach (var rune in text.EnumerateRunes())
        {
            if (Rune.IsControl(rune))
            {
                return true;
            }
        }
        return false;
    }

    /// <summary>
    /// Rejects unpaired surrogates, which the command-line client rejects as invalid UTF-8.
    /// </summary>
    /// <param name="text">The text to check.</param>
    /// <returns>True when the text converts to UTF-8 without replacement.</returns>
    private static bool IsWellFormedUtf16(string text)
    {
        for (var i = 0; i < text.Length; i++)
        {
            if (char.IsHighSurrogate(text[i]) && i + 1 < text.Length && char.IsLowSurrogate(text[i + 1]))
            {
                i++;
            }
            else if (char.IsSurrogate(text[i]))
            {
                return false;
            }
        }
        return true;
    }
}

/// <summary>
/// Thrown when the pipe server is not the installed helper service; the message names the failed check only.
/// </summary>
public sealed class HelperIdentityException : Exception
{
    /// <summary>
    /// Creates the exception with a fixed explanation.
    /// </summary>
    /// <param name="message">The failed check.</param>
    public HelperIdentityException(string message)
        : base(message)
    {
    }
}
