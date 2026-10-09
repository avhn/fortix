using System.Security.Principal;
using Fortix.App.Model;
using Microsoft.Win32;

namespace Fortix.App.Native;

/// <summary>
/// Checks the current sign-in token for the local fortix group.
/// </summary>
internal sealed class GroupMembership : IGroupMembership
{
    /// <inheritdoc/>
    public bool SessionHasFortixGroup()
    {
        try
        {
            var group = (SecurityIdentifier)new NTAccount(Environment.MachineName, "fortix").Translate(typeof(SecurityIdentifier));
            using var identity = WindowsIdentity.GetCurrent();
            return identity.Groups?.Contains(group) == true;
        }
        catch (Exception e) when (e is IdentityNotMappedException or SystemException)
        {
            return false;
        }
    }
}

/// <summary>
/// The per-user Run key entry that starts Fortix at sign-in.
/// </summary>
internal sealed class RunKeyAutostart : IAutostart
{
    /// <summary>The executable the entry starts.</summary>
    private readonly string executable;

    /// <summary>
    /// Creates the adapter for the running executable.
    /// </summary>
    /// <param name="executable">The full path of FortixApp.exe.</param>
    public RunKeyAutostart(string executable) => this.executable = executable;

    /// <inheritdoc/>
    public bool IsEnabled()
    {
        using var key = Registry.CurrentUser.OpenSubKey(AutostartCommand.KeyPath);
        return AutostartCommand.Matches(key?.GetValue(AutostartCommand.ValueName), executable);
    }

    /// <inheritdoc/>
    public void SetEnabled(bool enabled)
    {
        using var key = Registry.CurrentUser.CreateSubKey(AutostartCommand.KeyPath, writable: true);
        if (enabled)
        {
            key.SetValue(AutostartCommand.ValueName, AutostartCommand.For(executable), RegistryValueKind.String);
        }
        else
        {
            key.DeleteValue(AutostartCommand.ValueName, throwOnMissingValue: false);
        }
    }
}

/// <summary>
/// Reads the light and dark choices from the per-user personalization key.
/// </summary>
internal static class ThemeReader
{
    /// <summary>
    /// Reads both values; an unreadable key yields the system defaults.
    /// </summary>
    /// <returns>The snapshot.</returns>
    public static ThemeSnapshot Read()
    {
        try
        {
            using var key = Registry.CurrentUser.OpenSubKey(ThemeDetector.KeyPath);
            return ThemeDetector.Parse(key?.GetValue(ThemeDetector.AppsValue), key?.GetValue(ThemeDetector.SystemValue));
        }
        catch (Exception e) when (e is System.Security.SecurityException or IOException or UnauthorizedAccessException)
        {
            return ThemeDetector.Parse(null, null);
        }
    }
}
