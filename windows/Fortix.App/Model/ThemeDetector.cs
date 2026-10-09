namespace Fortix.App.Model;

/// <summary>
/// The light or dark choices Windows records for apps and for the taskbar.
/// </summary>
/// <param name="AppsLight">Whether windows use the light theme (AppsUseLightTheme).</param>
/// <param name="TaskbarLight">Whether the taskbar and notification area are light (SystemUsesLightTheme).</param>
public readonly record struct ThemeSnapshot(bool AppsLight, bool TaskbarLight);

/// <summary>
/// Interprets the personalization registry values without touching the registry.
/// </summary>
/// <remarks>
/// Windows stores the choices as DWORDs under
/// HKCU\Software\Microsoft\Windows\CurrentVersion\Themes\Personalize, 0 for dark and 1 for
/// light. A missing or malformed value means the system default, which is light for apps.
/// Windows 10 shipped a dark taskbar by default, so a missing taskbar value means dark.
/// </remarks>
public static class ThemeDetector
{
    /// <summary>The per-user key holding both values.</summary>
    public const string KeyPath = @"Software\Microsoft\Windows\CurrentVersion\Themes\Personalize";

    /// <summary>The value for application windows.</summary>
    public const string AppsValue = "AppsUseLightTheme";

    /// <summary>The value for the taskbar, Start, and the notification area.</summary>
    public const string SystemValue = "SystemUsesLightTheme";

    /// <summary>
    /// Interprets one registry value.
    /// </summary>
    /// <param name="value">The raw value, or null when absent.</param>
    /// <param name="fallback">The result for an absent or malformed value.</param>
    /// <returns>True for light.</returns>
    public static bool IsLight(object? value, bool fallback) => value switch
    {
        int dword => dword != 0,
        long qword => qword != 0,
        _ => fallback,
    };

    /// <summary>
    /// Builds a snapshot from the two raw values.
    /// </summary>
    /// <param name="apps">The AppsUseLightTheme value.</param>
    /// <param name="system">The SystemUsesLightTheme value.</param>
    /// <returns>The snapshot.</returns>
    public static ThemeSnapshot Parse(object? apps, object? system) =>
        new(IsLight(apps, fallback: true), IsLight(system, fallback: false));

    /// <summary>
    /// Reports whether a WM_SETTINGCHANGE parameter announces a theme change.
    /// </summary>
    /// <param name="area">The string the message's lParam points to, or null.</param>
    /// <returns>True for the ImmersiveColorSet notification.</returns>
    public static bool IsThemeChange(string? area) => string.Equals(area, "ImmersiveColorSet", StringComparison.Ordinal);
}
