using System.Text.Json;
using System.Text.Json.Serialization;

namespace Fortix.App.Model;

/// <summary>
/// Per-user app preferences; nothing here is a secret or a profile, which the helper owns.
/// </summary>
public sealed class AppSettings
{
    /// <summary>Gets or sets whether the connecting ring rotates; reduced motion still stops it.</summary>
    [JsonPropertyName("animate_icon")]
    public bool AnimateIcon { get; set; } = true;
}

/// <summary>
/// Source-generated serialization for <see cref="AppSettings"/>.
/// </summary>
[JsonSerializable(typeof(AppSettings))]
[JsonSourceGenerationOptions(WriteIndented = true)]
internal sealed partial class AppSettingsJsonContext : JsonSerializerContext
{
}

/// <summary>
/// Loads and saves <see cref="AppSettings"/> as a small JSON file.
/// </summary>
/// <remarks>
/// The file lives in LocalAppData\Fortix next to the command-line client's own preferences but
/// under a separate name, so neither program rewrites the other's file. A missing, oversized, or
/// malformed file yields defaults rather than an error, because preferences are never critical.
/// </remarks>
public sealed class AppSettingsStore
{
    /// <summary>The largest settings file that is read.</summary>
    private const int MaxBytes = 64 * 1024;

    /// <summary>The settings file path.</summary>
    private readonly string path;

    /// <summary>
    /// Creates a store for one file.
    /// </summary>
    /// <param name="path">The settings file path.</param>
    public AppSettingsStore(string path)
    {
        ArgumentException.ThrowIfNullOrEmpty(path);
        this.path = path;
    }

    /// <summary>
    /// Returns the default per-user location, LocalAppData\Fortix\FortixApp.json.
    /// </summary>
    /// <returns>The path.</returns>
    public static string DefaultPath() =>
        Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "Fortix", "FortixApp.json");

    /// <summary>
    /// Reads the settings, falling back to defaults for any problem.
    /// </summary>
    /// <returns>The settings.</returns>
    public AppSettings Load()
    {
        try
        {
            var info = new FileInfo(path);
            if (!info.Exists || info.Length > MaxBytes)
            {
                return new AppSettings();
            }
            return JsonSerializer.Deserialize(File.ReadAllBytes(path), AppSettingsJsonContext.Default.AppSettings) ?? new AppSettings();
        }
        catch (Exception e) when (e is IOException or UnauthorizedAccessException or JsonException)
        {
            return new AppSettings();
        }
    }

    /// <summary>
    /// Writes the settings through a temporary file so a crash never leaves a truncated file.
    /// </summary>
    /// <param name="settings">The settings.</param>
    /// <exception cref="IOException">The file cannot be written.</exception>
    public void Save(AppSettings settings)
    {
        ArgumentNullException.ThrowIfNull(settings);
        Directory.CreateDirectory(Path.GetDirectoryName(path)!);
        var temporary = path + ".tmp";
        File.WriteAllBytes(temporary, JsonSerializer.SerializeToUtf8Bytes(settings, AppSettingsJsonContext.Default.AppSettings));
        File.Move(temporary, path, overwrite: true);
    }
}

/// <summary>
/// The optional per-user start at sign-in entry, read from its real location each time.
/// </summary>
public interface IAutostart
{
    /// <summary>
    /// Reports whether the entry exists and starts this executable.
    /// </summary>
    /// <returns>True when Fortix starts at sign-in.</returns>
    bool IsEnabled();

    /// <summary>
    /// Adds or removes the entry.
    /// </summary>
    /// <param name="enabled">Whether Fortix should start at sign-in.</param>
    void SetEnabled(bool enabled);
}

/// <summary>
/// Builds and recognizes the Run key command for the app.
/// </summary>
public static class AutostartCommand
{
    /// <summary>The per-user Run key.</summary>
    public const string KeyPath = @"Software\Microsoft\Windows\CurrentVersion\Run";

    /// <summary>The value name under the Run key.</summary>
    public const string ValueName = "Fortix";

    /// <summary>The argument that starts the app in the notification area without opening a window.</summary>
    public const string BackgroundArgument = "--background";

    /// <summary>
    /// Returns the command stored in the Run key: the quoted executable path and the background flag.
    /// </summary>
    /// <param name="executable">The full path of FortixApp.exe.</param>
    /// <returns>The command line.</returns>
    public static string For(string executable)
    {
        ArgumentException.ThrowIfNullOrEmpty(executable);
        return "\"" + executable + "\" " + BackgroundArgument;
    }

    /// <summary>
    /// Reports whether a stored command starts the given executable, so a stale path counts as disabled.
    /// </summary>
    /// <param name="stored">The stored value, or null.</param>
    /// <param name="executable">The current executable path.</param>
    /// <returns>True when the stored command matches.</returns>
    public static bool Matches(object? stored, string executable) =>
        stored is string text && string.Equals(text, For(executable), StringComparison.OrdinalIgnoreCase);
}
