using Fortix.App.Model;
using Fortix.App.ViewModels;

namespace Fortix.App.Tests;

/// <summary>
/// Covers theme parsing, the preferences file, and the start at sign-in entry.
/// </summary>
public sealed class ThemeAndSettingsTests
{
    /// <summary>
    /// A Run key held in memory.
    /// </summary>
    private sealed class FakeAutostart : IAutostart
    {
        /// <summary>Gets or sets the stored value.</summary>
        public string? Value { get; set; }

        /// <summary>Gets or sets whether writes are denied.</summary>
        public bool Denied { get; set; }

        /// <summary>The executable path the entry must name.</summary>
        public const string Executable = @"C:\Users\jane\Downloads\fortix\FortixApp.exe";

        /// <inheritdoc/>
        public bool IsEnabled() => AutostartCommand.Matches(Value, Executable);

        /// <inheritdoc/>
        public void SetEnabled(bool enabled)
        {
            if (Denied)
            {
                throw new UnauthorizedAccessException();
            }
            Value = enabled ? AutostartCommand.For(Executable) : null;
        }
    }

    /// <summary>
    /// Registry values parse as light for nonzero DWORD or QWORD, with per-value defaults.
    /// </summary>
    [Fact]
    public void ParsesThemeValues()
    {
        Assert.Equal(new ThemeSnapshot(true, false), ThemeDetector.Parse(null, null));
        Assert.Equal(new ThemeSnapshot(false, true), ThemeDetector.Parse(0, 1));
        Assert.Equal(new ThemeSnapshot(true, true), ThemeDetector.Parse(1L, 2));
        Assert.Equal(new ThemeSnapshot(false, false), ThemeDetector.Parse(0L, 0L));
        Assert.Equal(new ThemeSnapshot(true, false), ThemeDetector.Parse("0", new byte[] { 1 }));
        Assert.True(ThemeDetector.IsThemeChange("ImmersiveColorSet"));
        Assert.False(ThemeDetector.IsThemeChange("immersivecolorset"));
        Assert.False(ThemeDetector.IsThemeChange(null));
        Assert.False(ThemeDetector.IsThemeChange("Policy"));
    }

    /// <summary>
    /// Preferences round-trip, and a missing or damaged file yields defaults.
    /// </summary>
    [Fact]
    public void SettingsFileRoundTrips()
    {
        var directory = Directory.CreateTempSubdirectory("fortix-settings-");
        try
        {
            var path = Path.Combine(directory.FullName, "Fortix", "FortixApp.json");
            var store = new AppSettingsStore(path);
            Assert.True(store.Load().AnimateIcon);
            store.Save(new AppSettings { AnimateIcon = false });
            using (var written = System.Text.Json.JsonDocument.Parse(File.ReadAllBytes(path)))
            {
                Assert.False(written.RootElement.GetProperty("animate_icon").GetBoolean());
            }
            Assert.False(store.Load().AnimateIcon);
            File.WriteAllText(path, "{not json");
            Assert.True(store.Load().AnimateIcon);
            Assert.False(File.Exists(path + ".tmp"));
        }
        finally
        {
            directory.Delete(recursive: true);
        }
    }

    /// <summary>
    /// Start at sign-in is off by default, writes the quoted background command, and shows the real value.
    /// </summary>
    [Fact]
    public void AutostartFollowsRunKey()
    {
        var directory = Directory.CreateTempSubdirectory("fortix-settings-");
        try
        {
            var autostart = new FakeAutostart();
            var model = new SettingsViewModel(new AppSettingsStore(Path.Combine(directory.FullName, "FortixApp.json")), autostart);
            Assert.False(model.StartAtSignIn);
            model.StartAtSignIn = true;
            Assert.Equal("\"" + FakeAutostart.Executable + "\" --background", autostart.Value);
            Assert.True(model.StartAtSignIn);
            autostart.Value = "\"C:\\Old\\FortixApp.exe\" --background";
            Assert.False(autostart.IsEnabled());
            autostart.Denied = true;
            model.StartAtSignIn = true;
            Assert.False(model.StartAtSignIn);
            Assert.Equal("Start at sign-in could not be changed.", model.Message);
            model.AnimateIcon = false;
            Assert.False(new AppSettingsStore(Path.Combine(directory.FullName, "FortixApp.json")).Load().AnimateIcon);
        }
        finally
        {
            directory.Delete(recursive: true);
        }
    }
}
