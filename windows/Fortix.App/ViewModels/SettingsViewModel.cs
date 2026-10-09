using Fortix.App.Model;

namespace Fortix.App.ViewModels;

/// <summary>
/// App preferences: the connecting animation and the optional start at sign-in.
/// </summary>
public sealed class SettingsViewModel : ObservableObject
{
    /// <summary>The preferences file.</summary>
    private readonly AppSettingsStore store;

    /// <summary>The Run key entry.</summary>
    private readonly IAutostart autostart;

    /// <summary>The loaded preferences.</summary>
    private readonly AppSettings settings;

    /// <summary>Whether Fortix starts at sign-in, as last read from the Run key.</summary>
    private bool startAtSignIn;

    /// <summary>The last failure, or null.</summary>
    private string? message;

    /// <summary>
    /// Loads the preferences and reads the real autostart state.
    /// </summary>
    /// <param name="store">The preferences file.</param>
    /// <param name="autostart">The Run key entry.</param>
    public SettingsViewModel(AppSettingsStore store, IAutostart autostart)
    {
        ArgumentNullException.ThrowIfNull(store);
        ArgumentNullException.ThrowIfNull(autostart);
        this.store = store;
        this.autostart = autostart;
        settings = store.Load();
        startAtSignIn = autostart.IsEnabled();
    }

    /// <summary>Gets or sets whether the connecting ring rotates; reduced motion still stops it.</summary>
    public bool AnimateIcon
    {
        get => settings.AnimateIcon;
        set
        {
            if (settings.AnimateIcon == value)
            {
                return;
            }
            settings.AnimateIcon = value;
            OnPropertyChanged();
            try
            {
                store.Save(settings);
            }
            catch (Exception e) when (e is IOException or UnauthorizedAccessException)
            {
                Message = "The preference could not be saved.";
            }
        }
    }

    /// <summary>Gets or sets whether Fortix starts in the notification area at sign-in; off by default.</summary>
    public bool StartAtSignIn
    {
        get => startAtSignIn;
        set
        {
            try
            {
                autostart.SetEnabled(value);
                Message = null;
            }
            catch (Exception e) when (e is IOException or UnauthorizedAccessException or System.Security.SecurityException)
            {
                Message = "Start at sign-in could not be changed.";
            }
            // Show what the system actually holds, not what was requested.
            startAtSignIn = autostart.IsEnabled();
            OnPropertyChanged();
        }
    }

    /// <summary>Gets the last failure, or null.</summary>
    public string? Message
    {
        get => message;
        private set => Set(ref message, value);
    }
}
