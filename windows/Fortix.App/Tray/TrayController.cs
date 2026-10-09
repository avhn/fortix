using System.ComponentModel;
using System.Windows;
using System.Windows.Threading;
using Fortix.App.Model;
using Fortix.App.Native;
using Fortix.App.ViewModels;
using Fortix.Core.Protocol;

namespace Fortix.App.Tray;

/// <summary>
/// Keeps the notification-area icon in step with the app state, theme, and motion preferences.
/// </summary>
/// <remarks>
/// The glyph is redrawn only when its status, frame, or theme changes. The connecting ring
/// rotates only while the user allows it and Windows animations are on.
/// </remarks>
internal sealed class TrayController : IDisposable
{
    /// <summary>The coordinator.</summary>
    private readonly AppViewModel model;

    /// <summary>The preferences.</summary>
    private readonly SettingsViewModel settings;

    /// <summary>The native icon.</summary>
    private readonly TrayIcon icon = new();

    /// <summary>Advances the connecting animation.</summary>
    private readonly DispatcherTimer animation = new() { Interval = RingGlyph.FrameInterval };

    /// <summary>The connecting frame.</summary>
    private int frame;

    /// <summary>Whether the taskbar is light.</summary>
    private bool lightTaskbar;

    /// <summary>
    /// Shows the icon and starts following the model.
    /// </summary>
    /// <param name="model">The coordinator.</param>
    /// <param name="settings">The preferences.</param>
    /// <param name="open">Opens the management window.</param>
    /// <param name="quit">Quits the app.</param>
    public TrayController(AppViewModel model, SettingsViewModel settings, Action open, Action quit)
    {
        this.model = model;
        this.settings = settings;
        lightTaskbar = ThemeReader.Read().TaskbarLight;
        icon.MenuBuilder = () => TrayMenu.Build(model, open, quit);
        icon.Activated += (_, _) => open();
        icon.ThemeChanged += (_, _) =>
        {
            lightTaskbar = ThemeReader.Read().TaskbarLight;
            ThemeChanged?.Invoke(this, EventArgs.Empty);
            Refresh();
        };
        animation.Tick += (_, _) =>
        {
            frame = (frame + 1) % RingGlyph.Frames;
            Draw();
        };
        model.PropertyChanged += OnChanged;
        settings.PropertyChanged += OnChanged;
        SystemParameters.StaticPropertyChanged += OnChanged;
        model.Failure += (_, failure) => icon.ShowBalloon(
            $"{failure.Name} could not connect",
            failure.Detail.Length == 0 ? "Open Fortix to see the log." : failure.Detail);
        Refresh();
    }

    /// <summary>Raised when Windows switches between light and dark.</summary>
    public event EventHandler? ThemeChanged;

    /// <summary>Removes the icon.</summary>
    public void Dispose()
    {
        animation.Stop();
        model.PropertyChanged -= OnChanged;
        settings.PropertyChanged -= OnChanged;
        SystemParameters.StaticPropertyChanged -= OnChanged;
        icon.Dispose();
    }

    /// <summary>
    /// Gets whether the ring should rotate under the current preferences.
    /// </summary>
    private bool Animates => model.Aggregate == AggregateStatus.Connecting && settings.AnimateIcon && SystemParameters.ClientAreaAnimation;

    /// <summary>
    /// Reacts to any state or preference change.
    /// </summary>
    /// <param name="sender">The source.</param>
    /// <param name="e">The change.</param>
    private void OnChanged(object? sender, PropertyChangedEventArgs e) => Refresh();

    /// <summary>
    /// Starts or stops the animation and redraws.
    /// </summary>
    private void Refresh()
    {
        if (Animates)
        {
            animation.Start();
        }
        else
        {
            animation.Stop();
            frame = 0;
        }
        Draw();
    }

    /// <summary>
    /// Shows the current glyph and tooltip.
    /// </summary>
    private void Draw() =>
        icon.Show(model.Aggregate, Animates ? frame : 0, lightTaskbar, "Fortix: " + model.StatusText);
}
