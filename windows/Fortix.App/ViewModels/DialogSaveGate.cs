namespace Fortix.App.ViewModels;

/// <summary>
/// Guards a dialog that saves asynchronously: one save at a time, no closing while a save is in
/// flight, and no dialog result once the window is gone, since WPF throws when a result is set
/// on a window that is no longer shown as a dialog.
/// </summary>
public sealed class DialogSaveGate : ObservableObject
{
    /// <summary>Whether a save is in flight.</summary>
    private bool saving;

    /// <summary>
    /// Gets whether a save is in flight.
    /// </summary>
    public bool Saving
    {
        get => saving;
        private set
        {
            if (Set(ref saving, value))
            {
                OnPropertyChanged(nameof(Idle));
            }
        }
    }

    /// <summary>
    /// Gets whether no save is in flight, for bindings that enable dismissing the dialog.
    /// </summary>
    public bool Idle => !saving;

    /// <summary>
    /// Gets whether the window has closed.
    /// </summary>
    public bool Closed { get; private set; }

    /// <summary>
    /// Starts a save unless one is already in flight or the window has closed.
    /// </summary>
    /// <returns>True when the caller may save; false for a duplicate or late submission.</returns>
    public bool TryBegin()
    {
        if (saving || Closed)
        {
            return false;
        }
        Saving = true;
        return true;
    }

    /// <summary>
    /// Ends the save started by <see cref="TryBegin"/>.
    /// </summary>
    /// <param name="succeeded">Whether the helper confirmed the save.</param>
    /// <returns>True when the caller should close the dialog with a positive result.</returns>
    public bool Finish(bool succeeded)
    {
        Saving = false;
        return succeeded && !Closed;
    }

    /// <summary>
    /// Decides whether a close request may proceed; it is refused while a save is in flight so
    /// the save's outcome always reaches an open window.
    /// </summary>
    /// <returns>True when the window may close.</returns>
    public bool AllowClose() => !saving;

    /// <summary>
    /// Records that the window has closed, so no later result is applied to it.
    /// </summary>
    public void MarkClosed() => Closed = true;
}
