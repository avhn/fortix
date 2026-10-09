using System.ComponentModel;
using System.Windows;
using Fortix.App.ViewModels;
using Fortix.Core.Profiles;

namespace Fortix.App.Views;

/// <summary>
/// The profile editor dialog; it closes only after the helper confirmed the save.
/// </summary>
public partial class ProfileEditorWindow : Window
{
    /// <summary>
    /// Creates the dialog.
    /// </summary>
    /// <param name="model">The coordinator that saves through the helper.</param>
    /// <param name="editor">The editor state.</param>
    public ProfileEditorWindow(AppViewModel model, ProfileEditorViewModel editor)
    {
        Model = model;
        Editor = editor;
        InitializeComponent();
        DataContext = this;
        Loaded += (_, _) => (editor.IdEditable ? IdBox : NameBox).Focus();
        Closing += RefuseCloseWhileSaving;
        Closed += (_, _) => Gate.MarkClosed();
    }

    /// <summary>Gets the guard that serializes saves and keeps the window open while one runs.</summary>
    public DialogSaveGate Gate { get; } = new();

    /// <summary>Gets the coordinator.</summary>
    public AppViewModel Model { get; }

    /// <summary>Gets the editor state.</summary>
    public ProfileEditorViewModel Editor { get; }

    /// <summary>Gets whether the user chose to abandon the rest of an import.</summary>
    public bool StopImport { get; private set; }

    /// <summary>
    /// Validates, saves through the helper, and closes on success; problems stay visible otherwise.
    /// A second click while a save runs is ignored, and the result is only applied to an open window.
    /// </summary>
    /// <param name="sender">The button.</param>
    /// <param name="e">The click.</param>
    private async void Save(object sender, RoutedEventArgs e)
    {
        Profile profile;
        try
        {
            profile = Editor.Value();
        }
        catch (ProfileValidationException error)
        {
            Model.Message = AppViewModel.FailureText(error);
            return;
        }
        if (!Gate.TryBegin())
        {
            return;
        }
        var saved = false;
        try
        {
            saved = await Model.PerformAsync(() => Model.SaveAsync(profile, Editor.IsExisting));
        }
        finally
        {
            if (Gate.Finish(saved))
            {
                DialogResult = true;
            }
        }
    }

    /// <summary>
    /// Cancels Cancel, Escape, and title-bar close requests while this editor's save is in flight,
    /// so the save's outcome is never applied to a window that is no longer a dialog.
    /// </summary>
    /// <param name="sender">The window.</param>
    /// <param name="e">The close request.</param>
    private void RefuseCloseWhileSaving(object? sender, CancelEventArgs e)
    {
        if (!Gate.AllowClose())
        {
            e.Cancel = true;
        }
    }

    /// <summary>
    /// Removes the saved password of the stored profile.
    /// </summary>
    /// <param name="sender">The button.</param>
    /// <param name="e">The click.</param>
    private void ForgetPassword(object sender, RoutedEventArgs e) => Model.Perform(() => Model.ForgetAsync(Editor.Id));

    /// <summary>
    /// Closes this review and skips the remaining imported profiles.
    /// </summary>
    /// <param name="sender">The button.</param>
    /// <param name="e">The click.</param>
    private void StopImportClick(object sender, RoutedEventArgs e)
    {
        StopImport = true;
        DialogResult = false;
    }
}
