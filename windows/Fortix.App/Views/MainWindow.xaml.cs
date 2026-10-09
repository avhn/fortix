using System.Reflection;
using System.Windows;
using System.Windows.Controls;
using Fortix.App.ViewModels;
using Fortix.Core.Profiles;
using Microsoft.Win32;

namespace Fortix.App.Views;

/// <summary>
/// The management window: profiles, logs, settings, and the first-run helper setup.
/// </summary>
public partial class MainWindow : Window
{
    /// <summary>Explains why second factors are unavailable, using the helper's own refusal.</summary>
    public static readonly string MfaNote =
        "Password-only profiles use the native backend. " + ProfileRules.WindowsMfaUnavailable + ", and " + ProfileRules.WindowsOpenfortivpnUnavailable + ".";

    /// <summary>
    /// Creates the window over the shared models.
    /// </summary>
    /// <param name="model">The coordinator.</param>
    /// <param name="setup">The setup page model.</param>
    /// <param name="settings">The preferences.</param>
    public MainWindow(AppViewModel model, SetupViewModel setup, SettingsViewModel settings)
    {
        Model = model;
        Setup = setup;
        Settings = settings;
        InitializeComponent();
        DataContext = this;
        var version = typeof(MainWindow).Assembly.GetCustomAttribute<AssemblyInformationalVersionAttribute>()?.InformationalVersion.Split('+')[0] ?? "dev";
        AboutText.Text = $"Fortix {version}. Free software under the GNU General Public License, version 3 or later. " +
            "Not affiliated with or endorsed by Fortinet. FortiGate and FortiClient are trademarks of Fortinet, Inc.";
        model.Rows.CollectionChanged += (_, _) => UpdateEmptyNote();
        UpdateEmptyNote();
        if (!model.Reachable && setup.NeedsSetup)
        {
            Tabs.SelectedIndex = 0;
        }
    }

    /// <summary>Gets the coordinator.</summary>
    public AppViewModel Model { get; }

    /// <summary>Gets the setup page model.</summary>
    public SetupViewModel Setup { get; }

    /// <summary>Gets the preferences.</summary>
    public SettingsViewModel Settings { get; }

    /// <summary>
    /// Shows the empty-list hint only while there are no profiles.
    /// </summary>
    private void UpdateEmptyNote() => EmptyNote.Visibility = Model.Rows.Count == 0 ? Visibility.Visible : Visibility.Collapsed;

    /// <summary>
    /// Opens the editor for a new profile.
    /// </summary>
    /// <param name="sender">The button.</param>
    /// <param name="e">The click.</param>
    private void NewProfile(object sender, RoutedEventArgs e) =>
        new ProfileEditorWindow(Model, new ProfileEditorViewModel((Profile?)null, Model.Profiles)) { Owner = this }.ShowDialog();

    /// <summary>
    /// Opens the editor for the clicked row's profile.
    /// </summary>
    /// <param name="sender">The button.</param>
    /// <param name="e">The click.</param>
    private void EditProfile(object sender, RoutedEventArgs e)
    {
        if (((FrameworkElement)sender).DataContext is ProfileRowViewModel row)
        {
            new ProfileEditorWindow(Model, new ProfileEditorViewModel(row.Profile, Model.Profiles)) { Owner = this }.ShowDialog();
        }
    }

    /// <summary>
    /// Deletes the clicked row's profile after an explicit confirmation.
    /// </summary>
    /// <param name="sender">The button.</param>
    /// <param name="e">The click.</param>
    private void DeleteProfile(object sender, RoutedEventArgs e)
    {
        if (((FrameworkElement)sender).DataContext is not ProfileRowViewModel row)
        {
            return;
        }
        var answer = MessageBox.Show(this,
            $"Delete {row.Name}? This removes the idle profile. Its saved password in Credential Manager is not removed automatically.",
            "Delete profile", MessageBoxButton.YesNo, MessageBoxImage.Warning, MessageBoxResult.No);
        if (answer == MessageBoxResult.Yes)
        {
            Model.Perform(() => Model.DeleteAsync(row.Id));
        }
    }

    /// <summary>
    /// Writes the selected profile, or all profiles, as a secret-free share file.
    /// </summary>
    /// <remarks>
    /// The document is built and validated before the save dialog opens, so no partial file is written.
    /// </remarks>
    /// <param name="sender">The button.</param>
    /// <param name="e">The click.</param>
    private void ExportProfiles(object sender, RoutedEventArgs e)
    {
        List<Profile> chosen = ProfileList.SelectedItem is ProfileRowViewModel row ? [row.Profile] : [.. Model.Profiles];
        if (chosen.Count == 0)
        {
            Model.Message = "There are no profiles to export.";
            return;
        }
        byte[] data;
        try
        {
            data = SharedProfiles.Export(chosen);
        }
        catch (Exception error) when (error is ShareException or ProfileValidationException)
        {
            Model.Message = AppViewModel.FailureText(error);
            return;
        }
        var dialog = new SaveFileDialog
        {
            Title = chosen.Count == 1 ? "Export profile" : $"Export {chosen.Count} profiles",
            FileName = chosen.Count == 1 ? $"{chosen[0].Id}.fortix.json" : "profiles.fortix.json",
            Filter = "Fortix profile files (*.json)|*.json",
            AddExtension = true,
        };
        if (dialog.ShowDialog(this) != true)
        {
            return;
        }
        try
        {
            File.WriteAllBytes(dialog.FileName, data);
            Model.Message = chosen.Count == 1
                ? $"Exported {chosen[0].Name}. Usernames and passwords are not included."
                : $"Exported {chosen.Count} profiles. Usernames and passwords are not included.";
        }
        catch (Exception error) when (error is IOException or UnauthorizedAccessException)
        {
            Model.Message = "The profile file could not be written. Choose another location.";
        }
    }

    /// <summary>
    /// Parses a share file, then reviews each profile in its own editor; nothing is saved unreviewed.
    /// </summary>
    /// <param name="sender">The button.</param>
    /// <param name="e">The click.</param>
    private void ImportProfiles(object sender, RoutedEventArgs e)
    {
        var dialog = new OpenFileDialog { Title = "Import profile", Filter = "Fortix profile files (*.json)|*.json|All files (*.*)|*.*" };
        if (dialog.ShowDialog(this) != true)
        {
            return;
        }
        IReadOnlyList<ProfileDraft> drafts;
        try
        {
            drafts = SharedProfiles.Parse(ReadBounded(dialog.FileName));
        }
        catch (ShareException error)
        {
            Model.Message = AppViewModel.SharedFailureText(error);
            return;
        }
        catch (Exception error) when (error is IOException or UnauthorizedAccessException)
        {
            Model.Message = "The profile file could not be read.";
            return;
        }
        Model.Message = null;
        for (var i = 0; i < drafts.Count; i++)
        {
            var editor = new ProfileEditorWindow(Model, new ProfileEditorViewModel(new SharedImport(drafts[i], i + 1, drafts.Count), Model.Profiles)) { Owner = this };
            editor.ShowDialog();
            if (editor.StopImport || Model.Prompts.Count > 0)
            {
                break;
            }
        }
    }

    /// <summary>
    /// Reads a file of at most one byte over the share limit, so an oversized file is rejected without loading it all.
    /// </summary>
    /// <param name="path">The file.</param>
    /// <returns>The bytes read.</returns>
    private static byte[] ReadBounded(string path)
    {
        using var file = File.OpenRead(path);
        var buffer = new byte[SharedProfiles.MaxBytes + 1];
        var total = 0;
        int read;
        while (total < buffer.Length && (read = file.Read(buffer, total, buffer.Length - total)) > 0)
        {
            total += read;
        }
        return buffer[..total];
    }
}
