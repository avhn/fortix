using System.Text;
using Fortix.App.ViewModels;
using Fortix.Core.Profiles;

namespace Fortix.App.Tests;

/// <summary>
/// Covers the profile editor: field mapping, validation with the helper's rules, and import review.
/// </summary>
public sealed class ProfileEditorTests
{
    /// <summary>
    /// Parses one shared profile document into an import of one.
    /// </summary>
    /// <param name="profileJson">The profile object inside the file.</param>
    /// <returns>The import.</returns>
    private static SharedImport Import(string profileJson) =>
        new(SharedProfiles.Parse(Encoding.UTF8.GetBytes("{\"format\":\"fortix-profile\",\"version\":1,\"profiles\":[" + profileJson + "]}"))[0], 1, 1);

    /// <summary>
    /// A new profile starts with the documented defaults and keeps automatic choices omitted.
    /// </summary>
    [Fact]
    public void NewProfileDefaults()
    {
        var editor = new ProfileEditorViewModel((Profile?)null, []);
        Assert.Equal("443", editor.Port);
        Assert.Equal("automatic", editor.Backend);
        Assert.True(editor.PreserveLan);
        Assert.True(editor.IdEditable);
        Assert.False(editor.CanForgetPassword);
        editor.Id = "work";
        editor.Name = "Work";
        editor.Host = "vpn.example.com";
        editor.Username = "jane.doe";
        var profile = editor.Value();
        Assert.Null(profile.Backend);
        Assert.Equal(443, profile.Gateway.Port);
        Assert.Null(profile.Routes.Include);
        Assert.Null(profile.Dns.Domains);
    }

    /// <summary>
    /// Invalid fields raise the helper's problems, and an unparsable port is reported as out of range.
    /// </summary>
    [Fact]
    public void InvalidFieldsUseCoreMessages()
    {
        var editor = new ProfileEditorViewModel((Profile?)null, []);
        editor.Id = "work";
        editor.Name = "Work";
        editor.Host = "vpn.example.com";
        editor.Username = "jane.doe";
        editor.Port = "https";
        var error = Assert.Throws<ProfileValidationException>(editor.Value);
        Assert.Contains(error.Problems, p => p.Field == "gateway.port");
        Assert.True(editor.ShowProblems);
        Assert.Contains("gateway.port", editor.ProblemsText, StringComparison.Ordinal);
    }

    /// <summary>
    /// Custom routes need at least one prefix, and a bad entry marks its own row.
    /// </summary>
    [Fact]
    public void RouteRowsReportProblems()
    {
        var editor = new ProfileEditorViewModel(AppViewModelTests.Sample(), []);
        editor.RoutesMode = "custom";
        Assert.Equal("Add at least one IPv4 prefix.", editor.RoutesListProblem);
        Assert.False(editor.CanSave);
        editor.RouteRows[0].Text = "192.0.2.0/24";
        Assert.Null(editor.RoutesListProblem);
        Assert.Null(editor.RouteRows[0].Problem);
        Assert.True(editor.CanSave);
        editor.AddRouteCommand.Execute(null);
        editor.RouteRows[1].Text = "not a prefix";
        Assert.NotNull(editor.RouteRows[1].Problem);
        Assert.True(char.IsUpper(editor.RouteRows[1].Problem![0]));
        Assert.False(editor.CanSave);
        editor.RemoveRowCommand.Execute(editor.RouteRows[1]);
        Assert.True(editor.CanSave);
        Assert.Equal(["192.0.2.0/24"], editor.Value().Routes.Include!);
    }

    /// <summary>
    /// Second-factor modes explain that Windows cannot use them and that native has none.
    /// </summary>
    [Fact]
    public void WindowsLimitsAreShown()
    {
        var editor = new ProfileEditorViewModel(AppViewModelTests.Sample(), []);
        Assert.True(editor.CanForgetPassword);
        Assert.False(editor.IdEditable);
        Assert.Null(editor.WindowsNote);
        editor.MfaMode = "push";
        Assert.Equal(ProfileRules.WindowsMfaUnavailable, editor.WindowsNote);
        editor.Backend = "native";
        Assert.NotNull(editor.NativeMfaNote);
        Assert.All(ProfileEditorViewModel.MfaModes.Skip(1), c => Assert.EndsWith("(not available on Windows)", c.Label, StringComparison.Ordinal));
    }

    /// <summary>
    /// An import as a new profile flags missing fields and never keeps the file's pin.
    /// </summary>
    [Fact]
    public void ImportAsNewDropsPin()
    {
        var pin = string.Join(':', Enumerable.Repeat("AB", 32));
        var editor = new ProfileEditorViewModel(Import("{\"name\":\"Office\",\"gateway\":{\"host\":\"vpn.example.com\"},\"trusted_cert\":\"" + pin + "\"}"), []);
        Assert.Equal(ProfileEditorViewModel.RequiredFromFile, editor.IdNote);
        Assert.Equal("Required. Shared profile files never include a username.", editor.UsernameNote);
        Assert.NotNull(editor.ImportedPin);
        editor.Id = "office";
        editor.Username = "jane.doe";
        Assert.Null(editor.IdNote);
        Assert.Null(editor.Value().TrustedCert);
    }

    /// <summary>
    /// A file that names an existing identifier must be merged or renamed, never silently replaced.
    /// </summary>
    [Fact]
    public void ImportWarnsAboutExistingIdAndGatewayChange()
    {
        var stored = AppViewModelTests.Sample();
        stored.TrustedCert = string.Join(':', Enumerable.Repeat("CD", 32));
        var editor = new ProfileEditorViewModel(Import("{\"id\":\"work\",\"name\":\"Work\",\"gateway\":{\"host\":\"vpn2.example.com\"}}"), [stored]);
        Assert.Equal(ImportTarget.New, editor.Target);
        Assert.StartsWith("This ID already exists.", editor.IdNote, StringComparison.Ordinal);
        editor.Target = ImportTarget.Merge;
        Assert.Equal("work", editor.MergeId);
        Assert.Contains("from vpn.example.com:443 to vpn2.example.com:443", editor.GatewayChangeWarning, StringComparison.Ordinal);
        var merged = editor.Value();
        Assert.Equal("jane.doe", merged.Username);
        Assert.Equal(stored.TrustedCert, merged.TrustedCert);
        Assert.Equal("vpn2.example.com", merged.Gateway.Host);
    }

    /// <summary>
    /// A file listing domains without a mode opens them in split DNS so nothing is hidden.
    /// </summary>
    [Fact]
    public void ImportShowsSuppliedLists()
    {
        var editor = new ProfileEditorViewModel(Import("{\"id\":\"work\",\"name\":\"Work\",\"gateway\":{\"host\":\"vpn.example.com\"},\"dns\":{\"domains\":[\"corp.example.com\"]}}"), []);
        Assert.True(editor.IsSplitDns);
        Assert.Equal("corp.example.com", editor.DomainRows[0].Text);
    }
}
