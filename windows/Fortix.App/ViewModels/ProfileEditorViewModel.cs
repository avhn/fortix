using System.Collections.ObjectModel;
using System.Collections.Specialized;
using System.ComponentModel;
using System.Globalization;
using Fortix.Core.Profiles;

namespace Fortix.App.ViewModels;

/// <summary>
/// One editable list entry with its own validation message.
/// </summary>
public sealed class EntryRow : ObservableObject
{
    /// <summary>The raw text as typed.</summary>
    private string text;

    /// <summary>The first validation message for this entry, or null.</summary>
    private string? problem;

    /// <summary>
    /// Creates a row.
    /// </summary>
    /// <param name="text">The initial text.</param>
    public EntryRow(string text = "") => this.text = text;

    /// <summary>Gets or sets the raw text; it is normalized only when the profile is built.</summary>
    public string Text
    {
        get => text;
        set => Set(ref text, value ?? "");
    }

    /// <summary>Gets the validation message for this entry, or null when it is valid.</summary>
    public string? Problem
    {
        get => problem;
        internal set => Set(ref problem, value);
    }
}

/// <summary>
/// A choice in a picker: the stored value and its label.
/// </summary>
/// <param name="Value">The value stored in the profile.</param>
/// <param name="Label">The text shown to the user.</param>
public sealed record Choice(string Value, string Label);

/// <summary>
/// Whether an imported profile becomes a new profile or updates an existing one.
/// </summary>
public enum ImportTarget
{
    /// <summary>Create a profile; fields missing from the file must be filled in.</summary>
    New,

    /// <summary>Overlay the file's fields onto a chosen existing profile.</summary>
    Merge,
}

/// <summary>
/// One parsed profile from a shared file and its position in a multi-profile import.
/// </summary>
/// <param name="Draft">The fields the file supplied.</param>
/// <param name="Position">The one-based position in the file.</param>
/// <param name="Count">The number of profiles in the file.</param>
public sealed record SharedImport(ProfileDraft Draft, int Position, int Count);

/// <summary>
/// Edits one secret-free profile with the helper's own field rules and messages.
/// </summary>
/// <remarks>
/// Unedited fields such as the certificate pin and TOTP settings are carried over from the
/// stored profile. The pin is never editable: it changes only by trusting a rejected
/// certificate during a connection. An imported file's pin is shown but never saved.
/// </remarks>
public sealed class ProfileEditorViewModel : ObservableObject
{
    /// <summary>The message for an empty required field the file did not supply.</summary>
    public const string RequiredFromFile = "Required. Not in the imported file.";

    /// <summary>Second-factor and backend choices that the Windows helper refuses are labelled as such.</summary>
    private const string NotOnWindows = " (not available on Windows)";

    /// <summary>The imported profile, or null for ordinary editing.</summary>
    private readonly SharedImport? shared;

    /// <summary>The stored profiles, for duplicate and merge checks.</summary>
    private readonly IReadOnlyList<Profile> existingProfiles;

    /// <summary>The profile whose unedited fields are preserved.</summary>
    private Profile baseProfile = new() { SchemaVersion = 1 };

    /// <summary>Suppresses recomputation while many fields load at once.</summary>
    private bool loading;

    /// <summary>The backing fields of the editable values.</summary>
    private string id = "", name = "", host = "", port = "443", realm = "", username = "";

    /// <summary>The backing fields of the picker values.</summary>
    private string backend = "automatic", mfaMode = "none", totpDigits = "", totpPeriod = "", totpAlgorithm = "", routesMode = "gateway", dnsMode = "none";

    /// <summary>Whether local networks stay reachable.</summary>
    private bool preserveLan = true;

    /// <summary>The import choice.</summary>
    private ImportTarget target;

    /// <summary>The profile a merge updates.</summary>
    private string mergeId = "";

    /// <summary>Whether the full problem list is shown, after the first save attempt.</summary>
    private bool showProblems;

    /// <summary>
    /// Creates an editor for a new profile, or for a stored one when <paramref name="profile"/> is set.
    /// </summary>
    /// <param name="profile">The stored profile, or null for a new one.</param>
    /// <param name="existingProfiles">The stored profiles.</param>
    public ProfileEditorViewModel(Profile? profile, IReadOnlyList<Profile> existingProfiles)
    {
        ArgumentNullException.ThrowIfNull(existingProfiles);
        this.existingProfiles = existingProfiles;
        EditingExisting = profile is not null;
        Initialize();
        Load(profile ?? new Profile { SchemaVersion = 1 });
    }

    /// <summary>
    /// Creates an import review as a new profile; a merge is always an explicit choice.
    /// </summary>
    /// <remarks>
    /// The merge target defaults to the stored profile with the file's identifier, because a
    /// merge can change the gateway that profile connects to and should never be silent.
    /// </remarks>
    /// <param name="shared">The imported profile.</param>
    /// <param name="existingProfiles">The stored profiles.</param>
    public ProfileEditorViewModel(SharedImport shared, IReadOnlyList<Profile> existingProfiles)
    {
        ArgumentNullException.ThrowIfNull(shared);
        ArgumentNullException.ThrowIfNull(existingProfiles);
        this.shared = shared;
        this.existingProfiles = existingProfiles;
        mergeId = existingProfiles.FirstOrDefault(p => p.Id == shared.Draft.Id)?.Id ?? existingProfiles.FirstOrDefault()?.Id ?? "";
        Initialize();
        ReloadImport();
    }

    /// <summary>Gets the backend choices.</summary>
    public static IReadOnlyList<Choice> Backends { get; } =
    [
        new("automatic", "Automatic"),
        new("native", "Native (password only)"),
        new("openfortivpn", "openfortivpn (2FA support)" + NotOnWindows),
    ];

    /// <summary>Gets the second-factor choices.</summary>
    public static IReadOnlyList<Choice> MfaModes { get; } =
    [
        new("none", "None"),
        new("push", "Push" + NotOnWindows),
        new("prompt", "Code prompt" + NotOnWindows),
        new("totp", "TOTP" + NotOnWindows),
        new("static", "Static code" + NotOnWindows),
    ];

    /// <summary>Gets the TOTP algorithm choices.</summary>
    public static IReadOnlyList<Choice> Algorithms { get; } =
        [new("", "Default (SHA1)"), new("SHA1", "SHA1"), new("SHA256", "SHA256"), new("SHA512", "SHA512")];

    /// <summary>Gets the routing choices.</summary>
    public static IReadOnlyList<Choice> RouteModes { get; } =
        [new("gateway", "Gateway routes"), new("custom", "Custom routes"), new("full", "Full tunnel")];

    /// <summary>Gets the DNS choices.</summary>
    public static IReadOnlyList<Choice> DnsModes { get; } = [new("none", "Unmanaged"), new("split", "Split DNS")];

    /// <summary>Gets whether this edits a stored profile outside an import.</summary>
    public bool EditingExisting { get; }

    /// <summary>Gets whether this reviews an imported profile.</summary>
    public bool IsImport => shared is not null;

    /// <summary>Gets whether saving updates a stored profile, which keeps its identifier.</summary>
    public bool IsExisting => EditingExisting || (IsImport && Target == ImportTarget.Merge);

    /// <summary>Gets whether the identifier may be changed.</summary>
    public bool IdEditable => !IsExisting;

    /// <summary>Gets the window title, including the position within a multi-profile import.</summary>
    public string Title => shared is { } s
        ? s.Count > 1 ? $"Import profile {s.Position} of {s.Count}" : "Import profile"
        : IsExisting ? "Edit profile" : "New profile";

    /// <summary>Gets the dismiss label: Skip while more imported profiles follow, otherwise Cancel.</summary>
    public string DismissLabel => shared is { } s && s.Position < s.Count ? "_Skip" : "_Cancel";

    /// <summary>Gets whether the rest of a multi-profile import can be abandoned.</summary>
    public bool CanStopImport => shared is { } s && s.Position < s.Count;

    /// <summary>Gets whether the stored profile's saved password can be removed here.</summary>
    public bool CanForgetPassword => EditingExisting && !IsImport;

    /// <summary>Gets the stored profiles a merge can target.</summary>
    public IReadOnlyList<Profile> ExistingProfiles => existingProfiles;

    /// <summary>Gets whether a merge is possible at all.</summary>
    public bool CanMerge => IsImport && existingProfiles.Count > 0;

    /// <summary>Gets or sets the import choice.</summary>
    public ImportTarget Target
    {
        get => target;
        set
        {
            if (Set(ref target, value))
            {
                ReloadImport();
            }
        }
    }

    /// <summary>Gets or sets whether the import merges, for a check box or radio binding.</summary>
    public bool IsMerge
    {
        get => Target == ImportTarget.Merge;
        set => Target = value ? ImportTarget.Merge : ImportTarget.New;
    }

    /// <summary>Gets or sets the stored profile a merge updates.</summary>
    public string MergeId
    {
        get => mergeId;
        set
        {
            if (Set(ref mergeId, value ?? ""))
            {
                ReloadImport();
            }
        }
    }

    /// <summary>Gets or sets the profile identifier.</summary>
    public string Id { get => id; set => Edit(ref id, value); }

    /// <summary>Gets or sets the display name.</summary>
    public string Name { get => name; set => Edit(ref name, value); }

    /// <summary>Gets or sets the gateway host.</summary>
    public string Host { get => host; set => Edit(ref host, value); }

    /// <summary>Gets or sets the TLS port as text, so invalid input never becomes the default.</summary>
    public string Port { get => port; set => Edit(ref port, value); }

    /// <summary>Gets or sets the authentication realm; empty means none.</summary>
    public string Realm { get => realm; set => Edit(ref realm, value); }

    /// <summary>Gets or sets the account name.</summary>
    public string Username { get => username; set => Edit(ref username, value); }

    /// <summary>Gets or sets the backend: automatic, native, or openfortivpn.</summary>
    public string Backend { get => backend; set => Edit(ref backend, value); }

    /// <summary>Gets or sets the second-factor mode.</summary>
    public string MfaMode { get => mfaMode; set => Edit(ref mfaMode, value); }

    /// <summary>Gets or sets the TOTP length as text; empty means the default.</summary>
    public string TotpDigits { get => totpDigits; set => Edit(ref totpDigits, value); }

    /// <summary>Gets or sets the TOTP interval as text; empty means the default.</summary>
    public string TotpPeriod { get => totpPeriod; set => Edit(ref totpPeriod, value); }

    /// <summary>Gets or sets the TOTP algorithm; empty means the default.</summary>
    public string TotpAlgorithm { get => totpAlgorithm; set => Edit(ref totpAlgorithm, value); }

    /// <summary>Gets or sets the routing mode.</summary>
    public string RoutesMode { get => routesMode; set => Edit(ref routesMode, value); }

    /// <summary>Gets or sets whether local networks stay reachable.</summary>
    public bool PreserveLan { get => preserveLan; set => Edit(ref preserveLan, value); }

    /// <summary>Gets or sets the DNS mode.</summary>
    public string DnsMode { get => dnsMode; set => Edit(ref dnsMode, value); }

    /// <summary>Gets the custom route prefixes, one per row.</summary>
    public ObservableCollection<EntryRow> RouteRows { get; } = [];

    /// <summary>Gets the ranges removed from gateway routes, one per row.</summary>
    public ObservableCollection<EntryRow> ExcludeRows { get; } = [];

    /// <summary>Gets the split DNS domains, one per row.</summary>
    public ObservableCollection<EntryRow> DomainRows { get; } = [];

    /// <summary>Gets whether TOTP parameters apply.</summary>
    public bool IsTotp => MfaMode == "totp";

    /// <summary>Gets whether custom prefixes apply.</summary>
    public bool IsCustomRoutes => RoutesMode == "custom";

    /// <summary>Gets whether excluded ranges apply.</summary>
    public bool ShowExcludes => RoutesMode != "custom";

    /// <summary>Gets whether every IPv4 route goes through the tunnel.</summary>
    public bool IsFullTunnel => RoutesMode == "full";

    /// <summary>Gets whether split DNS domains apply.</summary>
    public bool IsSplitDns => DnsMode == "split";

    /// <summary>Gets the stored certificate pin, or a note that system validation is used.</summary>
    public string TrustedCertText => string.IsNullOrEmpty(baseProfile.TrustedCert) ? "System certificate validation; no stored pin." : baseProfile.TrustedCert;

    /// <summary>Gets the unverified pin carried by an imported file, or null.</summary>
    public string? ImportedPin => shared?.Draft.TrustedCert is { Length: > 0 } pin ? pin : null;

    /// <summary>Gets the note under the identifier, or null.</summary>
    public string? IdNote { get; private set; }

    /// <summary>Gets the note under the name, or null.</summary>
    public string? NameNote { get; private set; }

    /// <summary>Gets the note under the gateway host, or null.</summary>
    public string? HostNote { get; private set; }

    /// <summary>Gets the note under the username, or null.</summary>
    public string? UsernameNote { get; private set; }

    /// <summary>Gets the list-level problem of custom routes, or null.</summary>
    public string? RoutesListProblem { get; private set; }

    /// <summary>Gets the list-level problem of excluded ranges, or null.</summary>
    public string? ExcludeListProblem { get; private set; }

    /// <summary>Gets the list-level problem of split DNS domains, or null.</summary>
    public string? DomainsListProblem { get; private set; }

    /// <summary>Gets the note when native is combined with a second factor, or null.</summary>
    public string? NativeMfaNote { get; private set; }

    /// <summary>Gets the Windows helper's refusal for this backend and second factor, or null.</summary>
    public string? WindowsNote { get; private set; }

    /// <summary>Gets the warning when a merge changes the gateway, or null.</summary>
    public string? GatewayChangeWarning { get; private set; }

    /// <summary>Gets whether any list entry or list is invalid, which blocks saving.</summary>
    public bool HasListProblems { get; private set; }

    /// <summary>Gets every field problem as the helper would report it, one per line.</summary>
    public string ProblemsText { get; private set; } = "";

    /// <summary>Gets whether the problem list is shown, which starts after the first save attempt.</summary>
    public bool ShowProblems
    {
        get => showProblems && ProblemsText.Length > 0;
        private set
        {
            showProblems = value;
            OnPropertyChanged();
        }
    }

    /// <summary>Gets whether saving is allowed.</summary>
    public bool CanSave => !HasListProblems;

    /// <summary>Gets the action that adds a custom route row.</summary>
    public RelayCommand AddRouteCommand { get; private set; } = null!;

    /// <summary>Gets the action that adds an excluded range row.</summary>
    public RelayCommand AddExcludeCommand { get; private set; } = null!;

    /// <summary>Gets the action that adds a domain row.</summary>
    public RelayCommand AddDomainCommand { get; private set; } = null!;

    /// <summary>Gets the action that removes the row given as parameter from whichever list holds it.</summary>
    public RelayCommand RemoveRowCommand { get; private set; } = null!;

    /// <summary>
    /// Builds the profile to save, or throws the helper's problems for every invalid field.
    /// </summary>
    /// <remarks>
    /// Lists forbidden in the selected modes are omitted, unparsable numbers become out-of-range
    /// values so the helper's own message explains them, and automatic choices stay omitted.
    /// </remarks>
    /// <returns>The profile.</returns>
    /// <exception cref="ProfileValidationException">A field is invalid.</exception>
    public Profile Value()
    {
        ShowProblems = true;
        var result = Build();
        var check = result.Clone();
        ProfileRules.ApplyDefaults(check);
        var problems = ProfileRules.Validate(check);
        if (problems.Count > 0)
        {
            throw new ProfileValidationException(problems);
        }
        return result;
    }

    /// <summary>
    /// Wires the commands and change tracking shared by both constructors.
    /// </summary>
    private void Initialize()
    {
        AddRouteCommand = new RelayCommand(_ => RouteRows.Add(new EntryRow()));
        AddExcludeCommand = new RelayCommand(_ => ExcludeRows.Add(new EntryRow()));
        AddDomainCommand = new RelayCommand(_ => DomainRows.Add(new EntryRow()));
        RemoveRowCommand = new RelayCommand(p =>
        {
            if (p is EntryRow row)
            {
                _ = RouteRows.Remove(row) || ExcludeRows.Remove(row) || DomainRows.Remove(row);
            }
        });
        foreach (var rows in new[] { RouteRows, ExcludeRows, DomainRows })
        {
            rows.CollectionChanged += RowsChanged;
        }
    }

    /// <summary>
    /// Rebuilds an import draft for the current choice of new profile or merge.
    /// </summary>
    private void ReloadImport()
    {
        if (shared is null)
        {
            return;
        }
        var draft = ShowingLists(shared.Draft);
        Profile profile;
        if (Target == ImportTarget.Merge && existingProfiles.FirstOrDefault(p => p.Id == MergeId) is { } existing)
        {
            // A merge keeps the identifier, username, and stored pin of the profile it updates.
            profile = draft.Merge(existing);
            profile.TrustedCert = existing.TrustedCert;
        }
        else
        {
            // A file's pin is shown for review but never saved, because pins are helper-owned.
            profile = draft.Apply(new Profile { SchemaVersion = 1 });
            profile.TrustedCert = null;
        }
        Load(profile);
    }

    /// <summary>
    /// Copies a profile into the editable fields.
    /// </summary>
    /// <param name="profile">The profile.</param>
    private void Load(Profile profile)
    {
        loading = true;
        baseProfile = profile.Clone();
        Id = profile.Id;
        Name = profile.Name;
        Host = profile.Gateway.Host;
        Port = (profile.Gateway.Port == 0 ? 443 : profile.Gateway.Port).ToString(CultureInfo.InvariantCulture);
        Realm = profile.Realm ?? "";
        Username = profile.Username;
        Backend = string.IsNullOrEmpty(profile.Backend) ? "automatic" : profile.Backend;
        MfaMode = profile.Mfa.Mode.Length == 0 ? "none" : profile.Mfa.Mode;
        TotpDigits = profile.Mfa.Digits?.ToString(CultureInfo.InvariantCulture) ?? "";
        TotpPeriod = profile.Mfa.Period?.ToString(CultureInfo.InvariantCulture) ?? "";
        TotpAlgorithm = profile.Mfa.Algorithm ?? "";
        RoutesMode = profile.Routes.Mode.Length == 0 ? "gateway" : profile.Routes.Mode;
        PreserveLan = profile.Routes.PreserveLan ?? true;
        DnsMode = profile.Dns.Mode.Length == 0 ? "none" : profile.Dns.Mode;
        Fill(RouteRows, profile.Routes.Include);
        Fill(ExcludeRows, profile.Routes.Exclude);
        Fill(DomainRows, profile.Dns.Domains);
        loading = false;
        OnPropertyChanged(null);
        Recompute();
    }

    /// <summary>
    /// Replaces a list's rows, offering one empty row for an empty list.
    /// </summary>
    /// <param name="rows">The rows.</param>
    /// <param name="entries">The stored entries.</param>
    private void Fill(ObservableCollection<EntryRow> rows, List<string>? entries)
    {
        foreach (var row in rows)
        {
            row.PropertyChanged -= RowChanged;
        }
        rows.Clear();
        foreach (var entry in entries is { Count: > 0 } ? entries : [""])
        {
            rows.Add(new EntryRow(entry));
        }
    }

    /// <summary>
    /// Builds the profile from the fields without validating it.
    /// </summary>
    /// <returns>The unvalidated profile.</returns>
    private Profile Build()
    {
        var result = baseProfile.Clone();
        if (result.SchemaVersion == 0)
        {
            result.SchemaVersion = 1;
        }
        result.Id = Id;
        result.Name = Name;
        result.Gateway.Host = Host;
        result.Gateway.Port = ParseNumber(Port) is { } p and >= 1 and <= 65535 ? p : -1;
        result.Realm = Realm.Length == 0 ? null : Realm;
        result.Username = Username;
        result.Backend = Backend == "automatic" ? null : Backend;
        result.Mfa.Mode = MfaMode;
        if (IsTotp)
        {
            result.Mfa.Digits = TotpDigits.Trim().Length == 0 ? null : ParseNumber(TotpDigits) ?? -1;
            result.Mfa.Period = TotpPeriod.Trim().Length == 0 ? null : ParseNumber(TotpPeriod) ?? -1;
            result.Mfa.Algorithm = TotpAlgorithm.Length == 0 ? null : TotpAlgorithm;
        }
        else
        {
            result.Mfa.Digits = null;
            result.Mfa.Period = null;
            result.Mfa.Algorithm = null;
        }
        result.Routes.Mode = RoutesMode;
        result.Routes.Include = IsCustomRoutes ? [.. Entries(RouteRows).Select(e => e.Value)] : null;
        var excluded = Entries(ExcludeRows).Select(e => e.Value).ToList();
        result.Routes.Exclude = IsCustomRoutes || excluded.Count == 0 ? null : excluded;
        result.Routes.PreserveLan = PreserveLan;
        result.Dns.Mode = DnsMode;
        result.Dns.Domains = IsSplitDns ? [.. DomainEntries().Select(e => e.Value)] : null;
        return result;
    }

    /// <summary>
    /// Recomputes every note, row problem, and the full problem list.
    /// </summary>
    private void Recompute()
    {
        if (loading)
        {
            return;
        }
        var missing = shared is not null && Target == ImportTarget.New ? shared.Draft.Missing().ToHashSet(StringComparer.Ordinal) : [];
        string? Required(string field, string value) => missing.Contains(field) && value.Length == 0 ? RequiredFromFile : null;

        IdNote = Required("id", Id) ??
            (IsImport && !IsExisting && existingProfiles.Any(p => p.Id == Id) ? "This ID already exists. Choose another ID or merge into the existing profile." : null);
        NameNote = Required("name", Name);
        HostNote = Required("gateway.host", Host);
        UsernameNote = missing.Contains("username") && Username.Length == 0 ? "Required. Shared profile files never include a username." : null;

        var routes = Entries(RouteRows);
        var excludes = Entries(ExcludeRows);
        var domains = DomainEntries();
        MarkRows(RouteRows, IsCustomRoutes ? routes : [], "routes.include", p => p.Routes = new Routes { Mode = "custom", Include = [.. routes.Select(e => e.Value)] });
        MarkRows(ExcludeRows, ShowExcludes ? excludes : [], "routes.exclude", p => p.Routes = new Routes { Mode = "gateway", Exclude = [.. excludes.Select(e => e.Value)] });
        MarkRows(DomainRows, IsSplitDns ? domains : [], "dns.domains", p => p.Dns = new Dns { Mode = "split", Domains = [.. domains.Select(e => e.Value)] });
        RoutesListProblem = IsCustomRoutes && routes.Count == 0 ? (missing.Contains("routes.include") ? RequiredFromFile : "Add at least one IPv4 prefix.") : null;
        ExcludeListProblem = ShowExcludes && excludes.Count > ProfileRules.MaxExclude ? $"Exclude at most {ProfileRules.MaxExclude} ranges." : null;
        DomainsListProblem = IsSplitDns && domains.Count is < 1 or > 32 ? (missing.Contains("dns.domains") ? RequiredFromFile : "Add 1 to 32 domains.") : null;
        HasListProblems = RoutesListProblem is not null || ExcludeListProblem is not null || DomainsListProblem is not null ||
            RouteRows.Concat(ExcludeRows).Concat(DomainRows).Any(r => r.Problem is not null);

        var resolved = new Profile { Backend = Backend == "automatic" ? null : Backend, Mfa = new Mfa { Mode = MfaMode } };
        NativeMfaNote = ProfileText.ResolvedBackend(resolved) == "native" && MfaMode != "none"
            ? "Native does not support a second factor. Select Automatic or openfortivpn." : null;
        WindowsNote = ProfileText.WindowsUnavailableReason(resolved);
        GatewayChangeWarning = GatewayChange();

        var check = Build();
        ProfileRules.ApplyDefaults(check);
        ProblemsText = string.Join(Environment.NewLine, ProfileRules.Problems(check));
        foreach (var derived in new[]
        {
            nameof(IdNote), nameof(NameNote), nameof(HostNote), nameof(UsernameNote), nameof(RoutesListProblem),
            nameof(ExcludeListProblem), nameof(DomainsListProblem), nameof(HasListProblems), nameof(CanSave), nameof(NativeMfaNote),
            nameof(WindowsNote), nameof(GatewayChangeWarning), nameof(ProblemsText), nameof(ShowProblems), nameof(IsTotp),
            nameof(IsCustomRoutes), nameof(ShowExcludes), nameof(IsFullTunnel), nameof(IsSplitDns), nameof(IsExisting),
            nameof(IdEditable), nameof(Title), nameof(TrustedCertText),
        })
        {
            OnPropertyChanged(derived);
        }
    }

    /// <summary>
    /// Describes a merge that would point a stored profile at another gateway.
    /// </summary>
    /// <returns>The warning, or null.</returns>
    private string? GatewayChange()
    {
        if (shared is null || Target != ImportTarget.Merge || existingProfiles.FirstOrDefault(p => p.Id == MergeId) is not { } stored)
        {
            return null;
        }
        var storedPort = stored.Gateway.Port == 0 ? 443 : stored.Gateway.Port;
        var newHost = shared.Draft.Gateway?.Host ?? stored.Gateway.Host;
        var newPort = shared.Draft.Gateway?.Port ?? storedPort;
        if (newHost == stored.Gateway.Host && newPort == storedPort)
        {
            return null;
        }
        return $"This file changes the gateway from {stored.Gateway.Host}:{storedPort.ToString(CultureInfo.InvariantCulture)} to {newHost}:{newPort.ToString(CultureInfo.InvariantCulture)}. Your password would be sent to the new gateway. Confirm the change with your administrator before saving.";
    }

    /// <summary>
    /// Sets each row's first problem from the helper's indexed messages for that list.
    /// </summary>
    /// <param name="rows">The rows.</param>
    /// <param name="entries">The non-empty entries and their rows, or none when the list does not apply.</param>
    /// <param name="field">The list's JSON path.</param>
    /// <param name="fill">Places the entries into a scratch profile.</param>
    private static void MarkRows(ObservableCollection<EntryRow> rows, IReadOnlyList<(EntryRow Row, string Value)> entries, string field, Action<Profile> fill)
    {
        var messages = new Dictionary<EntryRow, string>();
        if (entries.Count > 0)
        {
            var scratch = new Profile { Backend = "native", Mfa = new Mfa { Mode = "none" } };
            fill(scratch);
            foreach (var problem in ProfileRules.Problems(scratch))
            {
                if (!problem.Field.StartsWith(field + "[", StringComparison.Ordinal) ||
                    !int.TryParse(problem.Field.AsSpan(field.Length + 1, problem.Field.Length - field.Length - 2), NumberStyles.None, CultureInfo.InvariantCulture, out var index) ||
                    index >= entries.Count)
                {
                    continue;
                }
                messages.TryAdd(entries[index].Row, char.ToUpperInvariant(problem.Message[0]) + problem.Message[1..]);
            }
        }
        foreach (var row in rows)
        {
            row.Problem = messages.GetValueOrDefault(row);
        }
    }

    /// <summary>
    /// Lists trimmed, non-empty entries with their rows.
    /// </summary>
    /// <param name="rows">The rows.</param>
    /// <returns>The entries.</returns>
    private static List<(EntryRow Row, string Value)> Entries(IEnumerable<EntryRow> rows) =>
        [.. rows.Select(r => (Row: r, Value: r.Text.Trim())).Where(e => e.Value.Length > 0)];

    /// <summary>
    /// Lists domain entries with one leading wildcard label removed and lowercased.
    /// </summary>
    /// <returns>The normalized entries.</returns>
    private List<(EntryRow Row, string Value)> DomainEntries() =>
        [.. Entries(DomainRows).Select(e => (e.Row, ProfileRules.NormalizeDomain(e.Value)))];

    /// <summary>
    /// Parses a non-negative decimal number, or returns null for anything else.
    /// </summary>
    /// <param name="text">The text.</param>
    /// <returns>The number or null.</returns>
    private static long? ParseNumber(string text) =>
        long.TryParse(text.Trim(), NumberStyles.None, CultureInfo.InvariantCulture, out var value) ? value : null;

    /// <summary>
    /// Selects custom routing or split DNS when a file supplies a list without its mode, so the
    /// entries are visible for review instead of silently dropped on save.
    /// </summary>
    /// <param name="draft">The parsed draft; it is not changed.</param>
    /// <returns>A copy with the modes chosen.</returns>
    private static ProfileDraft ShowingLists(ProfileDraft draft) => new()
    {
        SchemaVersion = draft.SchemaVersion,
        Id = draft.Id,
        Name = draft.Name,
        Backend = draft.Backend,
        Gateway = draft.Gateway,
        Realm = draft.Realm,
        TrustedCert = draft.TrustedCert,
        Mfa = draft.Mfa,
        Routes = draft.Routes is null ? null : new DraftRoutes
        {
            Mode = draft.Routes.Mode ?? (draft.Routes.Include is not null ? "custom" : null),
            Include = draft.Routes.Include,
            Exclude = draft.Routes.Exclude,
            PreserveLan = draft.Routes.PreserveLan,
        },
        Dns = draft.Dns is null ? null : new DraftDns
        {
            Mode = draft.Dns.Mode ?? (draft.Dns.Domains is not null ? "split" : null),
            Domains = draft.Dns.Domains,
        },
    };

    /// <summary>
    /// Stores an edited value and recomputes the derived state.
    /// </summary>
    /// <typeparam name="T">The value type.</typeparam>
    /// <param name="field">The backing field.</param>
    /// <param name="value">The new value.</param>
    /// <param name="property">The property name, supplied by the compiler.</param>
    private void Edit<T>(ref T field, T value, [System.Runtime.CompilerServices.CallerMemberName] string? property = null)
    {
        if (value is null)
        {
            return;
        }
        if (Set(ref field, value, property))
        {
            Recompute();
        }
    }

    /// <summary>
    /// Tracks added and removed rows.
    /// </summary>
    /// <param name="sender">The collection.</param>
    /// <param name="e">The change.</param>
    private void RowsChanged(object? sender, NotifyCollectionChangedEventArgs e)
    {
        foreach (var row in e.NewItems?.OfType<EntryRow>() ?? [])
        {
            row.PropertyChanged += RowChanged;
        }
        foreach (var row in e.OldItems?.OfType<EntryRow>() ?? [])
        {
            row.PropertyChanged -= RowChanged;
        }
        Recompute();
    }

    /// <summary>
    /// Recomputes when a row's text changes.
    /// </summary>
    /// <param name="sender">The row.</param>
    /// <param name="e">The change.</param>
    private void RowChanged(object? sender, PropertyChangedEventArgs e)
    {
        if (e.PropertyName == nameof(EntryRow.Text))
        {
            Recompute();
        }
    }
}
