using System.Collections.ObjectModel;
using System.ComponentModel;
using System.Text;
using Fortix.App.Model;
using Fortix.Core.Client;
using Fortix.Core.Credentials;
using Fortix.Core.Profiles;
using Fortix.Core.Protocol;

namespace Fortix.App.ViewModels;

/// <summary>
/// Coordinates the app's view of the helper; the helper owns every tunnel and stored profile.
/// </summary>
/// <remarks>
/// One helper connection carries requests and an ordered event stream. Reconnecting never
/// replays a connect or an answer. Prompts are bound to the exact profile, attempt, and
/// challenge that raised them, and a saved password is offered once per password challenge
/// and written to Credential Manager only after the matching attempt connects. Members are
/// meant to be used from one thread at a time, normally the UI thread.
/// </remarks>
public sealed class AppViewModel : ObservableObject
{
    /// <summary>The most log lines kept, matching the helper's largest log request.</summary>
    public const int MaxLogLines = 500;

    /// <summary>The explanation shown when a prompt is dismissed while another operation runs.</summary>
    public const string CancelWhileBusyMessage = "Another operation is still running. Cancel again when it finishes.";

    /// <summary>Opens and verifies a new helper connection.</summary>
    private readonly Func<CancellationToken, Task<HelperClient>> connector;

    /// <summary>Saved password storage.</summary>
    private readonly ICredentialStore credentials;

    /// <summary>Public states by profile identifier.</summary>
    private readonly Dictionary<string, ProfilePresentation> states = new(StringComparer.Ordinal);

    /// <summary>Queued prompts, oldest first, at most one per profile.</summary>
    private readonly List<PendingPrompt> prompts = [];

    /// <summary>Profiles whose password challenge is being answered from Credential Manager.</summary>
    private readonly HashSet<string> lookingUp = new(StringComparer.Ordinal);

    /// <summary>Passwords waiting for their attempt to connect before they are saved.</summary>
    private readonly Dictionary<string, SavedPassword> candidates = new(StringComparer.Ordinal);

    /// <summary>Failed attempts already reported, so each failure notifies once.</summary>
    private readonly HashSet<string> reportedFailures = new(StringComparer.Ordinal);

    /// <summary>Redacted log lines, oldest first.</summary>
    private readonly List<string> logs = [];

    /// <summary>The live connection, or null while disconnected.</summary>
    private HelperClient? client;

    /// <summary>Stops the reconnect loop.</summary>
    private CancellationTokenSource? loop;

    /// <summary>The reconnect loop.</summary>
    private Task? loopTask;

    /// <summary>The authoritative stored profiles.</summary>
    private IReadOnlyList<Profile> profiles = [];

    /// <summary>Whether the helper is connected and states are current.</summary>
    private bool reachable;

    /// <summary>Whether an explicit operation is running.</summary>
    private bool busy;

    /// <summary>The last operation result or failure.</summary>
    private string? message;

    /// <summary>Why the last connection attempt failed, or null.</summary>
    private string? connectionProblem;

    /// <summary>
    /// Creates an offline coordinator; nothing connects until <see cref="Start"/>.
    /// </summary>
    /// <param name="connector">Opens and verifies a helper connection.</param>
    /// <param name="credentials">Saved password storage.</param>
    public AppViewModel(Func<CancellationToken, Task<HelperClient>> connector, ICredentialStore credentials)
    {
        ArgumentNullException.ThrowIfNull(connector);
        ArgumentNullException.ThrowIfNull(credentials);
        this.connector = connector;
        this.credentials = credentials;
        ConnectAllCommand = new RelayCommand(_ => Perform(ConnectAllAsync), _ => Reachable && !Busy && profiles.Count > 0);
        DisconnectAllCommand = new RelayCommand(_ => Perform(() => DisconnectAsync(null)), _ => Reachable && !Busy);
        LoadLogsCommand = new RelayCommand(p => Perform(() => LoadLogsAsync((string)p!)), p => p is string { Length: > 0 } && Reachable && !Busy);
    }

    /// <summary>Raised once per failed attempt, never for states loaded at connection time.</summary>
    public event EventHandler<ConnectionFailure>? Failure;

    /// <summary>Gets or sets the wait between reconnect attempts.</summary>
    public TimeSpan RetryDelay { get; init; } = TimeSpan.FromSeconds(3);

    /// <summary>Gets or sets the bound on one helper request.</summary>
    public TimeSpan CallTimeout { get; init; } = TimeSpan.FromSeconds(10);

    /// <summary>Gets or sets the bound on a disconnect reaching a clean stop.</summary>
    public TimeSpan StopTimeout { get; init; } = TimeSpan.FromSeconds(30);

    /// <summary>Gets the stored profiles in helper order.</summary>
    public IReadOnlyList<Profile> Profiles => profiles;

    /// <summary>Gets the bindable profile rows.</summary>
    public ObservableCollection<ProfileRowViewModel> Rows { get; } = [];

    /// <summary>Gets the public states by profile identifier.</summary>
    public IReadOnlyDictionary<string, ProfilePresentation> States => states;

    /// <summary>Gets whether the helper is connected; stale states are never shown as current.</summary>
    public bool Reachable
    {
        get => reachable;
        private set => Set(ref reachable, value);
    }

    /// <summary>Gets whether an explicit operation is running; operations never overlap.</summary>
    public bool Busy
    {
        get => busy;
        private set => Set(ref busy, value);
    }

    /// <summary>Gets or sets the last operation result, always a fixed or helper-redacted text.</summary>
    public string? Message
    {
        get => message;
        set => Set(ref message, value);
    }

    /// <summary>Gets why the helper could not be reached, or null while connected.</summary>
    public string? ConnectionProblem
    {
        get => connectionProblem;
        private set => Set(ref connectionProblem, value);
    }

    /// <summary>Gets the queued prompts.</summary>
    public IReadOnlyList<PendingPrompt> Prompts => prompts;

    /// <summary>Gets the prompt to show, skipping profiles being answered from Credential Manager.</summary>
    public PendingPrompt? CurrentPrompt => prompts.FirstOrDefault(p => !lookingUp.Contains(p.Event.Profile));

    /// <summary>Gets the redacted log lines, prefixed with their profile.</summary>
    public IReadOnlyList<string> Logs => logs;

    /// <summary>Gets the log lines as one selectable text.</summary>
    public string LogText => string.Join(Environment.NewLine, logs);

    /// <summary>Gets the overall status with the command-line tray's precedence.</summary>
    public AggregateStatus Aggregate => AggregateStatusBuilder.Build(
        [.. states.Select(s => new AggregateProfile
        {
            Id = s.Key,
            State = s.Value.State,
            Wanted = s.Value.Wanted,
            PendingPassword = prompts.Any(p => p.Event.Profile == s.Key && p.IsPassword) && !lookingUp.Contains(s.Key),
            CleanupPending = s.Value.CleanupPending,
        })],
        Reachable);

    /// <summary>Gets the status as text, independent of the icon's shape.</summary>
    public string StatusText => RingGlyph.StatusText(Aggregate, Reachable);

    /// <summary>Gets the action that connects every profile Windows can connect.</summary>
    public RelayCommand ConnectAllCommand { get; }

    /// <summary>Gets the action that disconnects every profile.</summary>
    public RelayCommand DisconnectAllCommand { get; }

    /// <summary>Gets the action that loads a profile's recent log lines; the parameter is the profile identifier.</summary>
    public RelayCommand LoadLogsCommand { get; }

    /// <summary>
    /// Starts the reconnect loop once; it runs until <see cref="StopAsync"/>.
    /// </summary>
    public void Start()
    {
        if (loopTask is not null)
        {
            return;
        }
        loop = new CancellationTokenSource();
        loopTask = RunAsync(loop.Token);
    }

    /// <summary>
    /// Closes only the app's connection; helper-owned tunnels keep running.
    /// </summary>
    /// <returns>A task that completes when the loop and connection are closed.</returns>
    public async Task StopAsync()
    {
        if (loop is not null)
        {
            await loop.CancelAsync();
        }
        if (loopTask is not null)
        {
            await loopTask;
        }
        loop?.Dispose();
        loop = null;
        loopTask = null;
        await CloseClientAsync();
        Invalidate();
    }

    /// <summary>
    /// Opens a fresh connection, subscribes, and loads authoritative states and profiles.
    /// </summary>
    /// <remarks>
    /// Nothing is started or answered: reconnecting only refreshes what the helper reports.
    /// </remarks>
    /// <param name="cancellationToken">Cancels the attempt.</param>
    /// <returns>A task that completes when the app is current.</returns>
    public async Task ConnectHelperAsync(CancellationToken cancellationToken = default)
    {
        await CloseClientAsync();
        Invalidate();
        HelperClient? opened = null;
        try
        {
            opened = await connector(cancellationToken);
            client = opened;
            await Bounded((c, t) => c.SubscribeAsync(logs: true, t));
            var snapshots = await Bounded((c, t) => c.StatusAsync(t));
            Apply(snapshots);
            await RefreshProfilesAsync();
            Reachable = true;
            ConnectionProblem = null;
            Changed();
        }
        catch (Exception e)
        {
            ConnectionProblem = FailureText(e);
            client = null;
            if (opened is not null)
            {
                await opened.DisposeAsync();
            }
            Invalidate();
            throw;
        }
    }

    /// <summary>
    /// Applies one helper event, ignoring events from older attempts.
    /// </summary>
    /// <param name="helperEvent">The event.</param>
    /// <returns>A task that completes when any automatic answer was sent.</returns>
    public async Task ReceiveAsync(HelperEvent helperEvent)
    {
        ArgumentNullException.ThrowIfNull(helperEvent);
        var id = helperEvent.Profile;
        if (states.TryGetValue(id, out var known) && helperEvent.Attempt < known.Attempt)
        {
            return;
        }
        switch (helperEvent.Type)
        {
            case "log":
                AppendLogs([$"{id}: {helperEvent.Line}"], replace: false);
                return;
            case "state":
                ApplyState(helperEvent);
                return;
            case "challenge" or "cert":
                break;
            default:
                return;
        }
        var prompt = new PendingPrompt(helperEvent);
        if (prompts.Any(p => p.Id == prompt.Id))
        {
            return;
        }
        prompts.RemoveAll(p => p.Event.Profile == id);
        prompts.Add(prompt);
        if (!prompt.IsPassword)
        {
            Changed();
            return;
        }
        // A saved password answers the challenge once; on any problem the prompt stays visible.
        lookingUp.Add(id);
        Changed();
        try
        {
            var profile = await Bounded((c, t) => c.ProfileGetAsync(id, t));
            var password = credentials.Read(CredentialTarget.For(profile));
            if (IsCurrent(prompt))
            {
                await AnswerAsync(prompt, password, remember: false);
            }
        }
        catch (Exception e) when (e is not OutOfMemoryException)
        {
            // A missing or unusable saved password leaves the challenge for explicit entry.
        }
        finally
        {
            lookingUp.Remove(id);
            Changed();
        }
    }

    /// <summary>
    /// Reports whether a prompt still matches the live connection, attempt, and phase.
    /// </summary>
    /// <param name="prompt">The prompt.</param>
    /// <returns>True when answering it is still meaningful.</returns>
    public bool IsCurrent(PendingPrompt prompt)
    {
        ArgumentNullException.ThrowIfNull(prompt);
        return Reachable && prompts.Any(p => p.Id == prompt.Id) &&
            states.TryGetValue(prompt.Event.Profile, out var state) && state.Attempt == prompt.Event.Attempt &&
            MatchesPrompt(prompt, state.State);
    }

    /// <summary>
    /// Runs one explicit operation unless another is running, showing any failure as fixed text.
    /// </summary>
    /// <param name="operation">The operation.</param>
    /// <returns>True when the operation ran and succeeded.</returns>
    public async Task<bool> PerformAsync(Func<Task> operation)
    {
        ArgumentNullException.ThrowIfNull(operation);
        if (Busy)
        {
            return false;
        }
        Busy = true;
        Message = null;
        Changed();
        try
        {
            await operation();
            return true;
        }
        catch (Exception e)
        {
            Message = FailureText(e);
            return false;
        }
        finally
        {
            Busy = false;
            Changed();
        }
    }

    /// <summary>
    /// Starts <see cref="PerformAsync"/> without waiting, for commands.
    /// </summary>
    /// <param name="operation">The operation.</param>
    public void Perform(Func<Task> operation) => _ = PerformAsync(operation);

    /// <summary>
    /// Asks the helper to connect a profile; the stored backend is never changed.
    /// </summary>
    /// <param name="id">The profile identifier.</param>
    /// <returns>A task that completes when the helper accepted the request.</returns>
    public Task ConnectAsync(string id) => Bounded((c, t) => c.UpAsync(id, t));

    /// <summary>
    /// Connects every profile Windows can connect, one after another.
    /// </summary>
    /// <returns>A task that completes when every request was accepted.</returns>
    public async Task ConnectAllAsync()
    {
        foreach (var profile in profiles.Where(p => ProfileText.WindowsUnavailableReason(p) is null).ToList())
        {
            await ConnectAsync(profile.Id);
        }
    }

    /// <summary>
    /// Disconnects one profile, or all when <paramref name="id"/> is null, and waits for a clean stop.
    /// </summary>
    /// <remarks>
    /// Success means every affected profile reports disconnected, unwanted, and without pending
    /// cleanup in the same attempt; a failed or unclean stop is reported, never hidden.
    /// </remarks>
    /// <param name="id">The profile identifier, or null for all.</param>
    /// <returns>A task that completes after a clean stop.</returns>
    /// <exception cref="StopFailedException">The stop did not finish cleanly.</exception>
    /// <exception cref="TimeoutException">The stop did not finish in time.</exception>
    public async Task DisconnectAsync(string? id)
    {
        var deadline = DateTime.UtcNow + StopTimeout;
        var before = await Bounded((c, t) => c.StatusAsync(t));
        var targets = before.Where(s => id is null || s.Profile == id).ToDictionary(s => s.Profile, s => s.Attempt, StringComparer.Ordinal);
        if (id is not null && targets.Count == 0)
        {
            throw new StopFailedException();
        }
        await Bounded((c, t) => id is null ? c.DownAllAsync(t) : c.DownAsync(id, t));
        while (true)
        {
            if (DateTime.UtcNow >= deadline)
            {
                throw new TimeoutException("disconnect did not finish in time");
            }
            var snapshots = await Bounded((c, t) => c.StatusAsync(t));
            var clean = true;
            foreach (var (profile, attempt) in targets)
            {
                var snapshot = snapshots.FirstOrDefault(s => s.Profile == profile);
                if (snapshot is null || snapshot.Attempt != attempt || snapshot.Wanted || snapshot.CleanupPending ||
                    snapshot.State == SessionPhases.Failed || snapshot.Detail.StartsWith("network cleanup failed", StringComparison.Ordinal))
                {
                    Apply(snapshots);
                    throw new StopFailedException();
                }
                clean &= snapshot.State == SessionPhases.Disconnected;
            }
            if (clean)
            {
                Apply(snapshots);
                Changed();
                return;
            }
            await Task.Delay(TimeSpan.FromMilliseconds(100));
        }
    }

    /// <summary>
    /// Validates and stores a profile through the helper, then reloads the profile list.
    /// </summary>
    /// <param name="profile">The profile; automatic choices stay omitted.</param>
    /// <param name="existing">True when editing a stored profile; new profiles never replace one.</param>
    /// <returns>A task that completes when the helper stored the profile.</returns>
    /// <exception cref="ProfileValidationException">The profile is invalid.</exception>
    /// <exception cref="DuplicateProfileException">A new profile reuses a stored identifier.</exception>
    public async Task SaveAsync(Profile profile, bool existing)
    {
        ArgumentNullException.ThrowIfNull(profile);
        var check = profile.Clone();
        ProfileRules.ApplyDefaults(check);
        var problems = ProfileRules.Validate(check);
        if (problems.Count > 0)
        {
            throw new ProfileValidationException(problems);
        }
        if (!existing)
        {
            // A fresh list catches profiles created since the app last refreshed.
            var stored = await Bounded((c, t) => c.ProfileListAsync(t));
            if (stored.Any(s => s.Profile == profile.Id))
            {
                throw new DuplicateProfileException();
            }
        }
        await Bounded((c, t) => c.ProfilePutAsync(profile, t));
        await RefreshProfilesAsync();
        Changed();
    }

    /// <summary>
    /// Deletes an idle profile; the helper refuses active ones.
    /// </summary>
    /// <param name="id">The profile identifier.</param>
    /// <returns>A task that completes when the profile is gone.</returns>
    public async Task DeleteAsync(string id)
    {
        await Bounded((c, t) => c.ProfileDeleteAsync(id, t));
        await RefreshProfilesAsync();
        states.Remove(id);
        Changed();
    }

    /// <summary>
    /// Removes the saved password of the profile as currently stored; an absent password is fine.
    /// </summary>
    /// <param name="id">The profile identifier.</param>
    /// <returns>A task that completes when the password is gone.</returns>
    public async Task ForgetAsync(string id)
    {
        var profile = await Bounded((c, t) => c.ProfileGetAsync(id, t));
        credentials.Delete(CredentialTarget.For(profile));
        candidates.Remove(id);
        Message = "The saved password was removed.";
    }

    /// <summary>
    /// Answers a password or code prompt after checking it is still current.
    /// </summary>
    /// <remarks>
    /// A password chosen to be remembered is kept in memory only until its attempt connects,
    /// then saved; any other outcome discards it. Codes are never saved.
    /// </remarks>
    /// <param name="prompt">The prompt.</param>
    /// <param name="secret">The answer; it is never logged or shown.</param>
    /// <param name="remember">Whether to save a password after connecting.</param>
    /// <returns>A task that completes when the helper accepted the answer.</returns>
    /// <exception cref="StalePromptException">The prompt is no longer current or the answer is empty.</exception>
    public async Task AnswerAsync(PendingPrompt prompt, string secret, bool remember)
    {
        ArgumentNullException.ThrowIfNull(prompt);
        if (!IsCurrent(prompt) || prompt.IsCertificate || prompt.Event.ChallengeId.Length == 0 ||
            prompt.Event.Kind is not ("password" or "code") || string.IsNullOrEmpty(secret))
        {
            throw new StalePromptException();
        }
        var profile = await Bounded((c, t) => c.ProfileGetAsync(prompt.Event.Profile, t));
        if (!IsCurrent(prompt))
        {
            throw new StalePromptException();
        }
        string? notice = null;
        if (remember && prompt.IsPassword)
        {
            if (Encoding.UTF8.GetByteCount(secret) > CredentialBlob.MaxBytes)
            {
                notice = "This password is longer than 2560 bytes, so it cannot be saved in Credential Manager.";
            }
            else
            {
                candidates[profile.Id] = new SavedPassword(prompt.Event.Attempt, CredentialTarget.For(profile), secret);
            }
        }
        try
        {
            await Bounded((c, t) => c.AnswerAsync(prompt.Event.ChallengeId, secret, t));
        }
        catch
        {
            candidates.Remove(profile.Id);
            throw;
        }
        prompts.RemoveAll(p => p.Id == prompt.Id);
        Changed();
        if (notice is not null)
        {
            Message = notice;
        }
    }

    /// <summary>
    /// Trusts the certificate a current rejection reported; the digest is never user-editable.
    /// </summary>
    /// <param name="prompt">The certificate prompt.</param>
    /// <returns>A task that completes when the helper stored the trust decision.</returns>
    /// <exception cref="StalePromptException">The rejection is no longer current.</exception>
    public async Task TrustAsync(PendingPrompt prompt)
    {
        ArgumentNullException.ThrowIfNull(prompt);
        if (!IsCurrent(prompt) || !prompt.IsCertificate || prompt.Event.Digest.Length == 0)
        {
            throw new StalePromptException();
        }
        var snapshots = await Bounded((c, t) => c.StatusAsync(t));
        if (!IsCurrent(prompt) || !snapshots.Any(s => s.Profile == prompt.Event.Profile && s.Attempt == prompt.Event.Attempt && s.State == SessionPhases.WaitingTrust))
        {
            throw new StalePromptException();
        }
        await Bounded((c, t) => c.TrustAsync(prompt.Event.Profile, prompt.Event.Digest, t));
        prompts.RemoveAll(p => p.Id == prompt.Id);
        Changed();
    }

    /// <summary>
    /// Cancels a prompt and stops its attempt, so closing a dialog never leaves a request running.
    /// </summary>
    /// <param name="prompt">The prompt.</param>
    /// <returns>A task that completes when the attempt stopped.</returns>
    public async Task CancelAsync(PendingPrompt prompt)
    {
        ArgumentNullException.ThrowIfNull(prompt);
        if (!IsCurrent(prompt))
        {
            prompts.RemoveAll(p => p.Id == prompt.Id);
            Changed();
            return;
        }
        if (prompt.Event.ChallengeId.Length > 0)
        {
            await Bounded((c, t) => c.CancelChallengeAsync(prompt.Event.ChallengeId, t));
        }
        await DisconnectAsync(prompt.Event.Profile);
        prompts.RemoveAll(p => p.Id == prompt.Id);
        Changed();
    }

    /// <summary>
    /// Cancels a prompt for a closing dialog and reports whether the dialog may close.
    /// </summary>
    /// <remarks>
    /// A dialog stays open until its request is actually cancelled: while another operation
    /// runs, nothing is sent and the dialog is kept with an explanation, and a rejected
    /// cancellation keeps it with the failure text. A prompt that is no longer current needs
    /// no cancellation, so its dialog may always close.
    /// </remarks>
    /// <param name="prompt">The prompt.</param>
    /// <returns>True when the request was cancelled or is no longer current.</returns>
    public async Task<bool> DismissPromptAsync(PendingPrompt prompt)
    {
        ArgumentNullException.ThrowIfNull(prompt);
        if (!IsCurrent(prompt))
        {
            prompts.RemoveAll(p => p.Id == prompt.Id);
            Changed();
            return true;
        }
        if (Busy)
        {
            Message = CancelWhileBusyMessage;
            return false;
        }
        return await PerformAsync(() => CancelAsync(prompt)) || !IsCurrent(prompt);
    }

    /// <summary>
    /// Replaces the log view with a profile's newest redacted lines from the helper.
    /// </summary>
    /// <param name="id">The profile identifier.</param>
    /// <returns>A task that completes when the lines are shown.</returns>
    public async Task LoadLogsAsync(string id)
    {
        var lines = await Bounded((c, t) => c.LogsAsync(id, MaxLogLines, t));
        AppendLogs([.. lines.TakeLast(MaxLogLines).Select(line => $"{id}: {line}")], replace: true);
    }

    /// <summary>
    /// Maps any failure to fixed text or the helper's redacted message, never raw exception text.
    /// </summary>
    /// <remarks>
    /// A bare access-denied error only comes from opening the helper pipe, which the system refuses
    /// to a session without the fortix group, so it carries the same repair instruction as the
    /// helper's own rejection. Verification failures arrive wrapped and keep their own text.
    /// </remarks>
    /// <param name="error">The failure.</param>
    /// <returns>The message to show.</returns>
    public static string FailureText(Exception error) => error switch
    {
        DuplicateProfileException => "This profile ID already exists. Edit the existing profile instead.",
        HelperOperationException { Code: HelperErrorCodes.Unauthorized } => HelperOperationException.PermissionMessage,
        Win32Exception { NativeErrorCode: ServiceIdentityRules.ErrorAccessDenied } => HelperOperationException.PermissionMessage,
        HelperOperationException operation => $"{operation.Code}: {operation.Detail}",
        ShareException share => SharedFailureText(share),
        ProfileValidationException invalid => "The profile is invalid:" + Environment.NewLine + string.Join(Environment.NewLine, invalid.Problems),
        StopFailedException => "Disconnect did not finish cleanly. Check the profile status before quitting.",
        TimeoutException => "The operation timed out. Check the helper and try again.",
        StalePromptException => "This request is no longer current.",
        CredentialStoreException { Failure: CredentialFailure.TooLong } => "The password is longer than 2560 bytes and cannot be saved in Credential Manager.",
        CredentialStoreException => "Credential Manager could not be used for this password.",
        HelperVerificationException => "The Fortix helper service could not be verified. Reinstall it from the extracted release folder.",
        HelperDisconnectedException or IOException or HelperProtocolException => "The Fortix helper service is not reachable.",
        _ => "The operation could not be completed. Check the helper and configuration, then try again.",
    };

    /// <summary>
    /// Explains a rejected profile file using only fixed messages and schema paths.
    /// </summary>
    /// <param name="error">The rejection.</param>
    /// <returns>The message to show; a secret field is named by its key, never its value.</returns>
    public static string SharedFailureText(ShareException error)
    {
        ArgumentNullException.ThrowIfNull(error);
        return error.Kind switch
        {
            "secret" => $"The profile file was rejected because it contains a secret field ({error.Field}). Profile files must never carry passwords, tokens, or cookies.",
            "size" => "The profile file is larger than 1 MiB.",
            "count" => "A profile file must contain 1 to 32 profiles.",
            _ => $"The profile file was rejected. {(error.Field == "$" ? "" : error.Field + ": ")}{error.Detail}.",
        };
    }

    /// <summary>
    /// Reports whether a prompt matches the phase the helper is in.
    /// </summary>
    /// <param name="prompt">The prompt.</param>
    /// <param name="state">The current phase.</param>
    /// <returns>True when the phase still waits for this kind of answer.</returns>
    private static bool MatchesPrompt(PendingPrompt prompt, string state)
    {
        if (prompt.IsCertificate)
        {
            return state == SessionPhases.WaitingTrust;
        }
        return prompt.Event.Kind == "password" ? state == SessionPhases.WaitingPassword : state == SessionPhases.WaitingCode;
    }

    /// <summary>
    /// Connects, consumes events, and reconnects after a pause until stopped.
    /// </summary>
    /// <param name="cancellationToken">Stops the loop.</param>
    /// <returns>A task that completes when the loop stops.</returns>
    private async Task RunAsync(CancellationToken cancellationToken)
    {
        while (!cancellationToken.IsCancellationRequested)
        {
            try
            {
                await ConnectHelperAsync(cancellationToken);
                var events = client!.Events;
                await foreach (var helperEvent in events.ReadAllAsync(cancellationToken))
                {
                    await ReceiveAsync(helperEvent);
                }
            }
            catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
            {
                break;
            }
            catch (Exception e)
            {
                ConnectionProblem ??= FailureText(e);
            }
            await CloseClientAsync();
            Invalidate();
            try
            {
                await Task.Delay(RetryDelay, cancellationToken);
            }
            catch (OperationCanceledException)
            {
                break;
            }
        }
    }

    /// <summary>
    /// Applies a state event, reporting failures and saving or discarding a remembered password.
    /// </summary>
    /// <param name="helperEvent">The state event.</param>
    private void ApplyState(HelperEvent helperEvent)
    {
        var id = helperEvent.Profile;
        var state = helperEvent.State.Length == 0 ? "unknown" : helperEvent.State;
        states[id] = new ProfilePresentation(helperEvent.Attempt, state, helperEvent.Detail, helperEvent.Wanted, helperEvent.CleanupPending);
        if (state == SessionPhases.Failed && reportedFailures.Add($"{id}:{helperEvent.Attempt}"))
        {
            var name = profiles.FirstOrDefault(p => p.Id == id)?.Name ?? id;
            Failure?.Invoke(this, new ConnectionFailure(id, name, helperEvent.Detail));
        }
        prompts.RemoveAll(p => p.Event.Profile == id && (p.Event.Attempt != helperEvent.Attempt || !MatchesPrompt(p, state)));
        if (candidates.TryGetValue(id, out var candidate))
        {
            if (candidate.Attempt == helperEvent.Attempt && state == SessionPhases.Connected)
            {
                candidates.Remove(id);
                try
                {
                    credentials.Write(candidate.Target, candidate.Secret);
                }
                catch (CredentialStoreException)
                {
                    Message = "Connected, but the password could not be saved in Credential Manager.";
                }
            }
            else if (candidate.Attempt != helperEvent.Attempt ||
                state is SessionPhases.Failed or SessionPhases.Disconnected or SessionPhases.Stopping or SessionPhases.Backoff)
            {
                candidates.Remove(id);
            }
        }
        Changed();
    }

    /// <summary>
    /// Appends or replaces log lines, keeping the newest <see cref="MaxLogLines"/>.
    /// </summary>
    /// <param name="lines">The lines.</param>
    /// <param name="replace">Whether to discard the current lines first.</param>
    private void AppendLogs(IReadOnlyList<string> lines, bool replace)
    {
        if (replace)
        {
            logs.Clear();
        }
        logs.AddRange(lines);
        if (logs.Count > MaxLogLines)
        {
            logs.RemoveRange(0, logs.Count - MaxLogLines);
        }
        OnPropertyChanged(nameof(Logs));
        OnPropertyChanged(nameof(LogText));
    }

    /// <summary>
    /// Replaces public states with authoritative snapshots.
    /// </summary>
    /// <param name="snapshots">The snapshots.</param>
    private void Apply(IEnumerable<SessionStatus> snapshots)
    {
        states.Clear();
        foreach (var s in snapshots)
        {
            states[s.Profile] = new ProfilePresentation(s.Attempt, s.State, s.Detail, s.Wanted, s.CleanupPending);
        }
    }

    /// <summary>
    /// Reloads every stored profile from the helper; no local copy is ever written.
    /// </summary>
    /// <returns>A task that completes when the list is current.</returns>
    private async Task RefreshProfilesAsync()
    {
        var list = await Bounded((c, t) => c.ProfileListAsync(t));
        var loaded = new List<Profile>(list.Count);
        foreach (var entry in list)
        {
            loaded.Add(await Bounded((c, t) => c.ProfileGetAsync(entry.Profile, t)));
        }
        profiles = loaded;
        Rows.Clear();
        foreach (var profile in loaded)
        {
            Rows.Add(new ProfileRowViewModel(profile, this));
        }
        OnPropertyChanged(nameof(Profiles));
    }

    /// <summary>
    /// Drops prompts, remembered passwords, and lookups instead of trusting stale state.
    /// </summary>
    private void Invalidate()
    {
        Reachable = false;
        prompts.Clear();
        candidates.Clear();
        lookingUp.Clear();
        Changed();
    }

    /// <summary>
    /// Closes the current connection, if any.
    /// </summary>
    /// <returns>A task that completes when it is closed.</returns>
    private async Task CloseClientAsync()
    {
        var current = client;
        client = null;
        if (current is not null)
        {
            await current.DisposeAsync();
        }
    }

    /// <summary>
    /// Notifies derived values and refreshes row and command availability.
    /// </summary>
    private void Changed()
    {
        foreach (var row in Rows)
        {
            row.Update(states.GetValueOrDefault(row.Id), Reachable, Busy);
        }
        ConnectAllCommand.Refresh();
        DisconnectAllCommand.Refresh();
        LoadLogsCommand.Refresh();
        OnPropertyChanged(nameof(Prompts));
        OnPropertyChanged(nameof(CurrentPrompt));
        OnPropertyChanged(nameof(Aggregate));
        OnPropertyChanged(nameof(StatusText));
        OnPropertyChanged(nameof(States));
    }

    /// <summary>
    /// Runs one request on the live connection with a bounded wait.
    /// </summary>
    /// <typeparam name="T">The result type.</typeparam>
    /// <param name="call">The request.</param>
    /// <returns>The result.</returns>
    /// <exception cref="HelperDisconnectedException">No connection is open.</exception>
    /// <exception cref="TimeoutException">The helper did not answer in time.</exception>
    private async Task<T> Bounded<T>(Func<HelperClient, CancellationToken, Task<T>> call)
    {
        var current = client ?? throw new HelperDisconnectedException("helper connection closed");
        using var timeout = new CancellationTokenSource(CallTimeout);
        try
        {
            return await call(current, timeout.Token);
        }
        catch (OperationCanceledException) when (timeout.IsCancellationRequested)
        {
            throw new TimeoutException("the helper did not respond in time");
        }
    }

    /// <summary>
    /// Runs one request without a result on the live connection with a bounded wait.
    /// </summary>
    /// <param name="call">The request.</param>
    /// <returns>A task that completes with the request.</returns>
    private Task Bounded(Func<HelperClient, CancellationToken, Task> call) =>
        Bounded<bool>(async (c, t) =>
        {
            await call(c, t);
            return true;
        });

    /// <summary>
    /// A password held only until its attempt connects or ends.
    /// </summary>
    /// <remarks>
    /// A class rather than a record, so no generated ToString can ever print the secret.
    /// </remarks>
    /// <param name="attempt">The attempt that used it.</param>
    /// <param name="target">The identity loaded before answering.</param>
    /// <param name="secret">The password; never published, logged, or written elsewhere.</param>
    private sealed class SavedPassword(ulong attempt, CredentialTarget target, string secret)
    {
        /// <summary>Gets the attempt that used the password.</summary>
        public ulong Attempt { get; } = attempt;

        /// <summary>Gets the identity loaded before answering.</summary>
        public CredentialTarget Target { get; } = target;

        /// <summary>Gets the password.</summary>
        public string Secret { get; } = secret;
    }
}
