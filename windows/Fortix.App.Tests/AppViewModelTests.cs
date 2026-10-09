using System.ComponentModel;
using Fortix.App.Model;
using Fortix.App.ViewModels;
using Fortix.Core.Client;
using Fortix.Core.Credentials;
using Fortix.Core.Profiles;
using Fortix.Core.Protocol;

namespace Fortix.App.Tests;

/// <summary>
/// Drives the coordinator against a scripted helper without any window or UI thread.
/// </summary>
public sealed class AppViewModelTests
{
    /// <summary>
    /// Builds a valid password-only profile with documentation-only identities.
    /// </summary>
    /// <param name="id">The identifier.</param>
    /// <returns>The profile.</returns>
    internal static Profile Sample(string id = "work") => new()
    {
        SchemaVersion = 1,
        Id = id,
        Name = "Work " + id,
        Gateway = new Gateway { Host = "vpn.example.com", Port = 443 },
        Username = "jane.doe",
    };

    /// <summary>
    /// Creates a connected coordinator.
    /// </summary>
    /// <param name="helper">The scripted helper.</param>
    /// <param name="credentials">The credential store.</param>
    /// <returns>The coordinator.</returns>
    private static async Task<AppViewModel> Connected(ScriptedHelper helper, MemoryCredentials? credentials = null)
    {
        var model = new AppViewModel(helper.Connector(), credentials ?? new MemoryCredentials()) { StopTimeout = TimeSpan.FromSeconds(5) };
        await model.ConnectHelperAsync();
        return model;
    }

    /// <summary>
    /// A state event for a profile.
    /// </summary>
    /// <param name="state">The phase.</param>
    /// <param name="attempt">The attempt.</param>
    /// <param name="detail">The detail.</param>
    /// <param name="wanted">Whether connectivity is wanted.</param>
    /// <returns>The event.</returns>
    private static HelperEvent State(string state, ulong attempt = 1, string detail = "", bool wanted = true) =>
        new() { Type = "state", Profile = "work", Attempt = attempt, State = state, Detail = detail, Wanted = wanted };

    /// <summary>
    /// A password challenge for the work profile.
    /// </summary>
    /// <param name="attempt">The attempt.</param>
    /// <returns>The event.</returns>
    private static HelperEvent Password(ulong attempt = 1) =>
        new() { Type = "challenge", Profile = "work", Attempt = attempt, ChallengeId = "c1", Kind = "password", Prompt = "Password" };

    /// <summary>
    /// Connecting subscribes with logs, loads states and profiles, and builds rows.
    /// </summary>
    [Fact]
    public async Task ConnectLoadsAuthoritativeState()
    {
        var helper = new ScriptedHelper();
        helper.Add(Sample());
        var model = await Connected(helper);
        Assert.True(model.Reachable);
        Assert.Single(model.Rows);
        Assert.Equal("disconnected", model.Rows[0].StateText);
        Assert.Equal("vpn.example.com:443 | native", model.Rows[0].Endpoint);
        Assert.True(model.Rows[0].CanConnect);
        Assert.Equal("Not connected", model.StatusText);
        Assert.True((bool)helper.Sent("subscribe")[0]["logs"]!);
        Assert.Null(model.ConnectionProblem);
    }

    /// <summary>
    /// An unauthorized caller sees the group repair instruction rather than a generic failure.
    /// </summary>
    [Fact]
    public async Task UnauthorizedConnectionExplainsGroup()
    {
        var helper = new ScriptedHelper { Failure = ("subscribe", HelperErrorCodes.Unauthorized, "not a member") };
        var model = new AppViewModel(helper.Connector(), new MemoryCredentials());
        await Assert.ThrowsAnyAsync<Exception>(() => model.ConnectHelperAsync());
        Assert.False(model.Reachable);
        Assert.Equal(HelperOperationException.PermissionMessage, model.ConnectionProblem);
        Assert.Equal("Helper unavailable", model.StatusText);
    }

    /// <summary>
    /// The system refusing to open the pipe carries the group repair instruction, while a
    /// verification failure wrapping the same error keeps its own text.
    /// </summary>
    [Fact]
    public async Task PipeAccessDeniedExplainsGroup()
    {
        var model = new AppViewModel(_ => Task.FromException<HelperClient>(new Win32Exception(5)), new MemoryCredentials());
        await Assert.ThrowsAnyAsync<Exception>(() => model.ConnectHelperAsync());
        Assert.False(model.Reachable);
        Assert.Equal(HelperOperationException.PermissionMessage, model.ConnectionProblem);
        Assert.Equal(
            "The Fortix helper service could not be verified. Reinstall it from the extracted release folder.",
            AppViewModel.FailureText(new HelperVerificationException(new Win32Exception(5))));
        Assert.Equal(
            "The operation could not be completed. Check the helper and configuration, then try again.",
            AppViewModel.FailureText(new Win32Exception(2)));
    }

    /// <summary>
    /// Dismissing a prompt while another operation runs sends nothing and keeps the prompt.
    /// </summary>
    [Fact]
    public async Task DismissWhileBusyKeepsPrompt()
    {
        var helper = new ScriptedHelper();
        helper.Add(Sample());
        var model = await Connected(helper);
        await model.ReceiveAsync(State(SessionPhases.WaitingPassword, wanted: false));
        await model.ReceiveAsync(Password());
        var prompt = model.CurrentPrompt!;
        var gate = new TaskCompletionSource();
        var running = model.PerformAsync(() => gate.Task);
        Assert.True(model.Busy);
        Assert.False(await model.DismissPromptAsync(prompt));
        Assert.Equal(AppViewModel.CancelWhileBusyMessage, model.Message);
        Assert.Empty(helper.Sent("cancel"));
        Assert.Empty(helper.Sent("down"));
        Assert.True(model.IsCurrent(prompt));
        gate.SetResult();
        Assert.True(await running);
        Assert.True(await model.DismissPromptAsync(prompt));
        Assert.Single(helper.Sent("cancel"));
        Assert.Single(helper.Sent("down"));
        Assert.Null(model.CurrentPrompt);
    }

    /// <summary>
    /// A rejected cancellation keeps the prompt and reports the failure.
    /// </summary>
    [Fact]
    public async Task RejectedDismissKeepsPrompt()
    {
        var helper = new ScriptedHelper();
        helper.Add(Sample());
        var model = await Connected(helper);
        await model.ReceiveAsync(State(SessionPhases.WaitingPassword, wanted: false));
        await model.ReceiveAsync(Password());
        var prompt = model.CurrentPrompt!;
        helper.Failure = ("cancel", "INTERNAL", "cancel failed");
        Assert.False(await model.DismissPromptAsync(prompt));
        Assert.Equal("INTERNAL: cancel failed", model.Message);
        Assert.True(model.IsCurrent(prompt));
        Assert.Same(prompt, model.CurrentPrompt);
        Assert.Empty(helper.Sent("down"));
    }

    /// <summary>
    /// A saved password answers its challenge once, and no prompt is shown.
    /// </summary>
    [Fact]
    public async Task SavedPasswordAnswersChallenge()
    {
        var helper = new ScriptedHelper();
        helper.Add(Sample());
        var credentials = new MemoryCredentials();
        credentials.Entries[CredentialTarget.For(Sample()).Target] = "synthetic-password";
        var model = await Connected(helper, credentials);
        await model.ReceiveAsync(State(SessionPhases.WaitingPassword));
        await model.ReceiveAsync(Password());
        var answer = Assert.Single(helper.Sent("answer"));
        Assert.Equal("c1", (string?)answer["challenge_id"]);
        Assert.Equal("synthetic-password", (string?)answer["secret"]);
        Assert.Null(model.CurrentPrompt);
        Assert.Empty(model.Prompts);
    }

    /// <summary>
    /// Without a saved password the prompt stays visible and the status asks for attention.
    /// </summary>
    [Fact]
    public async Task MissingPasswordShowsPrompt()
    {
        var helper = new ScriptedHelper();
        helper.Add(Sample());
        var model = await Connected(helper);
        await model.ReceiveAsync(State(SessionPhases.WaitingPassword, wanted: false));
        await model.ReceiveAsync(Password());
        Assert.Empty(helper.Sent("answer"));
        Assert.NotNull(model.CurrentPrompt);
        Assert.True(model.CurrentPrompt!.IsPassword);
        Assert.True(model.IsCurrent(model.CurrentPrompt));
        Assert.Equal(AggregateStatus.Attention, model.Aggregate);
    }

    /// <summary>
    /// A remembered password is written only after the matching attempt connects.
    /// </summary>
    [Fact]
    public async Task RememberedPasswordSavedOnConnect()
    {
        var helper = new ScriptedHelper();
        helper.Add(Sample());
        var credentials = new MemoryCredentials();
        var model = await Connected(helper, credentials);
        await model.ReceiveAsync(State(SessionPhases.WaitingPassword));
        await model.ReceiveAsync(Password());
        await model.AnswerAsync(model.CurrentPrompt!, "typed-password", remember: true);
        Assert.Empty(credentials.Entries);
        await model.ReceiveAsync(State(SessionPhases.Authenticating));
        Assert.Empty(credentials.Entries);
        await model.ReceiveAsync(State(SessionPhases.Connected));
        Assert.Equal("typed-password", credentials.Entries[CredentialTarget.For(Sample()).Target]);
    }

    /// <summary>
    /// A remembered password is discarded when its attempt fails, and the failure is reported once.
    /// </summary>
    [Fact]
    public async Task FailedAttemptDiscardsPasswordAndNotifiesOnce()
    {
        var helper = new ScriptedHelper();
        helper.Add(Sample());
        var credentials = new MemoryCredentials();
        var model = await Connected(helper, credentials);
        var failures = new List<ConnectionFailure>();
        model.Failure += (_, f) => failures.Add(f);
        await model.ReceiveAsync(State(SessionPhases.WaitingPassword));
        await model.ReceiveAsync(Password());
        await model.AnswerAsync(model.CurrentPrompt!, "typed-password", remember: true);
        await model.ReceiveAsync(State(SessionPhases.Failed, detail: "authentication failed", wanted: false));
        await model.ReceiveAsync(State(SessionPhases.Failed, detail: "authentication failed", wanted: false));
        await model.ReceiveAsync(State(SessionPhases.Connected));
        Assert.Empty(credentials.Entries);
        var failure = Assert.Single(failures);
        Assert.Equal(new ConnectionFailure("work", "Work work", "authentication failed"), failure);
    }

    /// <summary>
    /// An answer longer than the helper accepts is refused before sending and is never kept.
    /// </summary>
    [Fact]
    public async Task OversizedAnswerIsRefusedAndNotKept()
    {
        var helper = new ScriptedHelper();
        helper.Add(Sample());
        var credentials = new MemoryCredentials();
        var model = await Connected(helper, credentials);
        await model.ReceiveAsync(State(SessionPhases.WaitingPassword));
        await model.ReceiveAsync(Password());
        Assert.False(await model.PerformAsync(() => model.AnswerAsync(model.CurrentPrompt!, new string('x', 998), remember: true)));
        Assert.Empty(helper.Sent("answer"));
        Assert.NotNull(model.CurrentPrompt);
        await model.ReceiveAsync(State(SessionPhases.Connected));
        Assert.Empty(credentials.Entries);
    }

    /// <summary>
    /// A save failure after connecting is reported, not hidden.
    /// </summary>
    [Fact]
    public async Task CredentialWriteFailureIsReported()
    {
        var helper = new ScriptedHelper();
        helper.Add(Sample());
        var credentials = new MemoryCredentials { FailWrites = true };
        var model = await Connected(helper, credentials);
        await model.ReceiveAsync(State(SessionPhases.WaitingPassword));
        await model.ReceiveAsync(Password());
        await model.AnswerAsync(model.CurrentPrompt!, "typed-password", remember: true);
        await model.ReceiveAsync(State(SessionPhases.Connected));
        Assert.Equal("Connected, but the password could not be saved in Credential Manager.", model.Message);
    }

    /// <summary>
    /// Events from an older attempt never change a newer one, and a stale prompt cannot be answered.
    /// </summary>
    [Fact]
    public async Task StaleEventsAndPromptsAreIgnored()
    {
        var helper = new ScriptedHelper();
        helper.Add(Sample());
        var model = await Connected(helper);
        await model.ReceiveAsync(State(SessionPhases.WaitingPassword, attempt: 2));
        await model.ReceiveAsync(Password(attempt: 2));
        var prompt = model.CurrentPrompt!;
        await model.ReceiveAsync(State(SessionPhases.Connected, attempt: 1));
        Assert.Equal(SessionPhases.WaitingPassword, model.States["work"].State);
        await model.ReceiveAsync(State(SessionPhases.Authenticating, attempt: 2));
        Assert.Null(model.CurrentPrompt);
        await Assert.ThrowsAsync<StalePromptException>(() => model.AnswerAsync(prompt, "late", remember: false));
        Assert.Empty(helper.Sent("answer"));
    }

    /// <summary>
    /// A certificate decision sends exactly the reported digest after rechecking the status.
    /// </summary>
    [Fact]
    public async Task TrustSendsReportedDigest()
    {
        var helper = new ScriptedHelper();
        helper.Add(Sample(), SessionPhases.WaitingTrust, 1);
        var model = await Connected(helper);
        var digest = new string('a', 64);
        await model.ReceiveAsync(new HelperEvent { Type = "cert", Profile = "work", Attempt = 1, Digest = digest, Subject = "CN=vpn.example.com", Issuer = "CN=Example CA" });
        Assert.True(model.CurrentPrompt!.IsCertificate);
        await model.TrustAsync(model.CurrentPrompt);
        Assert.Equal(digest, (string?)Assert.Single(helper.Sent("trust"))["digest"]);
        Assert.Null(model.CurrentPrompt);
    }

    /// <summary>
    /// Disconnect succeeds only once the helper reports a clean stop.
    /// </summary>
    [Fact]
    public async Task DisconnectWaitsForCleanStop()
    {
        var helper = new ScriptedHelper();
        helper.Add(Sample(), SessionPhases.Connected, 3);
        helper.Sessions["work"]["wanted"] = true;
        helper.OnDown = _ => helper.SetSession("work", SessionPhases.Disconnected, 3);
        var model = await Connected(helper);
        await model.DisconnectAsync("work");
        Assert.Equal(SessionPhases.Disconnected, model.States["work"].State);
    }

    /// <summary>
    /// Pending cleanup after a stop is reported as an unclean disconnect.
    /// </summary>
    [Fact]
    public async Task UncleanStopIsReported()
    {
        var helper = new ScriptedHelper();
        helper.Add(Sample(), SessionPhases.Connected, 3);
        helper.OnDown = _ => helper.SetSession("work", SessionPhases.Disconnected, 3, cleanup: true);
        var model = await Connected(helper);
        Assert.False(await model.PerformAsync(() => model.DisconnectAsync("work")));
        Assert.Equal("Disconnect did not finish cleanly. Check the profile status before quitting.", model.Message);
        Assert.False(model.Busy);
    }

    /// <summary>
    /// A new profile never replaces a stored one with the same identifier.
    /// </summary>
    [Fact]
    public async Task SaveRejectsDuplicateNewProfile()
    {
        var helper = new ScriptedHelper();
        helper.Add(Sample());
        var model = await Connected(helper);
        Assert.False(await model.PerformAsync(() => model.SaveAsync(Sample(), existing: false)));
        Assert.Equal("This profile ID already exists. Edit the existing profile instead.", model.Message);
        Assert.Empty(helper.Sent("profile.put"));
        Assert.True(await model.PerformAsync(() => model.SaveAsync(Sample("home"), existing: false)));
        Assert.Equal(2, model.Rows.Count);
    }

    /// <summary>
    /// An invalid profile is refused locally with the helper's paths and messages.
    /// </summary>
    [Fact]
    public async Task SaveReportsCoreProblems()
    {
        var helper = new ScriptedHelper();
        var model = await Connected(helper);
        var invalid = Sample("Bad");
        var error = await Assert.ThrowsAsync<ProfileValidationException>(() => model.SaveAsync(invalid, existing: false));
        Assert.Contains(error.Problems, p => p.ToString() == "id: must match ^[a-z0-9][a-z0-9-]{0,62}$");
        Assert.Empty(helper.Sent("profile.put"));
    }

    /// <summary>
    /// Profiles the Windows helper refuses show its exact reason and cannot be connected.
    /// </summary>
    [Fact]
    public async Task WindowsUnavailableProfilesAreMarked()
    {
        var helper = new ScriptedHelper();
        var mfa = Sample("mfa");
        mfa.Mfa.Mode = "push";
        var openfortivpn = Sample("ofv");
        openfortivpn.Backend = "openfortivpn";
        helper.Add(mfa);
        helper.Add(openfortivpn);
        helper.Add(Sample());
        var model = await Connected(helper);
        Assert.Equal(ProfileRules.WindowsMfaUnavailable, model.Rows.Single(r => r.Id == "mfa").UnavailableReason);
        Assert.Equal(ProfileRules.WindowsOpenfortivpnUnavailable, model.Rows.Single(r => r.Id == "ofv").UnavailableReason);
        Assert.False(model.Rows.Single(r => r.Id == "mfa").CanConnect);
        await model.ConnectAllAsync();
        Assert.Equal("work", (string?)Assert.Single(helper.Sent("up"))["profile"]);
    }

    /// <summary>
    /// Log views keep only the newest 500 lines, each tagged with its profile.
    /// </summary>
    [Fact]
    public async Task LogsAreBounded()
    {
        var helper = new ScriptedHelper();
        helper.Add(Sample());
        var model = await Connected(helper);
        for (var i = 0; i < 510; i++)
        {
            await model.ReceiveAsync(new HelperEvent { Type = "log", Profile = "work", Line = $"event {i}" });
        }
        Assert.Equal(AppViewModel.MaxLogLines, model.Logs.Count);
        Assert.Equal("work: event 10", model.Logs[0]);
        await model.LoadLogsAsync("work");
        Assert.Equal(["work: line 0", "work: line 1", "work: line 2"], model.Logs);
        Assert.Equal(500, (int)helper.Sent("logs")[0]["lines"]!);
    }

    /// <summary>
    /// Operations never overlap and always end with Busy cleared.
    /// </summary>
    [Fact]
    public async Task PerformSerializesOperations()
    {
        var model = new AppViewModel(new ScriptedHelper().Connector(), new MemoryCredentials());
        var gate = new TaskCompletionSource();
        var first = model.PerformAsync(() => gate.Task);
        Assert.True(model.Busy);
        Assert.False(await model.PerformAsync(() => Task.CompletedTask));
        gate.SetResult();
        Assert.True(await first);
        Assert.False(model.Busy);
        Assert.False(await model.PerformAsync(() => model.ConnectAsync("work")));
        Assert.Equal("The Fortix helper service is not reachable.", model.Message);
    }

    /// <summary>
    /// Failure text never reflects raw exception messages.
    /// </summary>
    [Fact]
    public void FailureTextIsFixed()
    {
        Assert.Equal("BUSY: try later", AppViewModel.FailureText(new HelperOperationException("BUSY", "try later")));
        Assert.Equal(HelperOperationException.PermissionMessage, AppViewModel.FailureText(new HelperOperationException(HelperErrorCodes.Unauthorized, "x")));
        Assert.Equal("The operation timed out. Check the helper and try again.", AppViewModel.FailureText(new TimeoutException("secret detail")));
        Assert.Equal("The operation could not be completed. Check the helper and configuration, then try again.", AppViewModel.FailureText(new InvalidOperationException("secret detail")));
        Assert.Equal("The profile file was rejected because it contains a secret field (profiles[0].password). Profile files must never carry passwords, tokens, or cookies.",
            AppViewModel.SharedFailureText(new ShareException("secret", "profiles[0].password", "secret field")));
    }

    /// <summary>
    /// The tray menu lists profiles with connect and disconnect, then Open Fortix and Quit.
    /// </summary>
    [Fact]
    public async Task TrayMenuMirrorsState()
    {
        var helper = new ScriptedHelper();
        helper.Add(Sample());
        helper.SetSession("work", SessionPhases.Failed, 2, detail: "the gateway refused the connection because the account is locked out for now");
        var model = await Connected(helper);
        var opened = 0;
        var items = TrayMenu.Build(model, () => opened++, () => { });
        Assert.Equal("Needs attention", items[0].Text);
        var profile = items.Single(i => i.Text == "Work work: failed");
        Assert.Equal(["Connect", "Disconnect"], profile.Children!.Select(c => c.Text));
        Assert.Contains(items, i => i.Text.StartsWith("    the gateway refused", StringComparison.Ordinal));
        Assert.All(items.Where(i => i.Text.StartsWith("    ", StringComparison.Ordinal)), i => Assert.True(i.Text.Length <= 60));
        items.Single(i => i.Text == "Open Fortix").Action!();
        Assert.Equal(1, opened);
        Assert.Contains(items, i => i.Text == "Quit Fortix (leave tunnels running)");
    }
}
