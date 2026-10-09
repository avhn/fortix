namespace Fortix.App.ViewModels;

/// <summary>
/// One notification-area menu entry; a null action with no children is informational.
/// </summary>
/// <param name="Text">The label.</param>
/// <param name="Enabled">Whether the entry can be chosen.</param>
/// <param name="Action">What choosing the entry does, or null.</param>
/// <param name="Children">The submenu entries, or null.</param>
public sealed record TrayMenuItem(string Text, bool Enabled = true, Action? Action = null, IReadOnlyList<TrayMenuItem>? Children = null)
{
    /// <summary>Gets a separator line.</summary>
    public static TrayMenuItem Separator { get; } = new("", Enabled: false);

    /// <summary>Gets whether this entry is a separator.</summary>
    public bool IsSeparator => Text.Length == 0;
}

/// <summary>
/// Builds the notification-area menu from current state each time it opens.
/// </summary>
public static class TrayMenu
{
    /// <summary>
    /// Returns the menu: status, profiles with connect and disconnect, bulk actions, Open Fortix, and Quit.
    /// </summary>
    /// <param name="model">The coordinator.</param>
    /// <param name="open">Opens the management window.</param>
    /// <param name="quit">Quits the app, leaving tunnels running.</param>
    /// <returns>The entries in display order.</returns>
    public static IReadOnlyList<TrayMenuItem> Build(AppViewModel model, Action open, Action quit)
    {
        ArgumentNullException.ThrowIfNull(model);
        var idle = model.Reachable && !model.Busy;
        var items = new List<TrayMenuItem> { new(model.StatusText, Enabled: false) };
        if (model.Message is { Length: > 0 } message)
        {
            items.AddRange(Wrap(message).Select(line => new TrayMenuItem(line, Enabled: false)));
        }
        items.Add(TrayMenuItem.Separator);
        foreach (var profile in model.Profiles)
        {
            var id = profile.Id;
            var state = model.States.GetValueOrDefault(id);
            var unavailable = ProfileText.WindowsUnavailableReason(profile);
            items.Add(new TrayMenuItem(
                $"{profile.Name}: {(model.Reachable ? ProfileText.Phase(state?.State ?? "") : "status unavailable")}",
                Children:
                [
                    new("Connect", idle && state?.Wanted != true && unavailable is null, () => model.Perform(() => model.ConnectAsync(id))),
                    new("Disconnect", idle, () => model.Perform(() => model.DisconnectAsync(id))),
                ]));
            // A failure reason sits under its profile, so a refusal explains itself.
            var reason = unavailable ?? (state is { State: "failed" or "backoff", Detail.Length: > 0 } ? state.Detail : null);
            if (reason is not null)
            {
                items.AddRange(Wrap(reason).Select(line => new TrayMenuItem("    " + line, Enabled: false)));
            }
        }
        items.Add(new TrayMenuItem("Connect all", idle && model.Profiles.Count > 0, () => model.Perform(model.ConnectAllAsync)));
        items.Add(new TrayMenuItem("Disconnect all", idle, () => model.Perform(() => model.DisconnectAsync(null))));
        items.Add(TrayMenuItem.Separator);
        items.Add(new TrayMenuItem(model.Prompts.Count == 0 ? "Open Fortix" : "Open Fortix (request pending)", Action: open));
        items.Add(TrayMenuItem.Separator);
        items.Add(new TrayMenuItem("Quit Fortix (leave tunnels running)", Action: quit));
        items.Add(new TrayMenuItem("Disconnect all and quit", idle, () => _ = DisconnectAndQuitAsync(model, quit)));
        return items;
    }

    /// <summary>
    /// Quits only after every tunnel stopped cleanly; a failure stays visible instead.
    /// </summary>
    /// <param name="model">The coordinator.</param>
    /// <param name="quit">Quits the app.</param>
    /// <returns>A task that completes when the decision is made.</returns>
    private static async Task DisconnectAndQuitAsync(AppViewModel model, Action quit)
    {
        if (await model.PerformAsync(() => model.DisconnectAsync(null)))
        {
            quit();
        }
    }

    /// <summary>
    /// Splits text into lines short enough to keep the menu narrow.
    /// </summary>
    /// <param name="text">The text.</param>
    /// <param name="width">The longest line, in characters.</param>
    /// <returns>The lines.</returns>
    public static IReadOnlyList<string> Wrap(string text, int width = 56)
    {
        ArgumentNullException.ThrowIfNull(text);
        var lines = new List<string>();
        var line = "";
        foreach (var word in text.Split(' ', StringSplitOptions.RemoveEmptyEntries))
        {
            if (line.Length > 0 && line.Length + 1 + word.Length > width)
            {
                lines.Add(line);
                line = "";
            }
            line = line.Length == 0 ? word : line + " " + word;
        }
        if (line.Length > 0)
        {
            lines.Add(line);
        }
        return lines;
    }
}
