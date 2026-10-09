using Fortix.App.ViewModels;

namespace Fortix.App.Tests;

/// <summary>
/// Covers the profile editor's save guard: duplicate submissions, closing while a save runs, and
/// results that arrive after the window closed.
/// </summary>
public sealed class DialogSaveGateTests
{
    /// <summary>
    /// A second submission while a save runs is refused until the first one finishes.
    /// </summary>
    [Fact]
    public void RefusesDuplicateSubmissions()
    {
        var gate = new DialogSaveGate();
        Assert.True(gate.TryBegin());
        Assert.False(gate.TryBegin());
        Assert.False(gate.Finish(false));
        Assert.True(gate.TryBegin());
    }

    /// <summary>
    /// Cancel, Escape, and title-bar close requests are refused while a save is in flight, and the
    /// delayed successful reply then closes the still-open dialog.
    /// </summary>
    [Fact]
    public void RefusesCloseWhileSavingThenClosesOnSuccess()
    {
        var gate = new DialogSaveGate();
        Assert.True(gate.AllowClose());
        Assert.True(gate.TryBegin());
        Assert.False(gate.AllowClose());
        Assert.False(gate.Idle);
        Assert.True(gate.Finish(true));
        Assert.True(gate.AllowClose());
        Assert.True(gate.Idle);
    }

    /// <summary>
    /// A successful reply that arrives after the window closed never yields a dialog result.
    /// </summary>
    [Fact]
    public void IgnoresResultAfterClose()
    {
        var gate = new DialogSaveGate();
        Assert.True(gate.TryBegin());
        gate.MarkClosed();
        Assert.False(gate.Finish(true));
        Assert.False(gate.TryBegin());
    }

    /// <summary>
    /// A failed save keeps the dialog open so the problem stays visible.
    /// </summary>
    [Fact]
    public void FailedSaveKeepsDialogOpen()
    {
        var gate = new DialogSaveGate();
        Assert.True(gate.TryBegin());
        Assert.False(gate.Finish(false));
        Assert.False(gate.Closed);
    }

    /// <summary>
    /// Bindings that disable dismissing the dialog are notified when a save starts and ends.
    /// </summary>
    [Fact]
    public void NotifiesIdleChanges()
    {
        var gate = new DialogSaveGate();
        var changed = new List<string?>();
        gate.PropertyChanged += (_, e) => changed.Add(e.PropertyName);
        gate.TryBegin();
        gate.Finish(true);
        Assert.Equal([nameof(DialogSaveGate.Saving), nameof(DialogSaveGate.Idle), nameof(DialogSaveGate.Saving), nameof(DialogSaveGate.Idle)], changed);
    }
}
