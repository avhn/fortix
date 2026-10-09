using Fortix.App.Model;
using Fortix.App.ViewModels;
using Fortix.Core.Protocol;

namespace Fortix.App.Tests;

/// <summary>
/// Covers the notification area glyph and its text.
/// </summary>
public sealed class TrayAndGlyphTests
{
    /// <summary>
    /// The glyph is black on a light taskbar and white on a dark one, with premultiplied pixels.
    /// </summary>
    [Fact]
    public void GlyphFollowsTaskbarTheme()
    {
        var dark = RingGlyph.Render(AggregateStatus.Connected, 0, 16, lightTaskbar: false);
        var light = RingGlyph.Render(AggregateStatus.Connected, 0, 16, lightTaskbar: true);
        Assert.Equal(256, dark.Length);
        Assert.Contains(dark, p => p >> 24 == 0xff);
        Assert.Contains(dark, p => p >> 24 == 0);
        Assert.All(light, p => Assert.Equal(0u, p & 0xffffff));
        Assert.All(dark, p => Assert.Equal(p >> 24, p & 0xff));
        Assert.Equal(dark.Select(p => p >> 24), light.Select(p => p >> 24));
    }

    /// <summary>
    /// Each status draws a distinct glyph, and connecting frames rotate.
    /// </summary>
    [Fact]
    public void StatusesAndFramesDiffer()
    {
        var shapes = Enum.GetValues<AggregateStatus>().Select(s => string.Join(',', RingGlyph.Render(s, 0, 20, false))).ToList();
        Assert.Equal(shapes.Count, shapes.Distinct().Count());
        Assert.NotEqual(RingGlyph.Render(AggregateStatus.Connecting, 0, 20, false), RingGlyph.Render(AggregateStatus.Connecting, 3, 20, false));
        Assert.Equal(RingGlyph.Render(AggregateStatus.Connecting, 0, 20, false), RingGlyph.Render(AggregateStatus.Connecting, RingGlyph.Frames, 20, false));
        Assert.Throws<ArgumentOutOfRangeException>(() => RingGlyph.Render(AggregateStatus.Connected, 0, 0, false));
    }

    /// <summary>
    /// The status text never depends on the glyph, and an unreachable helper says so.
    /// </summary>
    [Fact]
    public void StatusText()
    {
        Assert.Equal("Helper unavailable", RingGlyph.StatusText(AggregateStatus.Connected, reachable: false));
        Assert.Equal("Partially connected", RingGlyph.StatusText(AggregateStatus.Partial, reachable: true));
        Assert.Equal("Not connected", RingGlyph.StatusText(AggregateStatus.NotConnected, reachable: true));
    }

    /// <summary>
    /// Long menu text is wrapped into indented lines that fit the menu.
    /// </summary>
    [Fact]
    public void MenuWrapsLongText()
    {
        var lines = TrayMenu.Wrap("word " + new string('x', 70) + " tail", 56);
        Assert.True(lines.Count >= 2);
        Assert.Equal("word " + new string('x', 70) + " tail", string.Join(' ', lines));
    }
}
