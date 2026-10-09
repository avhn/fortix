using Fortix.Core.Protocol;

namespace Fortix.App.Model;

/// <summary>
/// The status ring drawn in the notification area, shared design with the macOS menu bar icon.
/// </summary>
/// <remarks>
/// The glyph is monochrome: shape alone carries the status, never color. On a 22-unit grid a
/// ring of radius 7 to 9 means not connected, a filled center means connected, a half center
/// means partially connected, a broken ring with a dot means attention, and a ring with a
/// bright quarter that steps clockwise in 12 frames per second means connecting.
/// </remarks>
public static class RingGlyph
{
    /// <summary>The number of connecting animation frames per rotation.</summary>
    public const int Frames = 12;

    /// <summary>The time each connecting frame is shown, one rotation per second.</summary>
    public static readonly TimeSpan FrameInterval = TimeSpan.FromSeconds(1.0 / Frames);

    /// <summary>
    /// Returns how much of one sample point the glyph covers, from 0 to 1.
    /// </summary>
    /// <param name="x">The horizontal grid position, -11 to 11.</param>
    /// <param name="y">The vertical grid position, -11 to 11, growing downward.</param>
    /// <param name="status">The status to draw.</param>
    /// <param name="frame">The connecting frame, 0 to 11.</param>
    /// <returns>The coverage.</returns>
    public static double Coverage(double x, double y, AggregateStatus status, int frame)
    {
        var radius = Math.Sqrt((x * x) + (y * y));
        var ring = radius is >= 7 and <= 9;
        var angle = Math.Atan2(y, x) + (Math.PI / 2);
        if (angle < 0)
        {
            angle += 2 * Math.PI;
        }
        switch (status)
        {
            case AggregateStatus.Connecting:
                if (!ring)
                {
                    return 0;
                }
                var position = (angle - (frame * 2 * Math.PI / Frames) + (2 * Math.PI)) % (2 * Math.PI);
                return position < Math.PI / 2 ? 1 : 0.35;
            case AggregateStatus.Connected:
                return ring || radius <= 5 ? 1 : 0;
            case AggregateStatus.Partial:
                return ring || (radius <= 5 && x <= 0) ? 1 : 0;
            case AggregateStatus.Attention:
                return Math.Sqrt(((x - 8) * (x - 8)) + (y * y)) <= 1.6 || (ring && (x < 0 || Math.Abs(y) > 3.5)) ? 1 : 0;
            default:
                return ring ? 1 : 0;
        }
    }

    /// <summary>
    /// Renders a square, premultiplied 32-bit BGRA bitmap, top row first.
    /// </summary>
    /// <remarks>
    /// Each pixel averages 4 by 4 samples. A light taskbar gets a black glyph and a dark
    /// taskbar a white one, matching the system's own notification-area icons.
    /// </remarks>
    /// <param name="status">The status to draw.</param>
    /// <param name="frame">The connecting frame.</param>
    /// <param name="size">The edge length in pixels, at least 1.</param>
    /// <param name="lightTaskbar">Whether the taskbar is light.</param>
    /// <returns>size * size pixels as 0xAARRGGBB values.</returns>
    public static uint[] Render(AggregateStatus status, int frame, int size, bool lightTaskbar)
    {
        ArgumentOutOfRangeException.ThrowIfLessThan(size, 1);
        var pixels = new uint[size * size];
        var scale = 22.0 / size;
        for (var py = 0; py < size; py++)
        {
            for (var px = 0; px < size; px++)
            {
                var alpha = 0.0;
                for (var sy = 0; sy < 4; sy++)
                {
                    for (var sx = 0; sx < 4; sx++)
                    {
                        alpha += Coverage(((px + ((sx + 0.5) / 4)) * scale) - 11, ((py + ((sy + 0.5) / 4)) * scale) - 11, status, frame);
                    }
                }
                var a = (uint)Math.Round(alpha * 255 / 16);
                // Premultiplied: white at alpha a is (a, a, a); black is always zero color.
                var c = lightTaskbar ? 0u : a;
                pixels[(py * size) + px] = (a << 24) | (c << 16) | (c << 8) | c;
            }
        }
        return pixels;
    }

    /// <summary>
    /// Names the status for the tooltip and screen readers, independent of the glyph.
    /// </summary>
    /// <param name="status">The aggregate status.</param>
    /// <param name="reachable">Whether the helper is connected.</param>
    /// <returns>The status text.</returns>
    public static string StatusText(AggregateStatus status, bool reachable) => !reachable ? "Helper unavailable" : status switch
    {
        AggregateStatus.Connecting => "Connecting",
        AggregateStatus.Connected => "Connected",
        AggregateStatus.Partial => "Partially connected",
        AggregateStatus.Attention => "Needs attention",
        _ => "Not connected",
    };
}
