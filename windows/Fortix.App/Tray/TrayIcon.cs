using System.Runtime.InteropServices;
using System.Windows.Interop;
using Fortix.App.Model;
using Fortix.App.ViewModels;
using Fortix.Core.Protocol;
using Windows.Win32;
using Windows.Win32.Foundation;
using Windows.Win32.Graphics.Gdi;
using Windows.Win32.UI.Shell;
using Windows.Win32.UI.WindowsAndMessaging;

namespace Fortix.App.Tray;

/// <summary>
/// The notification-area icon, its menu, and its balloons, through Shell_NotifyIconW.
/// </summary>
/// <remarks>
/// A hidden top-level window receives the icon's callbacks and the broadcasts a message-only
/// window would miss: TaskbarCreated, to add the icon again after Explorer restarts, and
/// WM_SETTINGCHANGE, to follow light and dark changes. Version 4 callbacks give keyboard
/// selection (Enter or Space on the focused icon) the same meaning as a click.
/// </remarks>
internal sealed unsafe class TrayIcon : IDisposable
{
    /// <summary>The application-defined callback message.</summary>
    private const uint CallbackMessage = PInvoke.WM_APP + 1;

    /// <summary>NIN_SELECT: the icon was clicked.</summary>
    private const uint NinSelect = 0x400;

    /// <summary>NIN_KEYSELECT: the icon was chosen with the keyboard.</summary>
    private const uint NinKeySelect = 0x401;

    /// <summary>NIN_BALLOONUSERCLICK: the balloon was clicked.</summary>
    private const uint NinBalloonUserClick = 0x405;

    /// <summary>SM_CXSMICON: the small icon width.</summary>
    private const int SmallIconMetric = 49;

    /// <summary>TPM_RETURNCMD | TPM_RIGHTBUTTON: return the chosen item instead of posting it.</summary>
    private const uint TrackFlags = 0x0100 | 0x0002;

    /// <summary>NIIF_RESPECT_QUIET_TIME: suppress balloons during quiet hours and full-screen apps.</summary>
    private const uint RespectQuietTime = 0x80;

    /// <summary>The hidden window that owns the icon.</summary>
    private readonly HwndSource window;

    /// <summary>The broadcast sent when Explorer recreates the taskbar.</summary>
    private readonly uint taskbarCreated;

    /// <summary>Rendered icons by status, frame, and taskbar theme, destroyed on disposal.</summary>
    private readonly Dictionary<(AggregateStatus, int, bool, int), HICON> icons = [];

    /// <summary>The current icon.</summary>
    private HICON icon;

    /// <summary>The current tooltip.</summary>
    private string tip = "Fortix";

    /// <summary>Whether the icon is in the notification area.</summary>
    private bool added;

    /// <summary>
    /// Creates the hidden window; the icon appears on the first <see cref="Show"/>.
    /// </summary>
    public TrayIcon()
    {
        taskbarCreated = PInvoke.RegisterWindowMessage("TaskbarCreated");
        var parameters = new HwndSourceParameters("Fortix notification area")
        {
            WindowStyle = 0,
            ExtendedWindowStyle = 0x80, // WS_EX_TOOLWINDOW keeps the hidden window off the taskbar.
            Width = 0,
            Height = 0,
        };
        window = new HwndSource(parameters);
        window.AddHook(Hook);
    }

    /// <summary>Raised when the icon is clicked, chosen with the keyboard, or its balloon is clicked.</summary>
    public event EventHandler? Activated;

    /// <summary>Raised when Windows switches between light and dark.</summary>
    public event EventHandler? ThemeChanged;

    /// <summary>Gets or sets the menu builder, called each time the menu opens.</summary>
    public Func<IReadOnlyList<TrayMenuItem>>? MenuBuilder { get; set; }

    /// <summary>
    /// Shows a status glyph and tooltip, rendering each distinct glyph once.
    /// </summary>
    /// <param name="status">The status.</param>
    /// <param name="frame">The connecting frame.</param>
    /// <param name="lightTaskbar">Whether the taskbar is light.</param>
    /// <param name="tooltip">The tooltip, which also names the status for screen readers.</param>
    public void Show(AggregateStatus status, int frame, bool lightTaskbar, string tooltip)
    {
        var size = Math.Max(16, PInvoke.GetSystemMetricsForDpi((SYSTEM_METRICS_INDEX)SmallIconMetric, PInvoke.GetDpiForWindow(Handle)));
        var key = (status, frame, lightTaskbar, size);
        if (!icons.TryGetValue(key, out var next))
        {
            next = CreateIcon(RingGlyph.Render(status, frame, size, lightTaskbar), size);
            icons[key] = next;
        }
        if (added && next == icon && tooltip == tip)
        {
            return;
        }
        icon = next;
        tip = tooltip;
        Notify(added ? NOTIFY_ICON_MESSAGE.NIM_MODIFY : NOTIFY_ICON_MESSAGE.NIM_ADD);
    }

    /// <summary>
    /// Shows a balloon with a plain failure reason.
    /// </summary>
    /// <param name="title">The title.</param>
    /// <param name="text">The body.</param>
    public void ShowBalloon(string title, string text)
    {
        if (!added)
        {
            return;
        }
        var data = Data(NOTIFY_ICON_DATA_FLAGS.NIF_INFO);
        data.szInfoTitle = Truncate(title, 63);
        data.szInfo = Truncate(text, 255);
        data.dwInfoFlags = (NOTIFY_ICON_INFOTIP_FLAGS)((uint)NOTIFY_ICON_INFOTIP_FLAGS.NIIF_ERROR | RespectQuietTime);
        PInvoke.Shell_NotifyIcon(NOTIFY_ICON_MESSAGE.NIM_MODIFY, in data);
    }

    /// <summary>Removes the icon and releases every rendered glyph.</summary>
    public void Dispose()
    {
        if (added)
        {
            var data = Data(0);
            PInvoke.Shell_NotifyIcon(NOTIFY_ICON_MESSAGE.NIM_DELETE, in data);
            added = false;
        }
        window.RemoveHook(Hook);
        window.Dispose();
        foreach (var value in icons.Values)
        {
            PInvoke.DestroyIcon(value);
        }
        icons.Clear();
    }

    /// <summary>Gets the hidden window handle.</summary>
    private HWND Handle => new(window.Handle);

    /// <summary>
    /// Copies text into a fixed-size field, leaving room for the terminator.
    /// </summary>
    /// <param name="text">The text.</param>
    /// <param name="max">The longest text that fits.</param>
    /// <returns>The text, shortened if needed.</returns>
    private static string Truncate(string text, int max) => text.Length <= max ? text : text[..(max - 1)] + "…";

    /// <summary>
    /// Creates a 32-bit icon with alpha from premultiplied pixels.
    /// </summary>
    /// <param name="pixels">size * size pixels, top row first.</param>
    /// <param name="size">The edge length.</param>
    /// <returns>The icon handle.</returns>
    private static HICON CreateIcon(uint[] pixels, int size)
    {
        var header = new BITMAPINFO();
        header.bmiHeader.biSize = (uint)sizeof(BITMAPINFOHEADER);
        header.bmiHeader.biWidth = size;
        header.bmiHeader.biHeight = -size;
        header.bmiHeader.biPlanes = 1;
        header.bmiHeader.biBitCount = 32;
        void* bits;
        var color = PInvoke.CreateDIBSection(default, &header, DIB_USAGE.DIB_RGB_COLORS, &bits, default, 0);
        var mask = PInvoke.CreateBitmap(size, size, 1, 1, null);
        try
        {
            pixels.AsSpan().CopyTo(new Span<uint>(bits, pixels.Length));
            var info = new ICONINFO { fIcon = true, hbmColor = color, hbmMask = mask };
            return PInvoke.CreateIconIndirect(&info);
        }
        finally
        {
            PInvoke.DeleteObject(color);
            PInvoke.DeleteObject(mask);
        }
    }

    /// <summary>
    /// Sends the icon state to the shell, adding the icon again if it was lost.
    /// </summary>
    /// <param name="message">NIM_ADD or NIM_MODIFY.</param>
    private void Notify(NOTIFY_ICON_MESSAGE message)
    {
        var data = Data(NOTIFY_ICON_DATA_FLAGS.NIF_MESSAGE | NOTIFY_ICON_DATA_FLAGS.NIF_ICON | NOTIFY_ICON_DATA_FLAGS.NIF_TIP | NOTIFY_ICON_DATA_FLAGS.NIF_SHOWTIP);
        if (!PInvoke.Shell_NotifyIcon(message, in data) && message == NOTIFY_ICON_MESSAGE.NIM_MODIFY)
        {
            added = false;
            PInvoke.Shell_NotifyIcon(NOTIFY_ICON_MESSAGE.NIM_ADD, in data);
            message = NOTIFY_ICON_MESSAGE.NIM_ADD;
        }
        if (message == NOTIFY_ICON_MESSAGE.NIM_ADD)
        {
            data.Anonymous.uVersion = PInvoke.NOTIFYICON_VERSION_4;
            PInvoke.Shell_NotifyIcon(NOTIFY_ICON_MESSAGE.NIM_SETVERSION, in data);
            added = true;
        }
    }

    /// <summary>
    /// Builds the shared icon data for one call.
    /// </summary>
    /// <param name="flags">The members the call uses.</param>
    /// <returns>The data.</returns>
    private NOTIFYICONDATAW Data(NOTIFY_ICON_DATA_FLAGS flags) => new()
    {
        cbSize = (uint)sizeof(NOTIFYICONDATAW),
        hWnd = Handle,
        uID = 1,
        uFlags = flags,
        uCallbackMessage = CallbackMessage,
        hIcon = icon,
        szTip = Truncate(tip, 127),
    };

    /// <summary>
    /// Handles icon callbacks, taskbar re-creation, and theme broadcasts.
    /// </summary>
    /// <param name="hwnd">The window.</param>
    /// <param name="msg">The message.</param>
    /// <param name="wParam">The first parameter.</param>
    /// <param name="lParam">The second parameter.</param>
    /// <param name="handled">Set when the message is consumed.</param>
    /// <returns>Zero.</returns>
    private nint Hook(nint hwnd, int msg, nint wParam, nint lParam, ref bool handled)
    {
        var message = (uint)msg;
        if (message == CallbackMessage)
        {
            switch ((uint)(lParam & 0xFFFF))
            {
                case PInvoke.WM_CONTEXTMENU:
                    // Version 4 passes the anchor point in wParam, for mouse and keyboard alike.
                    ShowMenu((short)(wParam & 0xFFFF), (short)((wParam >> 16) & 0xFFFF));
                    break;
                case NinSelect or NinKeySelect or NinBalloonUserClick:
                    Activated?.Invoke(this, EventArgs.Empty);
                    break;
            }
            handled = true;
        }
        else if (message == taskbarCreated)
        {
            added = false;
            Notify(NOTIFY_ICON_MESSAGE.NIM_ADD);
        }
        else if (message == PInvoke.WM_SETTINGCHANGE && lParam != 0 && ThemeDetector.IsThemeChange(Marshal.PtrToStringUni(lParam)))
        {
            ThemeChanged?.Invoke(this, EventArgs.Empty);
        }
        return 0;
    }

    /// <summary>
    /// Builds and shows the native menu, then runs the chosen entry.
    /// </summary>
    /// <param name="x">The anchor x in screen coordinates.</param>
    /// <param name="y">The anchor y in screen coordinates.</param>
    private void ShowMenu(int x, int y)
    {
        if (MenuBuilder is null)
        {
            return;
        }
        var actions = new List<Action>();
        var menu = Populate(MenuBuilder(), actions);
        try
        {
            // The owner must be foreground or the menu will not close when focus moves away.
            PInvoke.SetForegroundWindow(Handle);
            var chosen = PInvoke.TrackPopupMenuEx(menu, TrackFlags, x, y, Handle, null);
            PInvoke.PostMessage(Handle, PInvoke.WM_NULL, default, default);
            var index = (int)chosen.Value - 1;
            if (index >= 0 && index < actions.Count)
            {
                actions[index]();
            }
        }
        finally
        {
            PInvoke.DestroyMenu(menu);
        }
    }

    /// <summary>
    /// Creates a native menu for the entries, numbering actions from 1.
    /// </summary>
    /// <param name="items">The entries.</param>
    /// <param name="actions">Receives the actions in command order.</param>
    /// <returns>The menu; submenus are destroyed with it.</returns>
    private static HMENU Populate(IReadOnlyList<TrayMenuItem> items, List<Action> actions)
    {
        var menu = PInvoke.CreatePopupMenu();
        foreach (var item in items)
        {
            if (item.IsSeparator)
            {
                Append(menu, MENU_ITEM_FLAGS.MF_SEPARATOR, 0, null);
                continue;
            }
            // An ampersand would otherwise mark the next letter as an access key.
            var text = item.Text.Replace("&", "&&", StringComparison.Ordinal);
            var disabled = item.Enabled ? 0 : MENU_ITEM_FLAGS.MF_GRAYED;
            if (item.Children is { } children)
            {
                var submenu = Populate(children, actions);
                Append(menu, MENU_ITEM_FLAGS.MF_POPUP | disabled, (nuint)(nint)submenu.Value, text);
            }
            else if (item.Action is { } action && item.Enabled)
            {
                actions.Add(action);
                Append(menu, MENU_ITEM_FLAGS.MF_STRING, (nuint)actions.Count, text);
            }
            else
            {
                Append(menu, MENU_ITEM_FLAGS.MF_STRING | MENU_ITEM_FLAGS.MF_GRAYED, 0, text);
            }
        }
        return menu;
    }

    /// <summary>
    /// Appends one item to a native menu.
    /// </summary>
    /// <param name="menu">The menu.</param>
    /// <param name="flags">The item kind and state.</param>
    /// <param name="id">The command identifier or submenu handle.</param>
    /// <param name="text">The label, or null for a separator.</param>
    private static void Append(HMENU menu, MENU_ITEM_FLAGS flags, nuint id, string? text)
    {
        fixed (char* label = text)
        {
            PInvoke.AppendMenu(menu, flags, id, new PCWSTR(label));
        }
    }
}
