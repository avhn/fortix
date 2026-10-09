using System.ComponentModel;
using System.Reflection;
using System.Windows;
using Fortix.App.Model;
using Fortix.App.Native;
using Fortix.App.Tray;
using Fortix.App.ViewModels;
using Fortix.App.Views;

namespace Fortix.App;

/// <summary>
/// Starts one Fortix instance per sign-in session with its notification-area icon and windows.
/// </summary>
/// <remarks>
/// Closing the window keeps the app in the notification area; quitting the app leaves every
/// tunnel running because the helper service owns them. A second launch only asks the running
/// instance to open its window.
/// </remarks>
public partial class App : Application
{
    /// <summary>The per-session mutex that marks the running instance.</summary>
    private const string InstanceName = @"Local\Fortix.App.Instance";

    /// <summary>The per-session event a second launch signals to open the window.</summary>
    private const string ActivateName = @"Local\Fortix.App.Activate";

    /// <summary>Held for the lifetime of the first instance.</summary>
    private Mutex? instance;

    /// <summary>Signalled by later launches.</summary>
    private EventWaitHandle? activate;

    /// <summary>The thread-pool wait on <see cref="activate"/>.</summary>
    private RegisteredWaitHandle? activation;

    /// <summary>The coordinator.</summary>
    private AppViewModel? model;

    /// <summary>The first-run setup page model.</summary>
    private SetupViewModel? setup;

    /// <summary>The preferences.</summary>
    private SettingsViewModel? settings;

    /// <summary>The notification-area icon.</summary>
    private TrayController? tray;

    /// <summary>The management window, created on first use and hidden on close.</summary>
    private MainWindow? main;

    /// <summary>The open sign-in or certificate window, if any.</summary>
    private SignInWindow? signIn;

    /// <summary>Whether the app is shutting down.</summary>
    private bool quitting;

    /// <summary>
    /// Enforces a single instance, then starts the icon, the helper connection, and the window.
    /// </summary>
    /// <param name="e">The startup arguments; --background starts without opening the window.</param>
    protected override void OnStartup(StartupEventArgs e)
    {
        base.OnStartup(e);
        instance = new Mutex(initiallyOwned: true, InstanceName, out var first);
        if (!first)
        {
            SignalRunningInstance();
            Shutdown();
            return;
        }
        activate = new EventWaitHandle(false, EventResetMode.AutoReset, ActivateName);
        activation = ThreadPool.RegisterWaitForSingleObject(activate, (_, _) => Dispatcher.BeginInvoke(ShowMain), null, Timeout.Infinite, executeOnlyOnce: false);
        ApplyTheme();

        var version = typeof(App).Assembly.GetCustomAttribute<AssemblyInformationalVersionAttribute>()?.InformationalVersion.Split('+')[0] ?? "dev";
        model = new AppViewModel(HelperConnector.Create(version), new CredentialManagerStore());
        settings = new SettingsViewModel(new AppSettingsStore(AppSettingsStore.DefaultPath()), new RunKeyAutostart(Environment.ProcessPath ?? ""));
        var inspector = new NativeServiceInspector();
        var installDirectory = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles, Environment.SpecialFolderOption.DoNotVerify), "Fortix");
        setup = new SetupViewModel(inspector, new ElevatedInstaller(), new GroupMembership(), AppContext.BaseDirectory.TrimEnd('\\'), installDirectory, $@"{Environment.UserDomainName}\{Environment.UserName}");
        setup.Refresh();
        setup.Installed += async (_, _) =>
        {
            await model.StopAsync();
            model.Start();
        };
        model.PropertyChanged += OnModelChanged;
        tray = new TrayController(model, settings, ShowMain, Quit);
        tray.ThemeChanged += (_, _) => ApplyTheme();
        model.Start();
        if (!e.Args.Contains(AutostartCommand.BackgroundArgument, StringComparer.OrdinalIgnoreCase) || setup.NeedsSetup)
        {
            ShowMain();
        }
    }

    /// <summary>
    /// Releases the icon and the single-instance handles.
    /// </summary>
    /// <param name="e">The exit arguments.</param>
    protected override void OnExit(ExitEventArgs e)
    {
        tray?.Dispose();
        activation?.Unregister(null);
        activate?.Dispose();
        if (model is not null)
        {
            instance?.ReleaseMutex();
        }
        instance?.Dispose();
        base.OnExit(e);
    }

    /// <summary>
    /// Asks the first instance to open its window, waiting briefly in case it is still starting.
    /// </summary>
    private static void SignalRunningInstance()
    {
        for (var tries = 0; tries < 20; tries++)
        {
            if (EventWaitHandle.TryOpenExisting(ActivateName, out var running))
            {
                using (running)
                {
                    running.Set();
                }
                return;
            }
            Thread.Sleep(100);
        }
    }

    /// <summary>
    /// Follows the Windows app theme for every window.
    /// </summary>
    private void ApplyTheme()
    {
#pragma warning disable WPF0001 // The Fluent theme modes are the supported way to follow light and dark.
        ThemeMode = ThemeReader.Read().AppsLight ? ThemeMode.Light : ThemeMode.Dark;
#pragma warning restore WPF0001
    }

    /// <summary>
    /// Opens or focuses the management window.
    /// </summary>
    private void ShowMain()
    {
        if (quitting || model is null || setup is null || settings is null)
        {
            return;
        }
        if (main is null)
        {
            main = new MainWindow(model, setup, settings);
            main.Closing += (_, args) =>
            {
                // Closing only hides the window; Fortix keeps running in the notification area.
                if (!quitting)
                {
                    args.Cancel = true;
                    main.Hide();
                }
            };
        }
        setup.Refresh();
        main.Show();
        if (main.WindowState == WindowState.Minimized)
        {
            main.WindowState = WindowState.Normal;
        }
        main.Activate();
        ShowPrompt();
    }

    /// <summary>
    /// Opens the sign-in window for the current prompt, or closes it when nothing is pending.
    /// </summary>
    private void ShowPrompt()
    {
        var prompt = model?.CurrentPrompt;
        if (signIn is not null && (prompt is null || signIn.Prompt.Id != prompt.Id))
        {
            signIn.CloseQuietly();
            signIn = null;
        }
        if (prompt is null || signIn is not null || model is null)
        {
            return;
        }
        var window = new SignInWindow(model, prompt);
        if (main is { IsVisible: true })
        {
            window.Owner = main;
        }
        window.Closed += (_, _) =>
        {
            if (ReferenceEquals(signIn, window))
            {
                signIn = null;
            }
        };
        signIn = window;
        window.Show();
        window.Activate();
    }

    /// <summary>
    /// Opens prompts as they arrive and refreshes the setup page when reachability changes.
    /// </summary>
    /// <param name="sender">The coordinator.</param>
    /// <param name="e">The change.</param>
    private void OnModelChanged(object? sender, PropertyChangedEventArgs e)
    {
        if (e.PropertyName == nameof(AppViewModel.CurrentPrompt))
        {
            ShowPrompt();
        }
        else if (e.PropertyName == nameof(AppViewModel.Reachable))
        {
            setup?.Refresh();
        }
    }

    /// <summary>
    /// Quits the app; tunnels keep running because the helper owns them.
    /// </summary>
    private async void Quit()
    {
        if (quitting)
        {
            return;
        }
        quitting = true;
        signIn?.CloseQuietly();
        main?.Close();
        tray?.Dispose();
        tray = null;
        try
        {
            if (model is not null)
            {
                await model.StopAsync();
            }
        }
        finally
        {
            Shutdown();
        }
    }
}
