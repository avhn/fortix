using System.ComponentModel;
using System.Globalization;
using System.Windows;
using System.Windows.Automation;
using Fortix.App.ViewModels;

namespace Fortix.App.Views;

/// <summary>
/// Asks for a password or code, or for an explicit certificate decision, for one live helper request.
/// </summary>
/// <remarks>
/// The window is bound to one prompt and never retargets: a newer request opens a new window.
/// The typed secret lives only in the password box and is cleared on submit and on close.
/// Closing the window without answering cancels the request and stops that attempt, so no
/// credential request is ever left running unseen. The window stays open until that
/// cancellation succeeds, whether it was asked for with the button, Escape, or the title bar.
/// </remarks>
public partial class SignInWindow : Window
{
    /// <summary>The coordinator.</summary>
    private readonly AppViewModel model;

    /// <summary>Whether the window is closing because the prompt was answered or replaced.</summary>
    private bool settled;

    /// <summary>Whether a cancellation started by this window is in flight.</summary>
    private bool dismissing;

    /// <summary>
    /// Creates the window for one prompt.
    /// </summary>
    /// <param name="model">The coordinator.</param>
    /// <param name="prompt">The prompt.</param>
    public SignInWindow(AppViewModel model, PendingPrompt prompt)
    {
        this.model = model;
        Prompt = prompt;
        InitializeComponent();
        var e = prompt.Event;
        var name = model.Profiles.FirstOrDefault(p => p.Id == e.Profile)?.Name ?? e.Profile;
        Subject.Text = $"Profile: {name} ({e.Profile}), attempt {e.Attempt.ToString(CultureInfo.InvariantCulture)}";
        if (prompt.IsCertificate)
        {
            Title = Heading.Text = "Verify certificate";
            CredentialPanel.Visibility = Visibility.Collapsed;
            CertSubject.Text = "Subject: " + e.Subject;
            CertIssuer.Text = "Issuer: " + e.Issuer;
            Digest.Text = e.Digest;
            Confirm.Content = "_Trust and reconnect";
        }
        else
        {
            Title = Heading.Text = prompt.IsPassword ? "Sign in" : "Second-factor code";
            CertificatePanel.Visibility = Visibility.Collapsed;
            SecretLabel.Content = (e.Prompt.Length > 0 ? e.Prompt : prompt.IsPassword ? "Password" : "Code").Replace("_", "__", StringComparison.Ordinal);
            Secret.SetValue(AutomationProperties.NameProperty, prompt.IsPassword ? "Password" : "Second-factor code");
            Remember.Visibility = prompt.IsPassword ? Visibility.Visible : Visibility.Collapsed;
            Confirm.Content = "_Continue";
        }
        Problem.Visibility = Visibility.Collapsed;
        UpdateConfirm();
        model.PropertyChanged += OnModelChanged;
        Loaded += (_, _) => (prompt.IsCertificate ? (UIElement)Verified : Secret).Focus();
    }

    /// <summary>Gets the prompt this window answers.</summary>
    public PendingPrompt Prompt { get; }

    /// <summary>
    /// Closes the window without cancelling the request, for a prompt that was answered or replaced.
    /// </summary>
    public void CloseQuietly()
    {
        settled = true;
        Close();
    }

    /// <summary>
    /// Keeps an unanswered request's window open until it is cancelled, then clears the secret.
    /// </summary>
    /// <param name="e">The closing arguments.</param>
    protected override void OnClosing(CancelEventArgs e)
    {
        base.OnClosing(e);
        if (e.Cancel)
        {
            return;
        }
        if (!settled && model.IsCurrent(Prompt))
        {
            e.Cancel = true;
            Dismiss();
            return;
        }
        Secret.Clear();
        model.PropertyChanged -= OnModelChanged;
    }

    /// <summary>
    /// Cancels the request and closes the window only when the cancellation succeeded.
    /// </summary>
    /// <remarks>
    /// A refused or failed cancellation keeps the window open with the reason, so the request
    /// is never hidden while it still waits for an answer.
    /// </remarks>
    private async void Dismiss()
    {
        if (dismissing)
        {
            return;
        }
        dismissing = true;
        Secret.Clear();
        UpdateConfirm();
        bool closed;
        try
        {
            closed = await model.DismissPromptAsync(Prompt);
        }
        finally
        {
            dismissing = false;
        }
        if (closed)
        {
            CloseQuietly();
        }
        else
        {
            UpdateConfirm();
        }
    }

    /// <summary>
    /// Enables the confirm button only for a complete, current answer, and cancel only when it can run.
    /// </summary>
    private void UpdateConfirm()
    {
        Confirm.IsEnabled = !model.Busy && !dismissing && model.IsCurrent(Prompt) && (Prompt.IsCertificate ? Verified.IsChecked == true : Secret.SecurePassword.Length > 0);
        CancelButton.IsEnabled = !model.Busy && !dismissing;
        if (model.Message is { Length: > 0 } message)
        {
            Problem.Text = message;
            Problem.Visibility = Visibility.Visible;
        }
    }

    /// <summary>
    /// Re-evaluates availability as the helper state changes.
    /// </summary>
    /// <param name="sender">The coordinator.</param>
    /// <param name="e">The change.</param>
    private void OnModelChanged(object? sender, PropertyChangedEventArgs e) => UpdateConfirm();

    /// <summary>
    /// Re-evaluates availability as the secret is typed.
    /// </summary>
    /// <param name="sender">The password box.</param>
    /// <param name="e">The change.</param>
    private void SecretChanged(object sender, RoutedEventArgs e) => UpdateConfirm();

    /// <summary>
    /// Re-evaluates availability when the fingerprint check is ticked.
    /// </summary>
    /// <param name="sender">The check box.</param>
    /// <param name="e">The change.</param>
    private void VerifiedChanged(object sender, RoutedEventArgs e) => UpdateConfirm();

    /// <summary>
    /// Sends the answer or the trust decision; the window closes when the helper accepts it.
    /// </summary>
    /// <param name="sender">The button.</param>
    /// <param name="e">The click.</param>
    private async void ConfirmClick(object sender, RoutedEventArgs e)
    {
        bool ok;
        if (Prompt.IsCertificate)
        {
            ok = await model.PerformAsync(() => model.TrustAsync(Prompt));
        }
        else
        {
            var secret = Secret.Password;
            Secret.Clear();
            ok = await model.PerformAsync(() => model.AnswerAsync(Prompt, secret, Remember.IsChecked == true));
        }
        if (ok)
        {
            CloseQuietly();
        }
    }

    /// <summary>
    /// Cancels the request and stops the attempt; the window closes once that succeeded.
    /// </summary>
    /// <param name="sender">The button.</param>
    /// <param name="e">The click.</param>
    private void CancelClick(object sender, RoutedEventArgs e) => Dismiss();
}
