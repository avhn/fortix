using Fortix.App.Model;
using Fortix.Core.Client;

namespace Fortix.App.Native;

/// <summary>
/// Opens verified helper connections for the app.
/// </summary>
internal static class HelperConnector
{
    /// <summary>
    /// Returns a connector that opens the pipe, verifies the service, and performs hello off the UI thread.
    /// </summary>
    /// <param name="version">The app version sent with hello.</param>
    /// <returns>The connector.</returns>
    public static Func<CancellationToken, Task<HelperClient>> Create(string version) => cancellationToken => Task.Run(
        async () =>
        {
            var transport = await PipeTransport.OpenAsync(cancellationToken).ConfigureAwait(false);
            var options = new HelperClientOptions { ClientVersion = version, SubscribeLogs = true };
            return await HelperClient.ConnectAsync(transport, new PipeServerVerifier(new NativeServiceInspector()), options, cancellationToken).ConfigureAwait(false);
        },
        cancellationToken);
}
