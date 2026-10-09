namespace Fortix.Core.Client;

/// <summary>
/// A duplex byte stream to the helper, independent of the underlying pipe or socket.
/// </summary>
/// <remarks>
/// Disposing the transport must wake any pending read or write. Implementations do not
/// interpret records; framing, limits, and correlation belong to <see cref="HelperClient"/>.
/// </remarks>
public interface IHelperTransport : IAsyncDisposable
{
    /// <summary>
    /// Reads at most <paramref name="buffer"/>.Length bytes, returning 0 only at end of stream.
    /// </summary>
    /// <param name="buffer">The destination.</param>
    /// <param name="cancellationToken">Cancels the wait.</param>
    /// <returns>The number of bytes read.</returns>
    ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken);

    /// <summary>
    /// Writes every byte of <paramref name="buffer"/> or fails.
    /// </summary>
    /// <param name="buffer">The complete record.</param>
    /// <param name="cancellationToken">Cancels the write.</param>
    /// <returns>A task that completes when the record is written.</returns>
    ValueTask WriteAsync(ReadOnlyMemory<byte> buffer, CancellationToken cancellationToken);
}

/// <summary>
/// Proves the transport's peer is the installed helper before any byte is exchanged.
/// </summary>
/// <remarks>
/// On Windows this checks that the pipe server process is the running helper service, owned
/// by LocalSystem and started from the installed image. The client neither reads nor writes
/// until verification returns, so a spoofed endpoint never sees even the hello record.
/// </remarks>
public interface IServerVerifier
{
    /// <summary>
    /// Completes when the peer is verified and throws when it is not.
    /// </summary>
    /// <param name="transport">The connected, unused transport.</param>
    /// <param name="cancellationToken">Bounds the verification.</param>
    /// <returns>A task that completes after successful verification.</returns>
    ValueTask VerifyAsync(IHelperTransport transport, CancellationToken cancellationToken);
}

/// <summary>
/// Thrown when the helper rejects an operation; the message never includes request data.
/// </summary>
public sealed class HelperOperationException : Exception
{
    /// <summary>
    /// The repair instruction for an unauthorized caller, matching the command-line client on Windows.
    /// </summary>
    public const string PermissionMessage = "permission denied: ask an administrator to add your account to the local fortix group (net localgroup fortix <user> /add), then sign out and back in";

    /// <summary>
    /// Creates an exception from the helper's code and public message.
    /// </summary>
    /// <param name="code">The stable failure code.</param>
    /// <param name="detail">The helper's redacted message.</param>
    public HelperOperationException(string code, string detail)
        : base(code == Protocol.HelperErrorCodes.Unauthorized ? PermissionMessage : $"helper: {code}: {detail}")
    {
        Code = code;
        Detail = detail;
    }

    /// <summary>Gets the stable failure code.</summary>
    public string Code { get; }

    /// <summary>Gets the helper's redacted message.</summary>
    public string Detail { get; }
}

/// <summary>
/// Thrown when the peer could not be verified as the installed helper; nothing was sent.
/// </summary>
public sealed class HelperVerificationException : Exception
{
    /// <summary>
    /// Creates the exception, keeping the verifier's failure as the inner exception for diagnostics.
    /// </summary>
    /// <param name="inner">The verifier failure.</param>
    public HelperVerificationException(Exception inner)
        : base("the Fortix helper service could not be verified", inner)
    {
    }
}

/// <summary>
/// Thrown for calls on a closed connection or when the helper ends the stream.
/// </summary>
public sealed class HelperDisconnectedException : Exception
{
    /// <summary>
    /// Creates the exception with a fixed message.
    /// </summary>
    /// <param name="message">The reason the connection is closed.</param>
    public HelperDisconnectedException(string message)
        : base(message)
    {
    }
}
