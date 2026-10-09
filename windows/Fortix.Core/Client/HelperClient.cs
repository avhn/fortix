using System.Diagnostics;
using System.Globalization;
using System.Security.Cryptography;
using System.Text.Json;
using System.Text.Json.Serialization.Metadata;
using System.Threading.Channels;
using Fortix.Core.Json;
using Fortix.Core.Profiles;
using Fortix.Core.Protocol;

namespace Fortix.Core.Client;

/// <summary>
/// Connection settings for <see cref="HelperClient"/>.
/// </summary>
public sealed class HelperClientOptions
{
    /// <summary>Gets the client version sent with hello.</summary>
    public string ClientVersion { get; init; } = "dev";

    /// <summary>Gets whether subscriptions also request live log events.</summary>
    public bool SubscribeLogs { get; init; }

    /// <summary>Gets whether log events are dropped, for consumers that only track progress.</summary>
    public bool DiscardLogs { get; init; }

    /// <summary>Gets the bound on verification plus hello.</summary>
    public TimeSpan HandshakeTimeout { get; init; } = TimeSpan.FromSeconds(10);

    /// <summary>Gets the bound on writing one record.</summary>
    public TimeSpan WriteTimeout { get; init; } = TimeSpan.FromSeconds(10);

    /// <summary>
    /// Gets the bound on assembling one partially received record, measured from its first byte
    /// regardless of how many chunks follow; idle waits are unbounded.
    /// </summary>
    public TimeSpan AssemblyTimeout { get; init; } = TimeSpan.FromSeconds(10);

    /// <summary>Gets how many undelivered events may queue before the connection fails.</summary>
    public int EventCapacity { get; init; } = 256;
}

/// <summary>
/// One verified, correlated connection to the helper with a bounded, ordered event stream.
/// </summary>
/// <remarks>
/// Requests get sequential identifiers and complete when the matching result arrives; results
/// for cancelled calls are ignored. Consumers must drain <see cref="Events"/>: an overflow
/// fails the connection instead of silently losing a challenge or state change. Any malformed
/// record, oversized record, or transport error is terminal for the connection.
/// </remarks>
public sealed class HelperClient : IAsyncDisposable
{
    /// <summary>The transport, used only after verification succeeded.</summary>
    private readonly IHelperTransport transport;

    /// <summary>The connection settings.</summary>
    private readonly HelperClientOptions options;

    /// <summary>Serializes record writes so concurrent calls never interleave bytes.</summary>
    private readonly SemaphoreSlim writeLock = new(1, 1);

    /// <summary>Guards the pending map and the terminal error.</summary>
    private readonly Lock gate = new();

    /// <summary>Waiting calls by correlation identifier.</summary>
    private readonly Dictionary<string, TaskCompletionSource<HelperResult>> pending = new(StringComparer.Ordinal);

    /// <summary>The bounded event queue.</summary>
    private readonly Channel<HelperEvent> events;

    /// <summary>Cancelled when the connection fails or closes, waking writers and the reader.</summary>
    private readonly CancellationTokenSource closed = new();

    /// <summary>Completes with the terminal error once the connection ends.</summary>
    private readonly TaskCompletionSource<Exception> terminated = new(TaskCreationOptions.RunContinuationsAsynchronously);

    /// <summary>The last assigned correlation identifier.</summary>
    private ulong next;

    /// <summary>The first terminal error, or null while the connection is open.</summary>
    private Exception? error;

    /// <summary>The background reader.</summary>
    private Task reader = Task.CompletedTask;

    /// <summary>
    /// The single transport cleanup started by the first failure; disposal awaits it so the
    /// client never reports closed while the transport still holds resources.
    /// </summary>
    private Task transportDisposal = Task.CompletedTask;

    /// <summary>Completes once <see cref="transportDisposal"/> has been assigned by the first failure.</summary>
    private readonly TaskCompletionSource transportDisposalStarted = new(TaskCreationOptions.RunContinuationsAsynchronously);

    /// <summary>
    /// Creates a client around a verified transport; only <see cref="ConnectAsync"/> calls this.
    /// </summary>
    /// <param name="transport">The verified transport.</param>
    /// <param name="options">The connection settings.</param>
    private HelperClient(IHelperTransport transport, HelperClientOptions options)
    {
        this.transport = transport;
        this.options = options;
        events = Channel.CreateBounded<HelperEvent>(new BoundedChannelOptions(Math.Max(1, options.EventCapacity))
        {
            FullMode = BoundedChannelFullMode.Wait,
        });
    }

    /// <summary>Gets the ordered helper notifications; the reader completes when the connection ends.</summary>
    public ChannelReader<HelperEvent> Events => events.Reader;

    /// <summary>Gets the terminal error, or null while the connection is open.</summary>
    public Exception? Error
    {
        get
        {
            lock (gate)
            {
                return error;
            }
        }
    }

    /// <summary>Gets the helper version reported during hello.</summary>
    public string HelperVersion { get; private set; } = "";

    /// <summary>
    /// Verifies the peer, then starts the connection and performs hello.
    /// </summary>
    /// <remarks>
    /// Nothing is read or written until <paramref name="verifier"/> completes successfully. On
    /// any failure the transport is disposed. The returned client outlives
    /// <paramref name="cancellationToken"/>, which bounds only the handshake.
    /// </remarks>
    /// <param name="transport">A connected, unused transport; ownership passes to the client.</param>
    /// <param name="verifier">Proves the peer is the installed helper.</param>
    /// <param name="options">Optional settings.</param>
    /// <param name="cancellationToken">Cancels the handshake.</param>
    /// <returns>The connected client.</returns>
    /// <exception cref="HelperVerificationException">The peer could not be verified.</exception>
    /// <exception cref="HelperProtocolException">The helper speaks an incompatible protocol.</exception>
    public static async Task<HelperClient> ConnectAsync(IHelperTransport transport, IServerVerifier verifier, HelperClientOptions? options = null, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(transport);
        ArgumentNullException.ThrowIfNull(verifier);
        options ??= new HelperClientOptions();
        using var handshake = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        handshake.CancelAfter(options.HandshakeTimeout);
        try
        {
            await verifier.VerifyAsync(transport, handshake.Token).ConfigureAwait(false);
        }
        catch (Exception e)
        {
            await transport.DisposeAsync().ConfigureAwait(false);
            if (e is OperationCanceledException && handshake.IsCancellationRequested)
            {
                cancellationToken.ThrowIfCancellationRequested();
                throw new TimeoutException("the Fortix helper service did not respond in time");
            }
            throw new HelperVerificationException(e);
        }
        if (handshake.IsCancellationRequested)
        {
            await transport.DisposeAsync().ConfigureAwait(false);
            cancellationToken.ThrowIfCancellationRequested();
            throw new TimeoutException("the Fortix helper service did not respond in time");
        }
        var client = new HelperClient(transport, options);
        client.reader = Task.Run(client.ReadLoopAsync, CancellationToken.None);
        try
        {
            var hello = await client.CallAsync(new HelperRequest { Op = "hello", Version = options.ClientVersion }, CoreJsonContext.Default.HelloResponse, handshake.Token).ConfigureAwait(false);
            if (hello.Protocol != HelperProtocol.Version)
            {
                throw new HelperProtocolException("helper protocol version is incompatible; update fortix and fortix-helper together");
            }
            client.HelperVersion = hello.HelperVersion;
            return client;
        }
        catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
        {
            await client.DisposeAsync().ConfigureAwait(false);
            throw new TimeoutException("the Fortix helper service did not respond in time");
        }
        catch
        {
            await client.DisposeAsync().ConfigureAwait(false);
            throw;
        }
    }

    /// <summary>
    /// Sends one request and returns its result payload, or null when the result has none.
    /// </summary>
    /// <remarks>
    /// The identifier is replaced with a unique sequential one. Cancellation stops waiting but
    /// cannot undo a request already sent; a late result is ignored.
    /// </remarks>
    /// <param name="request">The request.</param>
    /// <param name="cancellationToken">Cancels the write or the wait.</param>
    /// <returns>The result data.</returns>
    /// <exception cref="HelperOperationException">The helper rejected the operation.</exception>
    /// <exception cref="HelperProtocolException">The request is invalid or the connection broke.</exception>
    public async Task<JsonElement?> CallAsync(HelperRequest request, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(request);
        if (request.Op == "subscribe")
        {
            request = request with { Logs = (request.Logs || options.SubscribeLogs) && !options.DiscardLogs };
        }
        cancellationToken.ThrowIfCancellationRequested();
        var completion = new TaskCompletionSource<HelperResult>(TaskCreationOptions.RunContinuationsAsynchronously);
        string id;
        lock (gate)
        {
            if (error is not null)
            {
                throw error;
            }
            next++;
            id = next.ToString(CultureInfo.InvariantCulture);
            pending[id] = completion;
        }
        try
        {
            var record = FrameCodec.Encode(request with { Id = id });
            try
            {
                await WriteAsync(record, cancellationToken).ConfigureAwait(false);
            }
            finally
            {
                CryptographicOperations.ZeroMemory(record);
            }
            var result = await completion.Task.WaitAsync(cancellationToken).ConfigureAwait(false);
            if (!result.Ok)
            {
                throw new HelperOperationException(result.Error!.Code, result.Error.Message);
            }
            return result.Data;
        }
        finally
        {
            lock (gate)
            {
                pending.Remove(id);
            }
        }
    }

    /// <summary>Subscribes this connection to state, challenge, certificate, and optionally log events.</summary>
    /// <param name="logs">Whether to receive log events, subject to the connection options.</param>
    /// <param name="cancellationToken">Cancels the call.</param>
    /// <returns>A task that completes when the helper confirms.</returns>
    public Task SubscribeAsync(bool logs = false, CancellationToken cancellationToken = default) =>
        CallAsync(new HelperRequest { Op = "subscribe", Logs = logs }, cancellationToken);

    /// <summary>Lists stored profiles with their current phases.</summary>
    /// <param name="cancellationToken">Cancels the call.</param>
    /// <returns>The profile states.</returns>
    public Task<List<ProfileState>> ProfileListAsync(CancellationToken cancellationToken = default) =>
        CallAsync(new HelperRequest { Op = "profile.list" }, CoreJsonContext.Default.ListProfileState, cancellationToken);

    /// <summary>Reads one stored profile.</summary>
    /// <param name="profile">The profile identifier.</param>
    /// <param name="cancellationToken">Cancels the call.</param>
    /// <returns>The stored profile.</returns>
    public Task<Profile> ProfileGetAsync(string profile, CancellationToken cancellationToken = default) =>
        CallAsync(new HelperRequest { Op = "profile.get", Profile = profile }, CoreJsonContext.Default.Profile, cancellationToken);

    /// <summary>Stores a profile; the helper validates it again and keeps its own certificate pin.</summary>
    /// <param name="profile">The profile to store.</param>
    /// <param name="cancellationToken">Cancels the call.</param>
    /// <returns>A task that completes when the helper confirms.</returns>
    public Task ProfilePutAsync(Profile profile, CancellationToken cancellationToken = default)
    {
        using var document = JsonDocument.Parse(ProfileCodec.Encode(profile));
        return CallAsync(new HelperRequest { Op = "profile.put", ProfileJson = document.RootElement.Clone() }, cancellationToken);
    }

    /// <summary>Deletes an idle stored profile.</summary>
    /// <param name="profile">The profile identifier.</param>
    /// <param name="cancellationToken">Cancels the call.</param>
    /// <returns>A task that completes when the helper confirms.</returns>
    public Task ProfileDeleteAsync(string profile, CancellationToken cancellationToken = default) =>
        CallAsync(new HelperRequest { Op = "profile.delete", Profile = profile }, cancellationToken);

    /// <summary>Starts a profile and returns the attempt that state events will carry.</summary>
    /// <param name="profile">The profile identifier.</param>
    /// <param name="cancellationToken">Cancels the call.</param>
    /// <returns>The attempt number.</returns>
    public async Task<ulong> UpAsync(string profile, CancellationToken cancellationToken = default) =>
        (await CallAsync(new HelperRequest { Op = "up", Profile = profile }, CoreJsonContext.Default.UpResponse, cancellationToken).ConfigureAwait(false)).Attempt;

    /// <summary>Stops one profile.</summary>
    /// <param name="profile">The profile identifier.</param>
    /// <param name="cancellationToken">Cancels the call.</param>
    /// <returns>A task that completes when the helper accepts the stop.</returns>
    public Task DownAsync(string profile, CancellationToken cancellationToken = default) =>
        CallAsync(new HelperRequest { Op = "down", Profile = profile }, cancellationToken);

    /// <summary>Stops every profile.</summary>
    /// <param name="cancellationToken">Cancels the call.</param>
    /// <returns>A task that completes when the helper accepts the stop.</returns>
    public Task DownAllAsync(CancellationToken cancellationToken = default) =>
        CallAsync(new HelperRequest { Op = "down", All = true }, cancellationToken);

    /// <summary>Returns complete snapshots for every profile, rejecting duplicate entries.</summary>
    /// <param name="cancellationToken">Cancels the call.</param>
    /// <returns>The snapshots.</returns>
    public async Task<List<SessionStatus>> StatusAsync(CancellationToken cancellationToken = default)
    {
        var snapshots = await CallAsync(new HelperRequest { Op = "status" }, CoreJsonContext.Default.ListSessionStatus, cancellationToken).ConfigureAwait(false);
        if (snapshots.Select(s => s.Profile).Distinct(StringComparer.Ordinal).Count() != snapshots.Count)
        {
            throw new HelperProtocolException("helper returned invalid result data");
        }
        return snapshots;
    }

    /// <summary>Answers a pending credential challenge.</summary>
    /// <param name="challengeId">The challenge from the challenge event.</param>
    /// <param name="secret">The answer; it is never logged.</param>
    /// <param name="cancellationToken">Cancels the call.</param>
    /// <returns>A task that completes when the helper accepts the answer.</returns>
    public Task AnswerAsync(string challengeId, string secret, CancellationToken cancellationToken = default) =>
        CallAsync(new HelperRequest { Op = "answer", ChallengeId = challengeId, Secret = secret }, cancellationToken);

    /// <summary>Cancels a pending credential challenge.</summary>
    /// <param name="challengeId">The challenge from the challenge event.</param>
    /// <param name="cancellationToken">Cancels the call.</param>
    /// <returns>A task that completes when the helper confirms.</returns>
    public Task CancelChallengeAsync(string challengeId, CancellationToken cancellationToken = default) =>
        CallAsync(new HelperRequest { Op = "cancel", ChallengeId = challengeId }, cancellationToken);

    /// <summary>Trusts the certificate a cert event reported for a profile.</summary>
    /// <param name="profile">The profile identifier.</param>
    /// <param name="digest">The 64-character SHA-256 digest from the event.</param>
    /// <param name="cancellationToken">Cancels the call.</param>
    /// <returns>A task that completes when the helper confirms.</returns>
    public Task TrustAsync(string profile, string digest, CancellationToken cancellationToken = default) =>
        CallAsync(new HelperRequest { Op = "trust", Profile = profile, Digest = digest }, cancellationToken);

    /// <summary>Returns the newest redacted log lines of a profile.</summary>
    /// <param name="profile">The profile identifier.</param>
    /// <param name="lines">Up to 500 lines; zero means the helper default.</param>
    /// <param name="cancellationToken">Cancels the call.</param>
    /// <returns>The log lines, oldest first.</returns>
    public Task<List<string>> LogsAsync(string profile, int lines = 0, CancellationToken cancellationToken = default) =>
        CallAsync(new HelperRequest { Op = "logs", Profile = profile, Lines = lines }, CoreJsonContext.Default.ListString, cancellationToken);

    /// <summary>
    /// Closes the transport, fails pending calls, and waits for the reader and the transport
    /// cleanup; repeated and concurrent calls are safe and all wait for the same cleanup.
    /// </summary>
    /// <returns>A task that completes when the reader has stopped and the transport is disposed.</returns>
    public async ValueTask DisposeAsync()
    {
        Fail(new HelperDisconnectedException("helper connection closed"), clean: true);
        await reader.ConfigureAwait(false);
        // The first failure may be running on another thread; wait until it published its cleanup.
        await transportDisposalStarted.Task.ConfigureAwait(false);
        await transportDisposal.ConfigureAwait(false);
    }

    /// <summary>
    /// Sends a request and decodes its payload into <typeparamref name="T"/>.
    /// </summary>
    /// <typeparam name="T">The payload type.</typeparam>
    /// <param name="request">The request.</param>
    /// <param name="type">The source-generated payload metadata.</param>
    /// <param name="cancellationToken">Cancels the call.</param>
    /// <returns>The decoded payload.</returns>
    private async Task<T> CallAsync<T>(HelperRequest request, JsonTypeInfo<T> type, CancellationToken cancellationToken)
    {
        var data = await CallAsync(request, cancellationToken).ConfigureAwait(false);
        try
        {
            if (data is { } element && element.Deserialize(type) is { } value)
            {
                return value;
            }
        }
        catch (Exception e) when (e is JsonException or InvalidOperationException)
        {
            // Payload text is never included in the error.
        }
        throw new HelperProtocolException("helper returned invalid result data");
    }

    /// <summary>
    /// Writes one record under the write lock and a bounded deadline.
    /// </summary>
    /// <remarks>
    /// A helper may reject an unauthorized peer and close before reading the request. After a
    /// failed write the reader gets a moment to deliver that rejection, so the caller sees the
    /// permission error rather than a bare transport failure. Caller cancellation ends that wait
    /// early and wins over the write failure.
    /// </remarks>
    /// <param name="record">The complete record.</param>
    /// <param name="cancellationToken">Cancels the write.</param>
    /// <returns>A task that completes when the record is written.</returns>
    private async Task WriteAsync(byte[] record, CancellationToken cancellationToken)
    {
        using var linked = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken, closed.Token);
        try
        {
            await writeLock.WaitAsync(linked.Token).ConfigureAwait(false);
        }
        catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
        {
            throw Error ?? new HelperDisconnectedException("helper connection closed");
        }
        try
        {
            linked.CancelAfter(options.WriteTimeout);
            await transport.WriteAsync(record, linked.Token).ConfigureAwait(false);
        }
        catch (Exception e)
        {
            if (cancellationToken.IsCancellationRequested)
            {
                // A partial record may be on the wire, so the connection cannot be reused.
                Fail(new OperationCanceledException(cancellationToken));
                throw new OperationCanceledException(cancellationToken);
            }
            // The grace wait also ends when the caller cancels, so cancellation stays prompt.
            await Task.WhenAny(terminated.Task, Task.Delay(TimeSpan.FromSeconds(1), cancellationToken)).ConfigureAwait(false);
            if (cancellationToken.IsCancellationRequested)
            {
                // The failed write may have left a partial record, so the connection is finished.
                Fail(new OperationCanceledException(cancellationToken));
                throw new OperationCanceledException(cancellationToken);
            }
            if (Error is HelperOperationException operation)
            {
                throw operation;
            }
            var failure = e is OperationCanceledException && !closed.IsCancellationRequested
                ? new TimeoutException("writing to the helper timed out")
                : Error ?? new HelperDisconnectedException("helper connection closed");
            Fail(failure);
            throw failure;
        }
        finally
        {
            writeLock.Release();
        }
    }

    /// <summary>
    /// Reads bounded records and routes results to callers and events to the queue until failure.
    /// </summary>
    /// <returns>A task that completes when the connection ends.</returns>
    private async Task ReadLoopAsync()
    {
        var buffer = new byte[HelperProtocol.MaxLine];
        int start = 0, end = 0;
        // Stopwatch timestamp by which the buffered partial record must complete; 0 means none.
        long deadline = 0;
        try
        {
            while (true)
            {
                var newline = buffer.AsSpan(start, end - start).IndexOf((byte)'\n');
                if (newline >= 0)
                {
                    var record = buffer.AsMemory(start, newline + 1);
                    start += newline + 1;
                    // The record completed, so any remaining bytes start a fresh deadline.
                    deadline = 0;
                    Dispatch(FrameCodec.Decode(record.Span));
                    record.Span.Clear();
                    continue;
                }
                if (end - start == HelperProtocol.MaxLine)
                {
                    throw new HelperProtocolException("protocol: incomplete or oversized record");
                }
                // Move a partial record to the front so a whole record always fits.
                buffer.AsSpan(start, end - start).CopyTo(buffer);
                buffer.AsSpan(end - start, start).Clear();
                end -= start;
                start = 0;
                if (end > 0 && deadline == 0)
                {
                    deadline = Stopwatch.GetTimestamp() + (long)(options.AssemblyTimeout.TotalSeconds * Stopwatch.Frequency);
                }
                var read = await ReadChunkAsync(buffer.AsMemory(end), end > 0 ? deadline : 0).ConfigureAwait(false);
                if (read == 0)
                {
                    throw end == 0
                        ? new HelperDisconnectedException("helper closed the connection")
                        : new HelperProtocolException("protocol: incomplete record");
                }
                end += read;
            }
        }
        catch (Exception e)
        {
            // After a close this is only the cancelled read, and the first error is kept.
            Fail(e);
        }
        finally
        {
            Array.Clear(buffer);
        }
    }

    /// <summary>
    /// Reads one chunk, bounding the wait only while a record is partially assembled.
    /// </summary>
    /// <remarks>
    /// The bound is the fixed deadline of the current record, not a fresh timeout per chunk, so a
    /// peer trickling bytes cannot keep an incomplete record buffered indefinitely.
    /// </remarks>
    /// <param name="destination">The free buffer space.</param>
    /// <param name="deadline">The Stopwatch timestamp by which the partial record must complete, or 0 when nothing is buffered.</param>
    /// <returns>The number of bytes read, or 0 at end of stream.</returns>
    private async Task<int> ReadChunkAsync(Memory<byte> destination, long deadline)
    {
        if (deadline == 0)
        {
            return await transport.ReadAsync(destination, closed.Token).ConfigureAwait(false);
        }
        var remaining = Stopwatch.GetElapsedTime(Stopwatch.GetTimestamp(), deadline);
        if (remaining <= TimeSpan.Zero)
        {
            throw new HelperProtocolException("protocol: record assembly timed out");
        }
        using var assembly = CancellationTokenSource.CreateLinkedTokenSource(closed.Token);
        assembly.CancelAfter(remaining);
        try
        {
            return await transport.ReadAsync(destination, assembly.Token).ConfigureAwait(false);
        }
        catch (OperationCanceledException) when (!closed.IsCancellationRequested)
        {
            throw new HelperProtocolException("protocol: record assembly timed out");
        }
    }

    /// <summary>
    /// Routes one decoded message.
    /// </summary>
    /// <param name="message">The decoded result or event.</param>
    private void Dispatch(HelperMessage message)
    {
        if (message.Result is { } result)
        {
            // Authorization failures end the connection, including rejections sent before any
            // request identifier was read; the waiting call receives the same error.
            if (!result.Ok && result.Error!.Code == HelperErrorCodes.Unauthorized)
            {
                throw new HelperOperationException(result.Error.Code, result.Error.Message);
            }
            TaskCompletionSource<HelperResult>? completion;
            lock (gate)
            {
                pending.Remove(result.Id, out completion);
            }
            completion?.TrySetResult(result);
            return;
        }
        var notification = message.Event!;
        if (notification.Type == "log" && options.DiscardLogs)
        {
            return;
        }
        if (!events.Writer.TryWrite(notification))
        {
            throw new HelperProtocolException("helper event queue overflow; reconnect and retry");
        }
    }

    /// <summary>
    /// Records the first terminal error, closes the transport, and wakes every waiter exactly once.
    /// </summary>
    /// <param name="failure">The terminal error.</param>
    /// <param name="clean">True for an explicit close, which completes the event stream without an error.</param>
    private void Fail(Exception failure, bool clean = false)
    {
        List<TaskCompletionSource<HelperResult>> waiting;
        lock (gate)
        {
            if (error is not null)
            {
                return;
            }
            error = failure;
            waiting = [.. pending.Values];
            pending.Clear();
        }
        closed.Cancel();
        terminated.TrySetResult(failure);
        foreach (var completion in waiting)
        {
            completion.TrySetException(failure);
        }
        events.Writer.TryComplete(clean ? null : failure);
        // Started without awaiting so a failing reader never waits on itself; disposal awaits it.
        transportDisposal = DisposeTransportAsync();
        transportDisposalStarted.TrySetResult();
    }

    /// <summary>
    /// Disposes the transport once, tracked by <see cref="transportDisposal"/>.
    /// </summary>
    /// <returns>A task that completes when the transport is disposed.</returns>
    private async Task DisposeTransportAsync()
    {
        try
        {
            await transport.DisposeAsync().ConfigureAwait(false);
        }
        catch (Exception e) when (e is IOException or ObjectDisposedException or InvalidOperationException)
        {
            // The connection is already terminal; a close failure adds nothing actionable.
        }
    }
}
