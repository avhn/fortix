using System.Text;
using System.Text.Json;
using Fortix.Core.Client;
using Fortix.Core.Protocol;

namespace Fortix.Core.Tests;

/// <summary>
/// Exercises verification ordering, framing limits, correlation, cancellation, and failure handling.
/// </summary>
public sealed class HelperClientTests
{
    /// <summary>A generous bound so a broken client fails a test instead of hanging it.</summary>
    private static readonly TimeSpan Bound = TimeSpan.FromSeconds(10);

    /// <summary>Gets the malformed record names.</summary>
    public static TheoryData<string> Malformed => Vectors.Names("protocol-frames.json", "malformed");

    /// <summary>
    /// A failing verifier means not one byte is written or read and the transport is disposed.
    /// </summary>
    [Fact]
    public async Task VerifierFailureWritesNothing()
    {
        var transport = new FakeTransport();
        var verifier = new Verifier(_ => throw new UnauthorizedAccessException("pipe owner mismatch"));
        var e = await Assert.ThrowsAsync<HelperVerificationException>(() => HelperClient.ConnectAsync(transport, verifier));
        Assert.Equal("the Fortix helper service could not be verified", e.Message);
        Assert.Equal((0, 0, true), (transport.BytesWritten, transport.ReadCalls, transport.Disposed));
    }

    /// <summary>
    /// Verification completes before the first byte is written; hello is the first record.
    /// </summary>
    [Fact]
    public async Task VerificationPrecedesFirstByte()
    {
        var transport = new FakeTransport();
        var observed = (-1, -1);
        var verifier = new Verifier(async t =>
        {
            await Task.Delay(50);
            observed = (transport.BytesWritten, transport.ReadCalls);
        });
        await using var client = await HelperClient.ConnectAsync(transport, verifier, new HelperClientOptions { ClientVersion = "0.3.0" });
        Assert.Equal((0, 0), observed);
        var hello = transport.Requests[0];
        Assert.Equal(("hello", "0.3.0"), (hello.GetProperty("op").GetString(), hello.GetProperty("version").GetString()));
        Assert.Equal("0.3.0", client.HelperVersion);
    }

    /// <summary>
    /// Cancelling during verification writes nothing and reports cancellation.
    /// </summary>
    [Fact]
    public async Task VerifierCancellationWritesNothing()
    {
        var transport = new FakeTransport();
        using var cancel = new CancellationTokenSource();
        var verifier = new Verifier(async t =>
        {
            await cancel.CancelAsync();
            t.ThrowIfCancellationRequested();
        });
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => HelperClient.ConnectAsync(transport, verifier, null, cancel.Token));
        Assert.Equal((0, true), (transport.BytesWritten, transport.Disposed));
    }

    /// <summary>
    /// A helper speaking another protocol version is refused and the connection closed.
    /// </summary>
    [Fact]
    public async Task IncompatibleProtocolRefused()
    {
        var transport = new FakeTransport
        {
            Responder = r => $"{{\"type\":\"result\",\"id\":\"{r.GetProperty("id").GetString()}\",\"ok\":true,\"data\":{{\"helper_version\":\"9\",\"protocol\":2}}}}\n",
        };
        var e = await Assert.ThrowsAsync<HelperProtocolException>(() => HelperClient.ConnectAsync(transport, Verifier.Accept));
        Assert.Equal("helper protocol version is incompatible; update fortix and fortix-helper together", e.Message);
        Assert.True(transport.Disposed);
    }

    /// <summary>
    /// An unauthorized rejection sent before any request id was read ends the connection with repair advice.
    /// </summary>
    [Fact]
    public async Task UnauthorizedBeforeRequest()
    {
        var transport = new FakeTransport { Responder = _ => "{\"type\":\"result\",\"id\":\"\",\"ok\":false,\"error\":{\"code\":\"UNAUTHORIZED\",\"message\":\"peer is not authorized\"}}\n" };
        var e = await Assert.ThrowsAsync<HelperOperationException>(() => HelperClient.ConnectAsync(transport, Verifier.Accept));
        Assert.Equal(HelperOperationException.PermissionMessage, e.Message);
        Assert.Equal(HelperErrorCodes.Unauthorized, e.Code);
    }

    /// <summary>
    /// Results correlate by id even when the helper answers out of order.
    /// </summary>
    [Fact]
    public async Task CorrelatesOutOfOrderResults()
    {
        var (client, transport) = await ConnectAsync();
        await using var _ = client;
        transport.Responder = _ => null;
        var logs = client.LogsAsync("work", 5);
        var list = client.ProfileListAsync();
        await WaitAsync(() => transport.Requests.Count == 3);
        var requests = transport.Requests;
        transport.Send(Result(requests[2], "[{\"profile\":\"work\",\"state\":\"connected\"}]"));
        transport.Send(Result(requests[1], "[\"one\",\"two\"]"));
        Assert.Equal("connected", (await list.WaitAsync(Bound))[0].State);
        Assert.Equal(["one", "two"], await logs.WaitAsync(Bound));
        Assert.Equal(["1", "2", "3"], requests.Select(r => r.GetProperty("id").GetString()));
    }

    /// <summary>
    /// A cancelled call stops waiting, its late result is ignored, and the connection stays usable.
    /// </summary>
    [Fact]
    public async Task CancelledCallIgnoresLateResult()
    {
        var (client, transport) = await ConnectAsync();
        await using var _ = client;
        transport.Responder = _ => null;
        using var cancel = new CancellationTokenSource();
        var status = client.StatusAsync(cancel.Token);
        await WaitAsync(() => transport.Requests.Count == 2);
        await cancel.CancelAsync();
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => status.WaitAsync(Bound));
        transport.Send(Result(transport.Requests[1], "[]"));
        transport.Responder = FakeTransport.DefaultResponder;
        await client.DownAsync("work").WaitAsync(Bound);
        Assert.Null(client.Error);
    }

    /// <summary>
    /// An already-cancelled token fails before anything is written.
    /// </summary>
    [Fact]
    public async Task PreCancelledCallWritesNothing()
    {
        var (client, transport) = await ConnectAsync();
        await using var _ = client;
        var before = transport.BytesWritten;
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => client.UpAsync("work", new CancellationToken(true)));
        Assert.Equal(before, transport.BytesWritten);
    }

    /// <summary>
    /// An invalid request is refused locally without writing a byte.
    /// </summary>
    [Fact]
    public async Task InvalidRequestWritesNothing()
    {
        var (client, transport) = await ConnectAsync();
        await using var _ = client;
        var before = transport.BytesWritten;
        await Assert.ThrowsAsync<HelperProtocolException>(() => client.TrustAsync("work", "short"));
        await Assert.ThrowsAsync<HelperProtocolException>(() => client.LogsAsync("work", 501));
        await Assert.ThrowsAsync<HelperProtocolException>(() => client.CallAsync(new HelperRequest { Op = "status", Profile = "work" }));
        Assert.Equal(before, transport.BytesWritten);
        Assert.Null(client.Error);
    }

    /// <summary>
    /// A helper failure surfaces its code and public message.
    /// </summary>
    [Fact]
    public async Task OperationErrorSurfaces()
    {
        var (client, transport) = await ConnectAsync();
        await using var _ = client;
        transport.Responder = r => $"{{\"type\":\"result\",\"id\":\"{r.GetProperty("id").GetString()}\",\"ok\":false,\"error\":{{\"code\":\"BUSY\",\"message\":\"profile is active\"}}}}\n";
        var e = await Assert.ThrowsAsync<HelperOperationException>(() => client.ProfileDeleteAsync("work"));
        Assert.Equal(("BUSY", "helper: BUSY: profile is active"), (e.Code, e.Message));
        Assert.Null(client.Error);
    }

    /// <summary>
    /// A record of exactly the limit is accepted; one without a newline at the limit is terminal.
    /// </summary>
    [Fact]
    public async Task FramingLimit()
    {
        var (client, transport) = await ConnectAsync();
        await using var _ = client;
        transport.Responder = r => Encoding.UTF8.GetString(PaddedResult(r.GetProperty("id").GetString()!, HelperProtocol.MaxLine));
        Assert.Single(await client.LogsAsync("work").WaitAsync(Bound));
        transport.Responder = _ => new string('x', HelperProtocol.MaxLine);
        var e = await Assert.ThrowsAsync<HelperProtocolException>(() => client.StatusAsync().WaitAsync(Bound));
        Assert.Equal("protocol: incomplete or oversized record", e.Message);
        await Assert.ThrowsAsync<HelperProtocolException>(() => client.Events.Completion.WaitAsync(Bound));
        Assert.True(transport.Disposed);
    }

    /// <summary>
    /// Records split across chunks and several records in one chunk arrive intact and in order.
    /// </summary>
    [Fact]
    public async Task ReassemblesChunks()
    {
        var (client, transport) = await ConnectAsync();
        await using var _ = client;
        var first = "{\"type\":\"log\",\"profile\":\"work\",\"attempt\":1,\"line\":\"東京 one\"}\n";
        var second = "{\"type\":\"log\",\"profile\":\"work\",\"attempt\":1,\"line\":\"two\"}\n";
        foreach (var b in Encoding.UTF8.GetBytes(first))
        {
            transport.Send([b]);
        }
        transport.Send(second + second);
        var lines = new List<string>();
        for (var i = 0; i < 3; i++)
        {
            lines.Add((await client.Events.ReadAsync().AsTask().WaitAsync(Bound)).Line);
        }
        Assert.Equal(["東京 one", "two", "two"], lines);
    }

    /// <summary>
    /// End of stream inside a record is an incomplete-record failure, not a clean close.
    /// </summary>
    [Fact]
    public async Task TruncatedRecordFails()
    {
        var (client, transport) = await ConnectAsync();
        await using var _ = client;
        transport.Send("{\"type\":\"log\"");
        transport.Close();
        var e = await Assert.ThrowsAsync<HelperProtocolException>(() => client.Events.Completion.WaitAsync(Bound));
        Assert.Equal("protocol: incomplete record", e.Message);
    }

    /// <summary>
    /// A partial record that stalls past the assembly bound fails the connection.
    /// </summary>
    [Fact]
    public async Task StalledRecordTimesOut()
    {
        var (client, transport) = await ConnectAsync(new HelperClientOptions { AssemblyTimeout = TimeSpan.FromMilliseconds(100) });
        await using var _ = client;
        transport.Send("{\"type\":");
        var e = await Assert.ThrowsAsync<HelperProtocolException>(() => client.Events.Completion.WaitAsync(Bound));
        Assert.Equal("protocol: record assembly timed out", e.Message);
    }

    /// <summary>
    /// A peer trickling bytes cannot extend the assembly bound: it runs from the first partial byte.
    /// </summary>
    [Fact]
    public async Task TricklingRecordTimesOutAtOriginalDeadline()
    {
        var (client, transport) = await ConnectAsync(new HelperClientOptions { AssemblyTimeout = TimeSpan.FromMilliseconds(100) });
        await using var _ = client;
        using var stop = new CancellationTokenSource();
        var started = System.Diagnostics.Stopwatch.StartNew();
        var trickle = Task.Run(async () =>
        {
            while (!stop.IsCancellationRequested)
            {
                transport.Send("x");
                await Task.Delay(60, CancellationToken.None);
            }
        }, CancellationToken.None);
        transport.Send("{\"type\":");
        var e = await Assert.ThrowsAsync<HelperProtocolException>(() => client.Events.Completion.WaitAsync(Bound));
        var elapsed = started.Elapsed;
        await stop.CancelAsync();
        await trickle;
        Assert.Equal("protocol: record assembly timed out", e.Message);
        // A per-chunk timer would never fire while chunks arrive every 60 ms.
        Assert.True(elapsed < TimeSpan.FromSeconds(2), $"timed out after {elapsed}");
    }

    /// <summary>
    /// Every malformed record from the vectors is terminal and wakes pending calls.
    /// </summary>
    /// <param name="name">The vector name.</param>
    [Theory]
    [MemberData(nameof(Malformed))]
    public async Task MalformedRecordIsTerminal(string name)
    {
        var (client, transport) = await ConnectAsync();
        await using var _ = client;
        var frame = Vectors.Entry("protocol-frames.json", name, "malformed").GetProperty("frame").GetString()!;
        transport.Responder = _ => frame;
        var e = await Assert.ThrowsAsync<HelperProtocolException>(() => client.StatusAsync().WaitAsync(Bound));
        Assert.Equal("protocol: invalid object", e.Message);
        await Assert.ThrowsAsync<HelperProtocolException>(() => client.DownAllAsync());
    }

    /// <summary>
    /// A consumer that stops draining events fails the connection instead of losing one.
    /// </summary>
    [Fact]
    public async Task EventOverflowIsTerminal()
    {
        var (client, transport) = await ConnectAsync(new HelperClientOptions { EventCapacity = 2 });
        await using var _ = client;
        for (var i = 1; i <= 3; i++)
        {
            transport.Send($"{{\"type\":\"log\",\"profile\":\"work\",\"attempt\":{i},\"line\":\"\"}}\n");
        }
        await WaitAsync(() => client.Error is not null);
        Assert.Equal("helper event queue overflow; reconnect and retry", client.Error!.Message);
    }

    /// <summary>
    /// Subscriptions honor the log options, and discarded log events never reach consumers.
    /// </summary>
    [Fact]
    public async Task LogOptions()
    {
        var (client, transport) = await ConnectAsync(new HelperClientOptions { SubscribeLogs = true });
        await using (client)
        {
            await client.SubscribeAsync();
            Assert.True(transport.Requests[^1].GetProperty("logs").GetBoolean());
        }
        (client, transport) = await ConnectAsync(new HelperClientOptions { SubscribeLogs = true, DiscardLogs = true });
        await using (client)
        {
            await client.SubscribeAsync(logs: true);
            Assert.False(transport.Requests[^1].TryGetProperty("logs", out _));
            transport.Send("{\"type\":\"log\",\"profile\":\"work\",\"attempt\":1,\"line\":\"x\"}\n");
            transport.Send("{\"type\":\"cert\",\"profile\":\"work\",\"attempt\":1,\"digest\":\"d\",\"subject\":\"s\",\"issuer\":\"i\"}\n");
            Assert.Equal("cert", (await client.Events.ReadAsync().AsTask().WaitAsync(Bound)).Type);
        }
    }

    /// <summary>
    /// Disposing fails pending calls, completes events cleanly, and closes the transport.
    /// </summary>
    [Fact]
    public async Task DisposeWakesPendingCalls()
    {
        var (client, transport) = await ConnectAsync();
        transport.Responder = _ => null;
        var status = client.StatusAsync();
        await WaitAsync(() => transport.Requests.Count == 2);
        await client.DisposeAsync();
        await Assert.ThrowsAsync<HelperDisconnectedException>(() => status.WaitAsync(Bound));
        await client.Events.Completion.WaitAsync(Bound);
        Assert.True(transport.Disposed);
        await Assert.ThrowsAsync<HelperDisconnectedException>(() => client.StatusAsync());
        await client.DisposeAsync();
    }

    /// <summary>
    /// Disposal waits for asynchronous transport cleanup, and so does every repeated or concurrent call.
    /// </summary>
    [Fact]
    public async Task DisposeAwaitsTransportCleanup()
    {
        var (client, transport) = await ConnectAsync();
        var cleanup = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        transport.DisposeGate = cleanup.Task;
        var first = client.DisposeAsync().AsTask();
        await WaitAsync(() => transport.Disposed);
        var second = client.DisposeAsync().AsTask();
        await Task.Delay(100);
        Assert.False(first.IsCompleted);
        Assert.False(second.IsCompleted);
        Assert.False(transport.DisposeCompleted);
        cleanup.SetResult();
        await Task.WhenAll(first, second).WaitAsync(Bound);
        Assert.True(transport.DisposeCompleted);
        await client.DisposeAsync().AsTask().WaitAsync(Bound);
    }

    /// <summary>
    /// A failed write reports the buffered authorization rejection rather than a bare transport error.
    /// </summary>
    [Fact]
    public async Task WriteFailurePrefersRejection()
    {
        var (client, transport) = await ConnectAsync();
        await using var _ = client;
        transport.Send("{\"type\":\"result\",\"id\":\"\",\"ok\":false,\"error\":{\"code\":\"UNAUTHORIZED\",\"message\":\"peer is not authorized\"}}\n");
        transport.WriteFailure = new IOException("pipe closed");
        var e = await Assert.ThrowsAsync<HelperOperationException>(() => client.StatusAsync().WaitAsync(Bound));
        Assert.Equal(HelperOperationException.PermissionMessage, e.Message);
    }

    /// <summary>
    /// Cancelling during the rejection grace wait after a failed write ends the call promptly
    /// with cancellation instead of a disconnect after the full wait.
    /// </summary>
    [Fact]
    public async Task CancellationDuringWriteFailureGraceIsPrompt()
    {
        var (client, transport) = await ConnectAsync();
        await using var _ = client;
        transport.WriteFailure = new IOException("pipe closed");
        using var cancel = new CancellationTokenSource();
        var status = client.StatusAsync(cancel.Token);
        await WaitAsync(() => transport.FailedWrites == 1);
        // The write has failed and the reader is idle, so the call sits in the grace wait.
        await Task.Delay(100);
        Assert.False(status.IsCompleted);
        cancel.Cancel();
        var e = await Assert.ThrowsAnyAsync<OperationCanceledException>(() => status.WaitAsync(TimeSpan.FromMilliseconds(500)));
        Assert.Equal(cancel.Token, e.CancellationToken);
        await Assert.ThrowsAnyAsync<Exception>(() => client.StatusAsync().WaitAsync(Bound));
    }

    /// <summary>
    /// The status reply must not list a profile twice.
    /// </summary>
    [Fact]
    public async Task DuplicateStatusRejected()
    {
        var (client, transport) = await ConnectAsync();
        await using var _ = client;
        transport.Responder = r => Result(r, "[{\"profile\":\"work\"},{\"profile\":\"work\"}]");
        var e = await Assert.ThrowsAsync<HelperProtocolException>(() => client.StatusAsync());
        Assert.Equal("helper returned invalid result data", e.Message);
    }

    /// <summary>
    /// Connects a client over a fresh fake transport with an accepting verifier.
    /// </summary>
    /// <param name="options">Optional settings.</param>
    /// <returns>The client and its transport.</returns>
    private static async Task<(HelperClient Client, FakeTransport Transport)> ConnectAsync(HelperClientOptions? options = null)
    {
        var transport = new FakeTransport();
        return (await HelperClient.ConnectAsync(transport, Verifier.Accept, options).WaitAsync(Bound), transport);
    }

    /// <summary>
    /// Builds a success record answering a request with the given data.
    /// </summary>
    /// <param name="request">The request being answered.</param>
    /// <param name="data">The JSON payload.</param>
    /// <returns>The record.</returns>
    private static string Result(JsonElement request, string data) =>
        $"{{\"type\":\"result\",\"id\":\"{request.GetProperty("id").GetString()}\",\"ok\":true,\"data\":{data}}}\n";

    /// <summary>
    /// Builds a logs result with one padded line so the record has the given total length.
    /// </summary>
    /// <param name="id">The result id.</param>
    /// <param name="length">The total record length including the newline.</param>
    /// <returns>The record bytes.</returns>
    private static byte[] PaddedResult(string id, int length)
    {
        var prefix = $"{{\"type\":\"result\",\"id\":\"{id}\",\"ok\":true,\"data\":[\"";
        const string Suffix = "\"]}\n";
        return Encoding.UTF8.GetBytes(prefix + new string('x', length - prefix.Length - Suffix.Length) + Suffix);
    }

    /// <summary>
    /// Polls a condition until it holds or the test bound expires.
    /// </summary>
    /// <param name="condition">The condition.</param>
    /// <returns>A task that completes when the condition holds.</returns>
    private static async Task WaitAsync(Func<bool> condition)
    {
        var deadline = DateTime.UtcNow + Bound;
        while (!condition())
        {
            Assert.True(DateTime.UtcNow < deadline, "condition not reached");
            await Task.Delay(10);
        }
    }

    /// <summary>
    /// A verifier backed by a delegate.
    /// </summary>
    /// <param name="verify">The verification behavior.</param>
    private sealed class Verifier(Func<CancellationToken, Task> verify) : IServerVerifier
    {
        /// <summary>Gets a verifier that accepts immediately.</summary>
        public static Verifier Accept { get; } = new(_ => Task.CompletedTask);

        /// <inheritdoc/>
        public async ValueTask VerifyAsync(IHelperTransport transport, CancellationToken cancellationToken) => await verify(cancellationToken);
    }
}
