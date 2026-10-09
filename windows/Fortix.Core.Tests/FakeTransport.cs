using System.Text;
using System.Text.Json;
using System.Threading.Channels;
using Fortix.Core.Client;

namespace Fortix.Core.Tests;

/// <summary>
/// An in-memory helper endpoint that records every byte written and replays scripted replies.
/// </summary>
internal sealed class FakeTransport : IHelperTransport
{
    /// <summary>Chunks waiting to be read; completing the channel signals end of stream.</summary>
    private readonly Channel<byte[]> incoming = Channel.CreateUnbounded<byte[]>();

    /// <summary>Guards the written bytes and parsed requests.</summary>
    private readonly Lock gate = new();

    /// <summary>Every byte the client wrote.</summary>
    private readonly List<byte> written = [];

    /// <summary>Requests parsed from complete written records.</summary>
    private readonly List<JsonElement> requests = [];

    /// <summary>The unread remainder of the current chunk.</summary>
    private byte[] remainder = [];

    /// <summary>The number of bytes already consumed into requests.</summary>
    private int parsed;

    /// <summary>The number of read calls.</summary>
    private int readCalls;

    /// <summary>The number of writes that threw <see cref="WriteFailure"/>.</summary>
    private int failedWrites;

    /// <summary>
    /// Creates a transport whose default responder answers hello with protocol 1 and acknowledges the rest.
    /// </summary>
    public FakeTransport() => Responder = DefaultResponder;

    /// <summary>Gets or sets the reply producer for each written request; null replies are skipped.</summary>
    public Func<JsonElement, string?> Responder { get; set; }

    /// <summary>Gets or sets an exception every write throws, simulating a closed pipe.</summary>
    public Exception? WriteFailure { get; set; }

    /// <summary>Gets the number of bytes the client wrote.</summary>
    public int BytesWritten
    {
        get
        {
            lock (gate)
            {
                return written.Count;
            }
        }
    }

    /// <summary>Gets the number of read calls the client made.</summary>
    public int ReadCalls => Volatile.Read(ref readCalls);

    /// <summary>Gets the number of writes that threw <see cref="WriteFailure"/>.</summary>
    public int FailedWrites => Volatile.Read(ref failedWrites);

    /// <summary>Gets whether the client disposed the transport.</summary>
    public bool Disposed { get; private set; }

    /// <summary>Gets or sets a task disposal waits on after closing, simulating asynchronous handle cleanup.</summary>
    public Task DisposeGate { get; set; } = Task.CompletedTask;

    /// <summary>Gets whether disposal finished, including the wait on <see cref="DisposeGate"/>.</summary>
    public bool DisposeCompleted { get; private set; }

    /// <summary>Gets a snapshot of the parsed requests.</summary>
    public List<JsonElement> Requests
    {
        get
        {
            lock (gate)
            {
                return [.. requests];
            }
        }
    }

    /// <summary>
    /// Answers hello with protocol 1 and every other request with an empty success.
    /// </summary>
    /// <param name="request">The parsed request.</param>
    /// <returns>The reply record.</returns>
    public static string DefaultResponder(JsonElement request)
    {
        var id = request.GetProperty("id").GetString();
        return request.GetProperty("op").GetString() == "hello"
            ? $"{{\"type\":\"result\",\"id\":\"{id}\",\"ok\":true,\"data\":{{\"helper_version\":\"0.3.0\",\"protocol\":1}}}}\n"
            : $"{{\"type\":\"result\",\"id\":\"{id}\",\"ok\":true}}\n";
    }

    /// <summary>
    /// Queues bytes for the client to read.
    /// </summary>
    /// <param name="data">The chunk.</param>
    public void Send(byte[] data) => incoming.Writer.TryWrite(data);

    /// <summary>
    /// Queues UTF-8 text for the client to read.
    /// </summary>
    /// <param name="text">The text.</param>
    public void Send(string text) => Send(Encoding.UTF8.GetBytes(text));

    /// <summary>
    /// Ends the stream after queued chunks are read.
    /// </summary>
    public void Close() => incoming.Writer.TryComplete();

    /// <inheritdoc/>
    public async ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken)
    {
        Interlocked.Increment(ref readCalls);
        if (remainder.Length == 0)
        {
            try
            {
                remainder = await incoming.Reader.ReadAsync(cancellationToken);
            }
            catch (ChannelClosedException)
            {
                return 0;
            }
        }
        var count = Math.Min(buffer.Length, remainder.Length);
        remainder.AsSpan(0, count).CopyTo(buffer.Span);
        remainder = remainder[count..];
        return count;
    }

    /// <inheritdoc/>
    public ValueTask WriteAsync(ReadOnlyMemory<byte> buffer, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        ObjectDisposedException.ThrowIf(Disposed, this);
        if (WriteFailure is not null)
        {
            Interlocked.Increment(ref failedWrites);
            throw WriteFailure;
        }
        var replies = new List<string>();
        lock (gate)
        {
            written.AddRange(buffer.ToArray());
            int newline;
            while ((newline = written.IndexOf((byte)'\n', parsed)) >= 0)
            {
                using var document = JsonDocument.Parse(written.GetRange(parsed, newline - parsed).ToArray());
                var request = document.RootElement.Clone();
                requests.Add(request);
                parsed = newline + 1;
                if (Responder(request) is { } reply)
                {
                    replies.Add(reply);
                }
            }
        }
        replies.ForEach(Send);
        return ValueTask.CompletedTask;
    }

    /// <inheritdoc/>
    public async ValueTask DisposeAsync()
    {
        Disposed = true;
        incoming.Writer.TryComplete();
        await DisposeGate;
        DisposeCompleted = true;
    }
}
