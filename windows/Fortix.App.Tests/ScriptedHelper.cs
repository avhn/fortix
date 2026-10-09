using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using System.Threading.Channels;
using Fortix.App.Model;
using Fortix.Core.Client;
using Fortix.Core.Profiles;

namespace Fortix.App.Tests;

/// <summary>
/// An in-memory helper that stores profiles and sessions and answers requests like the service.
/// </summary>
/// <remarks>
/// It records every request so tests can assert what the app sent, and lets tests push events.
/// Replies are produced synchronously while the client writes, keeping tests deterministic.
/// </remarks>
internal sealed class ScriptedHelper : IHelperTransport, IHelperPipe
{
    /// <summary>Chunks for the client to read; completion means end of stream.</summary>
    private readonly Channel<byte[]> incoming = Channel.CreateUnbounded<byte[]>();

    /// <summary>Guards the request log and the written buffer.</summary>
    private readonly Lock gate = new();

    /// <summary>Bytes written but not yet parsed into requests.</summary>
    private readonly List<byte> pending = [];

    /// <summary>The unread remainder of the current chunk.</summary>
    private byte[] remainder = [];

    /// <summary>Gets the stored profiles by identifier.</summary>
    public Dictionary<string, Profile> Profiles { get; } = new(StringComparer.Ordinal);

    /// <summary>Gets the sessions by profile identifier.</summary>
    public Dictionary<string, JsonObject> Sessions { get; } = new(StringComparer.Ordinal);

    /// <summary>Gets every parsed request.</summary>
    public List<JsonObject> Requests { get; } = [];

    /// <summary>Gets or sets a hook that may change state when a down request arrives.</summary>
    public Action<JsonObject>? OnDown { get; set; }

    /// <summary>Gets or sets a failure returned for every request with this operation.</summary>
    public (string Op, string Code, string Message)? Failure { get; set; }

    /// <summary>Gets the number of bytes the client wrote.</summary>
    public int BytesWritten { get; private set; }

    /// <summary>
    /// Opens a verified client to this helper with a verifier that accepts it.
    /// </summary>
    /// <returns>The connector the view model uses.</returns>
    public Func<CancellationToken, Task<HelperClient>> Connector() =>
        ct => HelperClient.ConnectAsync(this, new AcceptingVerifier(), new HelperClientOptions { SubscribeLogs = true }, ct);

    /// <summary>
    /// Stores a profile and an idle session for it.
    /// </summary>
    /// <param name="profile">The profile.</param>
    /// <param name="state">The session phase.</param>
    /// <param name="attempt">The session attempt.</param>
    public void Add(Profile profile, string state = "disconnected", ulong attempt = 0)
    {
        Profiles[profile.Id] = profile;
        SetSession(profile.Id, state, attempt);
    }

    /// <summary>
    /// Replaces a session snapshot.
    /// </summary>
    /// <param name="id">The profile identifier.</param>
    /// <param name="state">The phase.</param>
    /// <param name="attempt">The attempt.</param>
    /// <param name="wanted">Whether connectivity is wanted.</param>
    /// <param name="cleanup">Whether cleanup is pending.</param>
    /// <param name="detail">The detail.</param>
    public void SetSession(string id, string state, ulong attempt, bool wanted = false, bool cleanup = false, string detail = "") =>
        Sessions[id] = new JsonObject
        {
            ["profile"] = id, ["state"] = state, ["detail"] = detail, ["attempt"] = attempt, ["wanted"] = wanted,
            ["initiated"] = false, ["cleanup_pending"] = cleanup, ["interface"] = "", ["local_ip"] = "", ["since"] = "0001-01-01T00:00:00Z",
        };

    /// <summary>
    /// Pushes an event record to the client.
    /// </summary>
    /// <param name="json">The event object without the trailing newline.</param>
    public void Push(string json) => incoming.Writer.TryWrite(Encoding.UTF8.GetBytes(json + "\n"));

    /// <summary>
    /// Returns the requests with one operation.
    /// </summary>
    /// <param name="op">The operation.</param>
    /// <returns>The matching requests.</returns>
    public List<JsonObject> Sent(string op)
    {
        lock (gate)
        {
            return [.. Requests.Where(r => (string?)r["op"] == op)];
        }
    }

    /// <inheritdoc/>
    public uint ServerProcessId() => 4242;

    /// <inheritdoc/>
    public async ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken)
    {
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
        lock (gate)
        {
            BytesWritten += buffer.Length;
            pending.AddRange(buffer.ToArray());
            int newline;
            while ((newline = pending.IndexOf((byte)'\n')) >= 0)
            {
                var request = JsonNode.Parse(pending.GetRange(0, newline).ToArray())!.AsObject();
                pending.RemoveRange(0, newline + 1);
                Requests.Add(request);
                incoming.Writer.TryWrite(Encoding.UTF8.GetBytes(Reply(request) + "\n"));
            }
        }
        return ValueTask.CompletedTask;
    }

    /// <inheritdoc/>
    public ValueTask DisposeAsync()
    {
        incoming.Writer.TryComplete();
        return ValueTask.CompletedTask;
    }

    /// <summary>
    /// Produces the result record for one request.
    /// </summary>
    /// <param name="request">The request.</param>
    /// <returns>The result JSON.</returns>
    private string Reply(JsonObject request)
    {
        var id = (string)request["id"]!;
        var op = (string)request["op"]!;
        if (Failure is { } failure && failure.Op == op)
        {
            return new JsonObject { ["type"] = "result", ["id"] = id, ["ok"] = false, ["error"] = new JsonObject { ["code"] = failure.Code, ["message"] = failure.Message } }.ToJsonString();
        }
        JsonNode? data = null;
        switch (op)
        {
            case "hello":
                data = new JsonObject { ["helper_version"] = "0.3.0", ["protocol"] = 1 };
                break;
            case "status":
                data = new JsonArray([.. Sessions.Values.Select(s => s.DeepClone())]);
                break;
            case "profile.list":
                data = new JsonArray([.. Profiles.Keys.Select(k => (JsonNode)new JsonObject { ["profile"] = k, ["state"] = (string?)Sessions.GetValueOrDefault(k)?["state"] ?? "disconnected" })]);
                break;
            case "profile.get":
                var name = (string)request["profile"]!;
                if (!Profiles.TryGetValue(name, out var stored))
                {
                    return new JsonObject { ["type"] = "result", ["id"] = id, ["ok"] = false, ["error"] = new JsonObject { ["code"] = "NOT_FOUND", ["message"] = "profile not found" } }.ToJsonString();
                }
                var copy = stored.Clone();
                ProfileRules.ApplyDefaults(copy);
                data = JsonNode.Parse(ProfileCodec.Encode(copy));
                break;
            case "profile.put":
                var profile = ProfileCodec.Decode(Encoding.UTF8.GetBytes(request["profile_json"]!.ToJsonString()));
                Profiles[profile.Id] = profile;
                if (!Sessions.ContainsKey(profile.Id))
                {
                    SetSession(profile.Id, "disconnected", 0);
                }
                break;
            case "profile.delete":
                Profiles.Remove((string)request["profile"]!);
                Sessions.Remove((string)request["profile"]!);
                break;
            case "up":
                data = new JsonObject { ["attempt"] = 1 };
                break;
            case "down":
                OnDown?.Invoke(request);
                break;
            case "logs":
                data = new JsonArray([.. Enumerable.Range(0, 3).Select(i => (JsonNode)$"line {i}")]);
                break;
        }
        var result = new JsonObject { ["type"] = "result", ["id"] = id, ["ok"] = true };
        if (data is not null)
        {
            result["data"] = data;
        }
        return result.ToJsonString();
    }

    /// <summary>
    /// A verifier that accepts any transport, for tests that do not exercise verification.
    /// </summary>
    private sealed class AcceptingVerifier : IServerVerifier
    {
        /// <inheritdoc/>
        public ValueTask VerifyAsync(IHelperTransport transport, CancellationToken cancellationToken) => ValueTask.CompletedTask;
    }
}

/// <summary>
/// An in-memory credential store that records writes and can be made to fail.
/// </summary>
internal sealed class MemoryCredentials : ICredentialStore
{
    /// <summary>Gets the stored passwords by target name.</summary>
    public Dictionary<string, string> Entries { get; } = new(StringComparer.Ordinal);

    /// <summary>Gets or sets whether writes fail.</summary>
    public bool FailWrites { get; set; }

    /// <inheritdoc/>
    public string Read(Fortix.Core.Credentials.CredentialTarget target) =>
        Entries.TryGetValue(target.Target, out var password) ? password : throw new CredentialStoreException(CredentialFailure.NotFound);

    /// <inheritdoc/>
    public void Write(Fortix.Core.Credentials.CredentialTarget target, string password)
    {
        if (FailWrites)
        {
            throw new CredentialStoreException(CredentialFailure.Unavailable);
        }
        Entries[target.Target] = password;
    }

    /// <inheritdoc/>
    public void Delete(Fortix.Core.Credentials.CredentialTarget target) => Entries.Remove(target.Target);
}

/// <summary>
/// Loads the golden vectors copied next to the test assembly.
/// </summary>
internal static class Vectors
{
    /// <summary>
    /// Returns every entry of a top-level array vector file.
    /// </summary>
    /// <param name="name">The file name.</param>
    /// <returns>The entries.</returns>
    public static List<JsonElement> Entries(string name)
    {
        using var document = JsonDocument.Parse(File.ReadAllBytes(Path.Combine(AppContext.BaseDirectory, "interop", name)));
        return [.. document.RootElement.EnumerateArray().Select(e => e.Clone())];
    }
}
