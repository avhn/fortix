using System.Security.Cryptography;
using System.Text.Json;
using Fortix.Core.Json;

namespace Fortix.Core.Protocol;

/// <summary>
/// Thrown for malformed, oversized, or semantically invalid records; messages never contain input.
/// </summary>
public sealed class HelperProtocolException : Exception
{
    /// <summary>
    /// Creates an exception with a fixed message.
    /// </summary>
    /// <param name="message">The failure description.</param>
    public HelperProtocolException(string message)
        : base(message)
    {
    }
}

/// <summary>
/// Encodes requests and decodes results and events as bounded newline-terminated records.
/// </summary>
public static class FrameCodec
{
    /// <summary>The fixed message for a structurally invalid record.</summary>
    internal const string InvalidObject = "protocol: invalid object";

    /// <summary>The fixed message for a record longer than the limit.</summary>
    internal const string RecordTooLarge = "protocol: record exceeds limit";

    /// <summary>
    /// Every key a result or event may carry, matching the Go client's shared envelope.
    /// </summary>
    private static readonly HashSet<string> FrameFields = new(StringComparer.Ordinal)
    {
        "type", "code", "wanted", "initiated", "cleanup_pending", "id", "ok", "error", "data", "profile",
        "attempt", "state", "detail", "challenge_id", "kind", "prompt", "digest", "subject", "issuer", "line",
    };

    /// <summary>
    /// Keys each event type must carry; state events may also carry code.
    /// </summary>
    private static readonly Dictionary<string, string[]> EventFields = new(StringComparer.Ordinal)
    {
        ["state"] = ["state", "detail", "wanted", "initiated", "cleanup_pending"],
        ["challenge"] = ["challenge_id", "kind", "prompt"],
        ["cert"] = ["digest", "subject", "issuer"],
        ["log"] = ["line"],
    };

    /// <summary>
    /// Validates and encodes one request as a complete record including its newline.
    /// </summary>
    /// <remarks>
    /// The caller owns the returned buffer and should clear it after writing, because a
    /// credential answer is encoded in it.
    /// </remarks>
    /// <param name="request">The request to encode.</param>
    /// <returns>The UTF-8 record.</returns>
    /// <exception cref="HelperProtocolException">The request is invalid or too large.</exception>
    public static byte[] Encode(HelperRequest request)
    {
        ArgumentNullException.ThrowIfNull(request);
        if (!request.IsValid())
        {
            throw new HelperProtocolException("protocol: invalid request arguments");
        }
        var json = JsonSerializer.SerializeToUtf8Bytes(request.ForWire(), CoreJsonContext.Wire.HelperRequest);
        try
        {
            if (json.Length + 1 > HelperProtocol.MaxLine)
            {
                throw new HelperProtocolException(RecordTooLarge);
            }
            var record = new byte[json.Length + 1];
            json.CopyTo(record, 0);
            record[^1] = (byte)'\n';
            return record;
        }
        finally
        {
            CryptographicOperations.ZeroMemory(json);
        }
    }

    /// <summary>
    /// Decodes one complete record, with or without its trailing newline, into a result or event.
    /// </summary>
    /// <remarks>
    /// Duplicate keys, nulls, unknown or case-variant keys, nesting deeper than 32, trailing data,
    /// and type mismatches fail. Results must pair ok with error correctly and carry an id unless
    /// they are an unauthorized rejection sent before any request was read. Events must carry
    /// exactly the fields of their type.
    /// </remarks>
    /// <param name="record">The record bytes.</param>
    /// <returns>The decoded message.</returns>
    /// <exception cref="HelperProtocolException">The record is rejected.</exception>
    public static HelperMessage Decode(ReadOnlySpan<byte> record)
    {
        if (record.Length > HelperProtocol.MaxLine)
        {
            throw new HelperProtocolException(RecordTooLarge);
        }
        if (!record.IsEmpty && record[^1] == (byte)'\n')
        {
            record = record[..^1];
        }
        if (!StrictJson.IsStrictObject(record, FrameFields))
        {
            throw new HelperProtocolException(InvalidObject);
        }
        HelperFrame frame;
        try
        {
            frame = JsonSerializer.Deserialize(record, CoreJsonContext.Default.HelperFrame)!;
        }
        catch (Exception e) when (e is JsonException or InvalidOperationException)
        {
            throw new HelperProtocolException(InvalidObject);
        }
        if (frame.Type == "result")
        {
            return DecodeResult(frame);
        }
        if (frame.Type is null || !EventFields.TryGetValue(frame.Type, out var required))
        {
            throw new HelperProtocolException("helper returned unknown message type");
        }
        var present = PresentFields(frame);
        var permitted = new HashSet<string>(required, StringComparer.Ordinal) { "type", "profile", "attempt" };
        if (frame.Type == "state")
        {
            permitted.Add("code");
        }
        if (!permitted.IsSubsetOf(present.Append("code")) || !present.All(permitted.Contains))
        {
            throw new HelperProtocolException("helper returned invalid event");
        }
        return new HelperMessage(null, new HelperEvent
        {
            Type = frame.Type,
            Profile = frame.Profile!,
            Attempt = frame.Attempt!.Value,
            State = frame.State ?? "",
            Detail = frame.Detail ?? "",
            Code = frame.Code ?? "",
            Wanted = frame.Wanted ?? false,
            Initiated = frame.Initiated ?? false,
            CleanupPending = frame.CleanupPending ?? false,
            ChallengeId = frame.ChallengeId ?? "",
            Kind = frame.Kind ?? "",
            Prompt = frame.Prompt ?? "",
            Digest = frame.Digest ?? "",
            Subject = frame.Subject ?? "",
            Issuer = frame.Issuer ?? "",
            Line = frame.Line ?? "",
        });
    }

    /// <summary>
    /// Checks result envelope semantics after structural decoding.
    /// </summary>
    /// <param name="frame">A frame of type result.</param>
    /// <returns>The result message.</returns>
    private static HelperMessage DecodeResult(HelperFrame frame)
    {
        var ok = frame.Ok ?? false;
        var eventOnly = frame.Profile is not null || frame.Attempt is not null || frame.State is not null || frame.Detail is not null
            || frame.Code is not null || frame.Wanted is not null || frame.Initiated is not null || frame.CleanupPending is not null
            || frame.ChallengeId is not null || frame.Kind is not null || frame.Prompt is not null || frame.Digest is not null
            || frame.Subject is not null || frame.Issuer is not null || frame.Line is not null;
        var preRequestRejection = !ok && frame.Error?.Code == HelperErrorCodes.Unauthorized;
        if (eventOnly || (string.IsNullOrEmpty(frame.Id) && !preRequestRejection) || (ok && frame.Error is not null)
            || (!ok && (frame.Error is null || frame.Data is not null)) || (frame.Id?.Length ?? 0) > 128)
        {
            throw new HelperProtocolException("helper returned invalid result");
        }
        return new HelperMessage(new HelperResult(frame.Id ?? "", ok, frame.Error, frame.Data), null);
    }

    /// <summary>
    /// Lists the wire names of the event fields present in a frame.
    /// </summary>
    /// <param name="frame">The decoded frame.</param>
    /// <returns>The present field names, including type, profile, and attempt.</returns>
    private static List<string> PresentFields(HelperFrame frame)
    {
        var present = new List<string> { "type" };
        void Mark(object? value, string name)
        {
            if (value is not null)
            {
                present.Add(name);
            }
        }
        Mark(frame.Profile, "profile");
        Mark(frame.Attempt, "attempt");
        Mark(frame.State, "state");
        Mark(frame.Detail, "detail");
        Mark(frame.Code, "code");
        Mark(frame.Wanted, "wanted");
        Mark(frame.Initiated, "initiated");
        Mark(frame.CleanupPending, "cleanup_pending");
        Mark(frame.ChallengeId, "challenge_id");
        Mark(frame.Kind, "kind");
        Mark(frame.Prompt, "prompt");
        Mark(frame.Digest, "digest");
        Mark(frame.Subject, "subject");
        Mark(frame.Issuer, "issuer");
        Mark(frame.Line, "line");
        Mark(frame.Id, "id");
        Mark(frame.Ok, "ok");
        Mark(frame.Error, "error");
        Mark(frame.Data, "data");
        return present;
    }
}

/// <summary>
/// A decoded record: exactly one of <see cref="Result"/> or <see cref="Event"/> is set.
/// </summary>
/// <param name="Result">The correlated reply, for result records.</param>
/// <param name="Event">The notification, for event records.</param>
public sealed record HelperMessage(HelperResult? Result, HelperEvent? Event);
