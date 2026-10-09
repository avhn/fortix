using System.Text.Encodings.Web;
using System.Text.Json;
using System.Text.Json.Serialization;
using System.Text.Unicode;
using Fortix.Core.Profiles;
using Fortix.Core.Protocol;

namespace Fortix.Core.Json;

/// <summary>
/// Source-generated serializers for every wire type, so no reflection is needed at run time.
/// </summary>
/// <remarks>
/// Absent values are omitted rather than written as null because the helper rejects null.
/// <see cref="JsonSerializerContext"/> settings apply to <c>Default</c>; <see cref="Wire"/>
/// adds an encoder that keeps non-ASCII text unescaped so frame sizes stay close to the helper's.
/// </remarks>
[JsonSourceGenerationOptions(DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull)]
[JsonSerializable(typeof(Profile))]
[JsonSerializable(typeof(ProfileDraft))]
[JsonSerializable(typeof(HelperRequest))]
[JsonSerializable(typeof(HelperFrame))]
[JsonSerializable(typeof(HelloResponse))]
[JsonSerializable(typeof(UpResponse))]
[JsonSerializable(typeof(List<SessionStatus>))]
[JsonSerializable(typeof(List<ProfileState>))]
[JsonSerializable(typeof(List<string>))]
[JsonSerializable(typeof(List<AggregateProfile>))]
internal sealed partial class CoreJsonContext : JsonSerializerContext
{
    /// <summary>
    /// Gets the context used for encoding records and profiles sent to the helper.
    /// </summary>
    internal static CoreJsonContext Wire { get; } = new(new JsonSerializerOptions
    {
        DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull,
        Encoder = JavaScriptEncoder.Create(UnicodeRanges.All),
    });
}
