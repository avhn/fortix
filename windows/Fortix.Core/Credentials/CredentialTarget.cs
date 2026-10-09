using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using Fortix.Core.Json;
using Fortix.Core.Profiles;

namespace Fortix.Core.Credentials;

/// <summary>
/// The credential store name that binds one password to a profile, gateway, and username.
/// </summary>
/// <remarks>
/// The command-line client stores passwords under <c>fortix:&lt;id&gt;:&lt;sha256&gt;:password</c>,
/// where the hash covers the JSON tuple [host, port, username] as the Go encoder writes it.
/// Hashing an encoded tuple prevents ambiguous concatenation, and changing the gateway or
/// username yields a different name so a stale password is never offered to a new endpoint.
/// </remarks>
public sealed record CredentialTarget
{
    /// <summary>The service prefix shared with the command-line client.</summary>
    public const string Service = "fortix";

    /// <summary>
    /// Creates the target for an explicit identity without normalizing any part of it.
    /// </summary>
    /// <param name="id">The profile identifier.</param>
    /// <param name="host">The gateway host exactly as stored.</param>
    /// <param name="port">The gateway port, 1 to 65535.</param>
    /// <param name="username">The account name exactly as stored.</param>
    /// <exception cref="ArgumentException">Any part of the identity is invalid.</exception>
    public CredentialTarget(string id, string host, long port, string username)
    {
        if (!ProfileRules.ValidId(id) || string.IsNullOrEmpty(host) || port is < 1 or > 65535 || string.IsNullOrEmpty(username))
        {
            throw new ArgumentException("credential identity is invalid");
        }
        TupleJson = "[" + GoJson.Quote(host) + "," + port.ToString(CultureInfo.InvariantCulture) + "," + GoJson.Quote(username) + "]";
        var digest = Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes(TupleJson)));
        Account = id + ":" + digest + ":password";
    }

    /// <summary>Gets the account part, <c>&lt;id&gt;:&lt;sha256&gt;:password</c>.</summary>
    public string Account { get; }

    /// <summary>Gets the hashed tuple, kept for interoperability checks with synthetic input.</summary>
    public string TupleJson { get; }

    /// <summary>Gets the full credential store target name, <c>fortix:&lt;account&gt;</c>.</summary>
    public string Target => Service + ":" + Account;

    /// <summary>
    /// Creates the target for a stored profile; an unset port means the default 443.
    /// </summary>
    /// <param name="profile">The helper's stored profile.</param>
    /// <returns>The credential target.</returns>
    public static CredentialTarget For(Profile profile)
    {
        ArgumentNullException.ThrowIfNull(profile);
        return new CredentialTarget(profile.Id, profile.Gateway.Host, profile.Gateway.Port == 0 ? 443 : profile.Gateway.Port, profile.Username);
    }
}
