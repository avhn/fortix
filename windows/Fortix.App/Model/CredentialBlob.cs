using System.Security.Cryptography;
using System.Text;
using Fortix.Core.Credentials;

namespace Fortix.App.Model;

/// <summary>
/// The Credential Manager encoding the command-line client uses, so either side reads the other's passwords.
/// </summary>
/// <remarks>
/// The command-line client's keyring library stores a generic credential named
/// <c>fortix:&lt;account&gt;</c> whose user name is the account and whose blob is the password's
/// raw UTF-8 bytes, persisted for the local machine. Unlike the macOS keychain encoding there is
/// no prefix or base64 layer. Passwords above 2560 bytes are refused there, so they are here too.
/// </remarks>
public static class CredentialBlob
{
    /// <summary>The largest password, in UTF-8 bytes, that the command-line client stores.</summary>
    public const int MaxBytes = 2560;

    /// <summary>
    /// Encodes a password as the credential blob; the caller zeroes the returned buffer after use.
    /// </summary>
    /// <param name="password">The password.</param>
    /// <returns>The UTF-8 bytes.</returns>
    /// <exception cref="CredentialStoreException">The password is empty, too long, or not valid Unicode.</exception>
    public static byte[] Encode(string password)
    {
        ArgumentNullException.ThrowIfNull(password);
        if (password.Length == 0)
        {
            throw new CredentialStoreException(CredentialFailure.Invalid);
        }
        int count;
        try
        {
            count = Strict.GetByteCount(password);
        }
        catch (EncoderFallbackException)
        {
            throw new CredentialStoreException(CredentialFailure.Invalid);
        }
        if (count > MaxBytes)
        {
            throw new CredentialStoreException(CredentialFailure.TooLong);
        }
        return Strict.GetBytes(password);
    }

    /// <summary>
    /// Decodes a stored blob; malformed UTF-8 is treated as an unusable entry, never repaired.
    /// </summary>
    /// <param name="blob">The stored bytes.</param>
    /// <returns>The password.</returns>
    /// <exception cref="CredentialStoreException">The blob is empty, too long, or not UTF-8.</exception>
    public static string Decode(ReadOnlySpan<byte> blob)
    {
        if (blob.Length is 0 or > MaxBytes)
        {
            throw new CredentialStoreException(CredentialFailure.Unavailable);
        }
        try
        {
            return Strict.GetString(blob);
        }
        catch (DecoderFallbackException)
        {
            throw new CredentialStoreException(CredentialFailure.Unavailable);
        }
    }

    /// <summary>
    /// Returns the user name the command-line client writes for a target: the account part.
    /// </summary>
    /// <param name="target">The credential target.</param>
    /// <returns>The credential user name.</returns>
    public static string UserName(CredentialTarget target)
    {
        ArgumentNullException.ThrowIfNull(target);
        return target.Account;
    }

    /// <summary>
    /// Clears a buffer that held a password.
    /// </summary>
    /// <param name="buffer">The buffer.</param>
    public static void Zero(Span<byte> buffer) => CryptographicOperations.ZeroMemory(buffer);

    /// <summary>
    /// UTF-8 that throws instead of substituting replacement characters.
    /// </summary>
    private static readonly UTF8Encoding Strict = new(encoderShouldEmitUTF8Identifier: false, throwOnInvalidBytes: true);
}

/// <summary>
/// Why a credential operation failed, without any detail from the store.
/// </summary>
public enum CredentialFailure
{
    /// <summary>No password is stored for the target.</summary>
    NotFound,

    /// <summary>The store refused access or holds an unusable entry.</summary>
    Unavailable,

    /// <summary>The password exceeds the shared 2560-byte limit.</summary>
    TooLong,

    /// <summary>The password is empty or not valid Unicode.</summary>
    Invalid,
}

/// <summary>
/// Thrown by credential operations; the message is fixed and never contains a secret.
/// </summary>
public sealed class CredentialStoreException : Exception
{
    /// <summary>
    /// Creates the exception for a failure category.
    /// </summary>
    /// <param name="failure">The category.</param>
    public CredentialStoreException(CredentialFailure failure)
        : base(failure switch
        {
            CredentialFailure.NotFound => "no saved password",
            CredentialFailure.TooLong => "the password is longer than 2560 bytes",
            CredentialFailure.Invalid => "the password is empty or not valid text",
            _ => "Credential Manager is unavailable",
        })
    {
        Failure = failure;
    }

    /// <summary>Gets the failure category.</summary>
    public CredentialFailure Failure { get; }
}

/// <summary>
/// Saved password storage keyed by profile identity; implementations never log targets or secrets.
/// </summary>
public interface ICredentialStore
{
    /// <summary>
    /// Reads the password saved for a target.
    /// </summary>
    /// <param name="target">The credential target.</param>
    /// <returns>The password.</returns>
    /// <exception cref="CredentialStoreException">Nothing is saved or the store is unavailable.</exception>
    string Read(CredentialTarget target);

    /// <summary>
    /// Saves or replaces the password for a target.
    /// </summary>
    /// <param name="target">The credential target.</param>
    /// <param name="password">The password.</param>
    /// <exception cref="CredentialStoreException">The password cannot be stored.</exception>
    void Write(CredentialTarget target, string password);

    /// <summary>
    /// Removes the password for a target; an absent entry is not an error.
    /// </summary>
    /// <param name="target">The credential target.</param>
    /// <exception cref="CredentialStoreException">The store is unavailable.</exception>
    void Delete(CredentialTarget target);
}
