using System.Text;
using Fortix.App.Model;
using Fortix.Core.Credentials;

namespace Fortix.App.Tests;

/// <summary>
/// Checks that saved passwords use the exact Credential Manager layout of the command-line client.
/// </summary>
public sealed class CredentialBlobTests
{
    /// <summary>
    /// Every golden vector maps to its target, user name, and raw UTF-8 blob; an empty password is never stored.
    /// </summary>
    [Fact]
    public void MatchesGoldenVectors()
    {
        var entries = Vectors.Entries("keychain.json");
        Assert.NotEmpty(entries);
        foreach (var entry in entries)
        {
            var target = new CredentialTarget(entry.GetProperty("id").GetString()!, entry.GetProperty("host").GetString()!,
                entry.GetProperty("port").GetInt64(), entry.GetProperty("username").GetString()!);
            var account = entry.GetProperty("account").GetString()!;
            var password = entry.GetProperty("password").GetString()!;
            Assert.Equal(account, CredentialBlob.UserName(target));
            Assert.Equal("fortix:" + account, target.Target);
            if (password.Length == 0)
            {
                // An empty saved value cannot answer a challenge, so the app asks instead of using it.
                Assert.Equal(CredentialFailure.Invalid, Assert.Throws<CredentialStoreException>(() => CredentialBlob.Encode(password)).Failure);
                Assert.Equal(CredentialFailure.Unavailable, Assert.Throws<CredentialStoreException>(() => CredentialBlob.Decode([])).Failure);
                continue;
            }
            var blob = CredentialBlob.Encode(password);
            Assert.Equal(Encoding.UTF8.GetBytes(password), blob);
            Assert.Equal(password, CredentialBlob.Decode(blob));
        }
    }

    /// <summary>
    /// Passwords up to 2560 UTF-8 bytes are accepted; longer ones are refused, counted in bytes.
    /// </summary>
    [Fact]
    public void EnforcesByteLimit()
    {
        Assert.Equal(CredentialBlob.MaxBytes, CredentialBlob.Encode(new string('x', CredentialBlob.MaxBytes)).Length);
        Assert.Equal(CredentialFailure.TooLong, Assert.Throws<CredentialStoreException>(() => CredentialBlob.Encode(new string('x', CredentialBlob.MaxBytes + 1))).Failure);
        // 1281 two-byte characters are 2562 bytes although only 1281 characters long.
        Assert.Equal(CredentialFailure.TooLong, Assert.Throws<CredentialStoreException>(() => CredentialBlob.Encode(new string('\u00e9', 1281))).Failure);
        Assert.Equal(CredentialFailure.Unavailable, Assert.Throws<CredentialStoreException>(() => CredentialBlob.Decode(new byte[CredentialBlob.MaxBytes + 1])).Failure);
    }

    /// <summary>
    /// Empty and malformed values are rejected, never repaired.
    /// </summary>
    [Fact]
    public void RejectsMalformedValues()
    {
        Assert.Equal(CredentialFailure.Invalid, Assert.Throws<CredentialStoreException>(() => CredentialBlob.Encode("")).Failure);
        Assert.Equal(CredentialFailure.Invalid, Assert.Throws<CredentialStoreException>(() => CredentialBlob.Encode("bad\ud800")).Failure);
        Assert.Equal(CredentialFailure.Unavailable, Assert.Throws<CredentialStoreException>(() => CredentialBlob.Decode([])).Failure);
        Assert.Equal(CredentialFailure.Unavailable, Assert.Throws<CredentialStoreException>(() => CredentialBlob.Decode([0xff, 0xfe])).Failure);
    }

    /// <summary>
    /// The base64 prefix of the macOS keychain format is not decoded on Windows.
    /// </summary>
    [Fact]
    public void StoredValueIsNotPrefixed()
    {
        var entry = Vectors.Entries("keychain.json")[0];
        var stored = entry.GetProperty("stored_password").GetString()!;
        Assert.StartsWith("go-keyring-base64:", stored, StringComparison.Ordinal);
        Assert.Equal(stored, CredentialBlob.Decode(Encoding.UTF8.GetBytes(stored)));
    }

    /// <summary>
    /// Zeroing clears every byte.
    /// </summary>
    [Fact]
    public void ZeroClearsBuffer()
    {
        var buffer = CredentialBlob.Encode("synthetic-password");
        CredentialBlob.Zero(buffer);
        Assert.All(buffer, b => Assert.Equal(0, b));
    }
}
