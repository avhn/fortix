using System.Runtime.InteropServices;
using Fortix.App.Model;
using Fortix.Core.Credentials;
using Windows.Win32;
using Windows.Win32.Foundation;
using Windows.Win32.Security.Credentials;

namespace Fortix.App.Native;

/// <summary>
/// Saved passwords in Windows Credential Manager, readable by the command-line client too.
/// </summary>
/// <remarks>
/// Entries are generic credentials persisted for this user on this machine, named and encoded
/// as <see cref="CredentialBlob"/> describes. Password buffers are cleared after each call and
/// no target, user name, or secret is ever written to a log.
/// </remarks>
internal sealed unsafe class CredentialManagerStore : ICredentialStore
{
    /// <summary>ERROR_NOT_FOUND, returned when no credential has the target name.</summary>
    private const int ErrorNotFound = 1168;

    /// <inheritdoc/>
    public string Read(CredentialTarget target)
    {
        ArgumentNullException.ThrowIfNull(target);
        if (!PInvoke.CredRead(target.Target, CRED_TYPE.CRED_TYPE_GENERIC, out var credential))
        {
            throw new CredentialStoreException(Marshal.GetLastPInvokeError() == ErrorNotFound ? CredentialFailure.NotFound : CredentialFailure.Unavailable);
        }
        try
        {
            var blob = new Span<byte>(credential->CredentialBlob, (int)Math.Min(credential->CredentialBlobSize, int.MaxValue));
            try
            {
                return CredentialBlob.Decode(blob);
            }
            finally
            {
                CredentialBlob.Zero(blob);
            }
        }
        finally
        {
            PInvoke.CredFree(credential);
        }
    }

    /// <inheritdoc/>
    public void Write(CredentialTarget target, string password)
    {
        ArgumentNullException.ThrowIfNull(target);
        var blob = CredentialBlob.Encode(password);
        try
        {
            fixed (byte* data = blob)
            fixed (char* name = target.Target)
            fixed (char* user = CredentialBlob.UserName(target))
            {
                var credential = new CREDENTIALW
                {
                    Type = CRED_TYPE.CRED_TYPE_GENERIC,
                    TargetName = name,
                    CredentialBlobSize = (uint)blob.Length,
                    CredentialBlob = data,
                    Persist = CRED_PERSIST.CRED_PERSIST_LOCAL_MACHINE,
                    UserName = user,
                };
                if (!PInvoke.CredWrite(&credential, 0))
                {
                    throw new CredentialStoreException(CredentialFailure.Unavailable);
                }
            }
        }
        finally
        {
            CredentialBlob.Zero(blob);
        }
    }

    /// <inheritdoc/>
    public void Delete(CredentialTarget target)
    {
        ArgumentNullException.ThrowIfNull(target);
        if (!PInvoke.CredDelete(target.Target, CRED_TYPE.CRED_TYPE_GENERIC) && Marshal.GetLastPInvokeError() != ErrorNotFound)
        {
            throw new CredentialStoreException(CredentialFailure.Unavailable);
        }
    }
}
