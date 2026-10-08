# Security

fortix is an early-development local VPN manager, not a sandbox or a managed
multi-user isolation service. Review its source and test it in an isolated
system before trusting it with production access.

## Privilege boundary

The CLI and tray run as the desktop user. The helper runs as root and alone
starts openfortivpn, manages owned routes/DNS, and records recovery state.
Openfortivpn and pppd are also privileged and part of the trusted computing
base. The helper never loads tray code or reads the desktop user's keychain.

The control socket is `root:fortix 0660`:

- macOS: `/var/run/fortix/fortix.sock`
- Linux: `/run/fortix/fortix.sock`

Each connection is checked using kernel peer credentials. Root and members
of the `fortix` group are authorized; others are refused. Membership grants
machine-wide management of every profile and tunnel. It is not restricted to
profiles created by that user. Authorized members can change a profile's
username, gateway, routing, and DNS domains, and confirm helper-captured
certificate pins for their own attempts. Membership is a trusted role: it permits
changing system routing and split DNS for the whole machine, affecting every user.
Grant it only to users trusted to manage machine-wide network access.

## What the helper accepts

The local newline-delimited JSON protocol uses bounded 64 KiB records and
correlated results. Typed operations cover version negotiation, subscription,
profile list/get/put/delete, connect/disconnect/status, credential answer/cancel,
certificate trust, and bounded redacted logs. Profile mutation is refused
while active. The helper independently performs strict schema validation;
client validation is not an authorization boundary.

Profiles cannot express raw openfortivpn flags, arbitrary configuration paths,
executables, PPP plugins, shell commands, passwords, or MFA seeds. Unknown
fields, duplicate keys, null values, malformed hostnames/domains/CIDRs, and
unsafe profile IDs fail validation. Stored profiles are `root:fortix 0640` in a `root:fortix 0750` directory, not
readable by non-members. Files are accessed
through trusted directories with symlink, ownership, mode, and file-type checks.

The helper constructs the openfortivpn argument list itself and executes it
without a shell. Username and realm are supplied through an inherited anonymous
pipe (`-c /dev/fd/3`), never argv or a disk configuration. It uses
a fixed working directory and environment, disabled openfortivpn/PPP DNS
writers, and its own trusted pinentry executable. Password and OTP command-line
flags and code-loading PPP options are never supplied by clients.

Before spawning, the helper checks executable files and their parent
directories for root ownership and unsafe write permissions. On macOS it also
checks loaded dylibs and rejects unsafe library paths. A normal Homebrew tree
is user-writable and must not be executed directly by a root helper. Explicit
installation copies openfortivpn and non-system libraries to a root-owned
location, rewrites Mach-O load paths, and re-signs the copies ad hoc. This does
not prove the original downloaded/build input is trustworthy: administrators
remain responsible for its provenance and checksum verification.

## Secrets and certificate flow

1. A user requests `up` for a stored profile.
2. The helper starts an attempt with a random token and a trusted pinentry
   responder. The attempt records the initiating kernel peer UID, retained across
   automatic retries. The private relay directory is `0700`.
3. A password/code request is bound to that attempt and routed to the initiating
   client if it is still present, otherwise only to subscribers with the same UID
   or root. Certificate events follow the same rule. Only that UID or root may
   answer, cancel, or trust. Trays ignore prompts for attempts they did not start.
   The first accepted answer wins and expired/obsolete answers are refused.
4. The client reads the OS keyring for passwords, otherwise asks for hidden
   input. Codes use hidden input and are not saved.
5. The secret crosses the local control socket and the attempt-bound relay,
   reaching openfortivpn through its Assuan pinentry exchange.

Secrets are not placed in files, argv, child environment variables, or log
messages. The keyring service is `fortix`; accounts bind the profile ID to a SHA-256 hash
of the gateway host, port, and username. Legacy ID-only entries are not read:
users re-enter and save the password after upgrading. A changed endpoint or
username cannot reuse a previous saved password.
Unavailable or locked keyrings cause a prompt, never plaintext storage.
`remember_passwords` defaults to true; users can disable it in their private
preferences. CLI `--save` explicitly enables saving. Prompted passwords are
saved only when the matching attempt connects successfully. A stored password
can still be used when remembering newly prompted passwords is disabled;
remove it with `fortix password clear <id>` or the tray profile's **Forget saved
password** entry if that is not desired.

Secrets necessarily exist in client, helper, pinentry, and openfortivpn memory,
and traverse local sockets in plaintext protected by OS access controls.
Go strings cannot guarantee cryptographic memory erasure. A process running
as the desktop user may access that user's keychain subject to OS policy;
root can inspect process memory and intercept credentials. fortix does not
protect against a compromised desktop account or root.

A rejected certificate triggers explicit confirmation of its SHA-256 digest,
subject, and issuer. The `trust` operation only accepts the last rejected digest
captured by the helper for that profile. Verify it independently before
confirmation. Displaying an identity does not authenticate it. CLI `--yes`
skips the human dialog, not the digest binding. Pins are helper-owned and set
only through `trust` with the captured digest. `profile add` preserves an
existing pin only when the gateway host and port are unchanged, and ignores the
submitted `trusted_cert`. Changing either gateway field clears the stored pin. Removing a profile and
adding it again clears its pin; group members can perform that reset.

## Network ownership and recovery

Custom routes are checked for overlapping active/configured routes, existing
routes, and connected interface subnets. Duplicate negotiated local IPv4
addresses and conflicting full-tunnel defaults are rejected. Gateway-pushed
routes are observed after authentication; gateway mode rejects default and
split-default routes on its own link, while full mode permits them. The kernel
must confirm that the reported tunnel interface carries the negotiated local IP
before the helper applies routes or split DNS. Otherwise it reports
`INTERFACE_MISMATCH`. Openfortivpn can install gateway routes before fortix
detects a conflict, so transient network changes remain possible.

Each attempt journals process identity and owned routes/DNS, not secrets.
Recovery compares process start identity before acting on recorded PIDs and
removes only owned resources. macOS resolver files have ownership markers;
foreign files are not overwritten and changed content is preserved during
cleanup. Linux split DNS uses systemd-resolved's per-link settings. Cleanup
errors are failures, not proof that the host was restored.

IPv6 routing is not handled. `preserve_lan` is currently configuration intent,
not an implemented bypass-route mechanism. There is no kill switch. fortix
cannot guarantee that every application sends DNS or traffic through the VPN,
or that another network manager will not change routes while a tunnel runs.
Authentication rejection and certificate changes do not trigger automatic
transport retry loops. Reconnecting the tray socket is distinct from restarting
a VPN session and does not generate new authentication attempts by itself.

## Threat model and diagnostics

In scope are unauthorized local socket callers, ambiguous or malicious protocol
input, path traversal and symlink attacks, arbitrary option injection, unsafe
privileged executable paths, stale credential replies, and accidental secret
exposure through diagnostics. Tests use temp-directory paths and injected
runners rather than real VPNs or privileged host changes.

Out of scope are hostile root, an already compromised authorized user, malicious
or vulnerable openfortivpn/pppd/OS components, compromised release/build inputs,
gateway-admin misconfiguration, and remote traffic confidentiality beyond the
VPN protocol and gateway configuration. Group-wide profile control is an
explicit trust decision, not tenant isolation.

Root log files remain private `0600` files in a `root:root 0700` directory.
Live log events are sent only to clients that explicitly subscribe to logs,
not to ordinary state subscribers. The tray requests at most 500
redacted lines through the helper and opens a `0600` copy in a private user
temporary directory. These snapshots remain until the tray exits normally;
an abrupt termination may leave copies, so treat them as sensitive diagnostics.

Per-profile logs are bounded and redacted, but gateway metadata, usernames,
addresses, and non-secret diagnostics can still be sensitive. Review logs
before sharing them. Never submit passwords, real gateway details, tokens,
keychain exports, or unredacted packet captures in an issue.

## Reporting vulnerabilities

Use GitHub's private vulnerability reporting for
[github.com/avhn/fortix](https://github.com/avhn/fortix): open the repository's
**Security** tab and choose **Report a vulnerability** to create a private
security advisory. Do not disclose an exploitable defect in a public issue.
If private reporting is unavailable, request a private contact through an issue
without including exploit details or secrets. Include affected versions,
platform, an isolated reproduction using placeholders, expected versus actual
behavior, and the impact. No response-time or remediation guarantee is implied.
