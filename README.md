# fortix

FortiGate SSL VPN profile manager for macOS and Debian/Ubuntu. A CLI and a
system tray share a small root helper that runs
[openfortivpn](https://github.com/adrienverge/openfortivpn) as a separate process.

## Features and status

- Named profiles, individual toggles, and several simultaneous tunnels when
  addresses and routes do not conflict.
- Password lookup and optional saving in the OS keychain, with hidden terminal
  or native desktop prompts when the keyring is unavailable.
- FortiToken push selection and prompted second-factor codes.
- Custom IPv4 routes and split DNS, owned-resource cleanup, and helper recovery.
- Explicit certificate confirmation showing SHA-256, subject, and issuer.
- A native tray with aggregate status, optional motion, notifications, and
  next-login autostart. The CLI works without a desktop tray.

**Status: early development.** Automated tests exercise unprivileged fixtures;
real-gateway compatibility and clean-machine installation need verification
before production use. No Windows, IPsec, SAML/SSO, or IPv6 tunnel routing.
The schema accepts `totp` and `static` MFA modes, but clients currently prompt
for their codes; automatic seed/static-secret storage is not implemented.
The `preserve_lan` field defaults to true but does not yet install additional
LAN bypass routes. Use custom routing for predictable local-network access.

## Installation

Download the archive for your OS and architecture from
[GitHub Releases](https://github.com/avhn/fortix/releases), verify its checksum,
and extract it. Keep `fortix` and `fortix-helper` together: the installer finds
the CLI beside the helper. Review the source before granting root access.
For a source build, use the Go version in `go.mod` and build each executable:

```sh
GOMAXPROCS=2 GOFLAGS=-p=2 go build -o dist/fortix ./cmd/fortix
GOMAXPROCS=2 GOFLAGS=-p=2 go build -o dist/fortix-helper ./cmd/fortix-helper
GOMAXPROCS=2 GOFLAGS=-p=2 go build -o dist/fortix-tray ./cmd/fortix-tray
```

Build the macOS tray natively with cgo and Xcode Command Line Tools installed.
Linux tray builds do not require cgo. The helper installs its own root-owned
binaries under `/usr/local/libexec/fortix` and links the CLI into
`/usr/local/bin`; it does not install the tray. Keep the tray at a stable,
user-owned location before enabling autostart.

### macOS

Install openfortivpn using Homebrew (or build it from its published source),
then explicitly vendor the binary and non-system libraries into a root-owned
location. A root helper must not execute a user-writable Homebrew binary or
load its user-writable libraries directly.

```sh
brew install openfortivpn
sudo ./fortix-helper install --openfortivpn "$(brew --prefix)/bin/openfortivpn"
```

The installer copies openfortivpn and its non-system dylibs to
`/Library/Application Support/fortix/libexec`, rewrites install names with
`install_name_tool`, and signs the copies ad hoc with `codesign`. It installs
and loads `com.github.avhn.fortix.helper` as a LaunchDaemon, creates the
`fortix` group, and enrolls `SUDO_USER`. Log out and back in to refresh group
membership. Release binaries are not Developer ID signed or notarized; review
and handle Gatekeeper's warnings according to your organization's policy.

### Debian/Ubuntu

Use a systemd installation with `iproute2`, `ppp`, `openfortivpn`, and
systemd-resolved for split DNS:

```sh
sudo apt install openfortivpn ppp iproute2 systemd-resolved
sudo ./fortix-helper install
```

This creates the `fortix` group, enrolls `SUDO_USER`, and enables
`fortix-helper.service`. Log out and back in before using the socket.
Alternatively install the release `.deb` with `apt install ./fortix_*.deb`.
The package starts the service but does not enroll desktop users; an
administrator must run `usermod -aG fortix <account>` and the user must log in
again. Packaged binaries live in `/usr/libexec/fortix`; do not mix package
ownership with the archive installer. Split DNS requires a working
`resolvectl`; there is no automatic resolvconf fallback.

The Linux tray uses StatusNotifierItem over D-Bus. KDE and XFCE usually expose
it directly; GNOME requires an AppIndicator-compatible extension. Without a
StatusNotifier host or working session D-Bus, no icon appears and the tray may
continue running invisibly. Use the CLI in that environment. Hidden
prompts require `zenity` or `kdialog`, and notifications use `notify-send`.
On macOS these use `osascript`.

## Quick start

Create `work.json` with a secret-free profile:

```json
{
  "schema_version": 1,
  "id": "work",
  "name": "Work",
  "backend": "openfortivpn",
  "gateway": { "host": "vpn.example.com", "port": 443 },
  "username": "jane.doe",
  "mfa": { "mode": "none" },
  "routes": { "mode": "custom", "include": ["10.20.0.0/16"], "preserve_lan": true },
  "dns": { "mode": "split", "domains": ["corp.example.com"] }
}
```

```sh
fortix profile validate work.json
fortix profile add work.json
fortix up work
fortix status
fortix down work
```

If the gateway's certificate is rejected, verify its identity with your
administrator over an independent channel, then use `fortix trust work`.
Trusting an unexpected digest without verification can expose credentials.
See [profiles](docs/profiles.md) for the complete schema.

## CLI reference

| Command | Behavior |
| --- | --- |
| `fortix version` | Print the binary version |
| `fortix profile validate <file>` | Validate local JSON without a helper |
| `fortix profile list` | List stored profile IDs and states |
| `fortix profile show <id>` | Show stored JSON |
| `fortix profile add <file>` | Validate and store through the helper |
| `fortix profile rm <id>` | Remove an inactive profile |
| `fortix import forticlient [--plist path] [--apply]` | Preview non-secret drafts; optionally store them |
| `fortix password set\|clear <id>` | Store a hidden password in, or remove it from, the keyring |
| `fortix up <id>...\|--all [--save]` | Wait for connection outcomes and answer challenges |
| `fortix down <id>...\|--all` | Stop selected tunnels |
| `fortix status [--json]` | Show the helper's current snapshot |
| `fortix logs <id> [--lines 1..500]` | Print bounded, redacted diagnostics |
| `fortix trust <id> [--yes]` | Capture rejected certificate identity, confirm trust, and connect |

Use `--help` for command-specific flags. `--yes` skips the confirmation prompt;
it does not bypass the helper's captured-digest check. Passwords are saved only
after successful connection when `--save` or `remember_passwords` is enabled.
To retry an incorrect cached password in the CLI, first run
`fortix password clear <id>`. After a failed attempt using a saved password,
the tray bypasses that password and prompts on the next attempt. A successful
remembered replacement restores keyring use; restarting the tray resets the
bypass, so clear the saved password if it should not be used again.

## Tray and preferences

Start `fortix-tray` as your desktop user, never as root. The **Profiles** menu
contains a checkbox for each profile with readable state text. Click it to
connect or stop its current attempt. **Connect all** starts inactive profiles,
**Disconnect all** stops all tunnels, and **Open logs** fetches up to 500
redacted lines from the helper and opens a private `0600` snapshot with `open`
or `xdg-open`. Snapshots are kept in a private user temporary directory until
the tray exits. Quit closes the tray client but does not stop helper-owned
connected tunnels. The tray reconnects with bounded backoff if
the helper restarts, without automatically starting stopped profiles.

The ring glyph uses shape as well as color; macOS uses a template icon that
adapts to menu-bar appearance. Colors apply only to Linux; macOS conveys
status through glyph shape, not grey, amber, or green:

| Status | Meaning |
| --- | --- |
| NotConnected | No verified connected profiles, grey on Linux |
| Connecting | A profile is starting, authenticating, configuring, stopping, or backing off |
| Connected | All wanted profiles are connected, green on Linux |
| Partial | Some profiles are connected, others are not |
| Attention | A failed profile, password prompt, or certificate needs attention |

Linux progress and attention states use amber; partial connectivity uses a
green partial ring. The tooltip lists
connected profiles and reports helper unavailability. Connecting can animate
only when both **Animate icon** and the desktop motion setting permit it;
unknown motion policy disables animation. The checkbox persists and takes
effect live. Optional notifications cover connect, disconnect, and failure.

User preferences are `~/Library/Application Support/fortix/config.json` on
macOS and `$XDG_CONFIG_HOME/fortix/config.json` on Linux (default
`~/.config/fortix/config.json`). The directory is private and the file is
`0600`. Missing values default to true:

```json
{ "remember_passwords": true, "animate_icon": true, "notifications": true }
```

```sh
fortix-tray autostart enable
fortix-tray autostart disable
```

These write/remove an owned LaunchAgent or XDG autostart entry; they take
effect on the next desktop login. Disabling autostart does not stop a running
tray, and neither operation starts or stops the root helper.

## Several profiles at once

Each profile has its own openfortivpn process. Custom CIDRs are checked against
other attempts, existing routes, and connected interface subnets. Negotiation
also checks duplicate tunnel IPv4 addresses; overlapping observed pushed routes
and simultaneous full-tunnel defaults are refused. Custom routing gives the
most predictable separation. Gateway routes are only known after authentication
and openfortivpn may have installed them before the helper detects a conflict.
Do not assume a conflict check prevents every transient network change.

FortiGate's default SSL VPN address pool is often `10.212.134.200-210`.
Independent gateways using that same pool can allocate the same local address
to two tunnels. openfortivpn discovers PPP interfaces by local address, so this
is not safe to ignore: fortix refuses the second duplicate address. Ask the
VPN administrators to allocate distinct pools; changing client routes alone
does not solve the collision. Only one full tunnel can be active. IPv6 is not
routed through the VPN, so IPv6 traffic may continue outside it. There is no
kill switch or universal DNS/leak-prevention guarantee.

## Security model

The CLI and tray are unprivileged. Only the helper starts trusted executables
and changes owned network resources. The Unix control socket is `root:fortix
0660`, with peer-credential checks. Membership grants management of **all**
profiles, not per-user isolation. Profile JSON cannot express arbitrary
commands, options, or passwords. Secrets travel through the local socket and
attempt-bound pinentry relay, not files, argv, or child environment variables.
See [security](docs/security.md) for the trust boundary and disclosure process.

## Uninstall

Disable tray autostart and quit it first. For an archive/source installation:

```sh
sudo /usr/local/libexec/fortix/fortix-helper uninstall
# Also delete stored profiles:
sudo /usr/local/libexec/fortix/fortix-helper uninstall --purge
```

The helper stops the service and removes owned resources and installed files;
profiles remain unless `--purge`. User preferences, keychain passwords, and
your separately installed tray are not removed. Clear passwords with
`fortix password clear <id>` before uninstalling if desired. For a Debian
package, use `apt remove fortix` or `apt purge fortix` instead of the helper
uninstaller. Remove any tray binary you copied manually.

## Development and license

See [CONTRIBUTING](CONTRIBUTING.md) for the local gate and build matrix.
fortix is MIT licensed; see [LICENSE](LICENSE). openfortivpn is GPL-3.0 and
runs as a separate program. fortix source does not contain its implementation.
Redistributing a bundle containing openfortivpn requires its license notices
and corresponding source or a GPL-compliant source offer, plus compliance with
the licenses of its bundled libraries. Local vendoring does not change those
redistribution obligations.
