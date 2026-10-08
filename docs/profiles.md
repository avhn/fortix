# Profiles

Profiles are secret-free JSON objects in schema version 1. The CLI validates
local drafts; the helper independently validates and stores them through the
control socket. All authorized `fortix` group members can manage every profile.
There is no per-user owner field and no administrator approval for each edit.

## Storage and validation

Use `fortix profile validate <file>` before `fortix profile add <file>`.
`profile add` creates or replaces a stored inactive profile; an active profile
cannot be replaced or deleted. Local edits do not affect the stored copy until
added again. `profile show <id>` prints that copy and `profile rm <id>` (or `profile remove <id>`) removes
an inactive copy.

Stored profiles are `root:fortix 0640` files in a `root:fortix 0750` directory under:

- macOS: `/Library/Application Support/fortix/profiles/`
- Linux: `/etc/fortix/profiles/`

The helper refuses symlinks, unsafe ownership/modes, traversal, and non-regular
files. Drafts can be kept wherever the user chooses, but should not contain
secrets. Stored usernames and gateway names are configuration, not encrypted
personal data, but stored copies are readable only by root and fortix members.

The decoder accepts one object of at most 64 KiB, with no trailing JSON,
unknown fields, duplicate keys (including nested keys), or null values.
Passwords, second-factor seeds, arbitrary openfortivpn options, and executable
paths have no schema fields and are rejected.

## Full field reference

| Field | Type and constraints | Default |
| --- | --- | --- |
| `schema_version` | Integer, exactly `1` | Required |
| `id` | Lowercase ASCII letter/digit first, then letters/digits/hyphens, 1..63 characters | Required |
| `name` | Valid UTF-8, 1..64 characters, no control characters | Required |
| `backend` | Exactly `openfortivpn` | Required |
| `gateway.host` | DNS hostname or unscoped IP literal; no URL scheme, path, or port suffix | Required |
| `gateway.port` | Integer, 1..65535 | `443` when omitted or zero |
| `realm` | At most 64 ASCII letters, digits, dots, underscores, or hyphens | Empty |
| `username` | UTF-8, 1..256 characters, no controls or whitespace at either end | Required |
| `trusted_cert` | Read-only through the helper; SHA-256 digest, 64 hexadecimal characters; case and colon separators normalize | Empty |
| `mfa.mode` | `none`, `push`, `prompt`, `totp`, or `static` | `none` |
| `mfa.digits` | `6` or `8`, allowed only for `totp` | `6` for `totp` |
| `mfa.period` | Integer seconds, 15..120, allowed only for `totp` | `30` for `totp` |
| `mfa.algorithm` | `SHA1`, `SHA256`, or `SHA512`, allowed only for `totp` | `SHA1` for `totp` |
| `routes.mode` | `gateway`, `custom`, or `full` | `gateway` |
| `routes.include` | Nonempty list of canonical, masked IPv4 CIDRs; /8..32; no duplicate/overlapping entries; allowed only for `custom` | Absent |
| `routes.preserve_lan` | Boolean; explicit false is preserved | `true` |
| `dns.mode` | `none` or `split` | `none` |
| `dns.domains` | 1..32 lowercase DNS names with at least two labels, without wildcard/trailing dot or duplicates; allowed only for `split` | Absent |

Hostnames use ASCII DNS labels, at most 63 characters per label and 253 total,
with no leading/trailing label hyphen. IP address literals must not contain a
zone identifier. Do not include `https://` in a gateway host.

Objects whose fields all have defaults can be omitted. `gateway` must still
supply a host. `routes.include` and `dns.domains` must be **absent**, not empty
arrays, when their modes do not allow them. Non-TOTP modes forbid all TOTP
parameters, including explicit zero values. `routes.preserve_lan: null` is
invalid, not an instruction to use the default.

### MFA behavior

`none` is appropriate for password-only accounts. An unexpected code challenge
still gets a hidden prompt. `push` allows openfortivpn's FortiToken push path;
other modes pass `--no-ftm-push`. The UI does not claim that a push was delivered.

`prompt`, `totp`, and `static` currently all use hidden code input when a code
challenge arrives. TOTP generation and dedicated second-secret/seed keyring
management are not wired into the clients, even though their schema parameters
are validated. Do not put these secrets in JSON. Saving a password is governed
by user preferences or CLI `--save`, not by a profile field.

### Routes and DNS behavior

`custom` disables openfortivpn route installation and installs only included
IPv4 prefixes on the tunnel link. `gateway` and `full` enable openfortivpn's
route handling, but `gateway` rejects default and split-default routes pushed
on its own tunnel link. Use `full` to allow those routes. `full` does not
independently synthesize a default route if
the gateway does not provide one. Only one full tunnel can be reserved at once.

`preserve_lan` is accepted and defaults to true but does not yet add LAN bypass
routes. Existing connected routes remain intact under custom routing; pushed
routes and full-tunnel behavior depend on the gateway and platform. Do not
assume this field alone guarantees LAN reachability.

Openfortivpn and PPP DNS writers are disabled in all modes. With `split`, the
helper uses negotiated DNS servers: owned `/etc/resolver/<domain>` files on
macOS, and per-link `resolvectl dns`/`domain` settings on Linux. On macOS a
domain already owned by another profile is a conflict. `none` leaves DNS
unmanaged; it does not prevent other applications or the OS from resolving
names. IPv6 VPN routing and universal leak prevention are not supported.

## Examples

### Password-only custom routing and split DNS

```json
{
  "schema_version": 1,
  "id": "work",
  "name": "Work",
  "backend": "openfortivpn",
  "gateway": { "host": "vpn.example.com", "port": 10443 },
  "realm": "staff",
  "username": "jane.doe",
  "mfa": { "mode": "none" },
  "routes": {
    "mode": "custom",
    "include": ["10.20.0.0/16"],
    "preserve_lan": true
  },
  "dns": { "mode": "split", "domains": ["corp.example.com"] }
}
```

### Minimal gateway-routing profile

```json
{
  "schema_version": 1,
  "id": "work",
  "name": "Work",
  "backend": "openfortivpn",
  "gateway": { "host": "vpn.example.com" },
  "username": "jane.doe"
}
```

### Push approval and explicit full-tunnel intent

```json
{
  "schema_version": 1,
  "id": "work",
  "name": "Work",
  "backend": "openfortivpn",
  "gateway": { "host": "vpn.example.com", "port": 443 },
  "username": "jane.doe",
  "mfa": { "mode": "push" },
  "routes": { "mode": "full", "preserve_lan": true },
  "dns": { "mode": "none" }
}
```

## Certificate trust and import

A successful system-certificate check needs no explicit pin. If certificate
validation fails, fortix displays the captured digest, subject, and issuer.
Verify those with the VPN administrator before confirming. `fortix trust <id>`
or the tray's confirmation sends the captured digest back to the helper. The
helper accepts only its last rejected digest for that profile, stores it as
`trusted_cert`, and immediately starts a new attempt. A changed certificate
requires a new confirmation. `profile add` preserves the existing helper-owned
pin and ignores any submitted `trusted_cert`; it cannot set or replace a pin.
Removing a profile and adding it again clears its stored pin.

`fortix import forticlient [--plist path]` previews non-secret drafts read from
FortiClient's macOS plist. `--apply` stores the displayed drafts. Import does
not decrypt or copy saved FortiClient passwords and never modifies its source.
