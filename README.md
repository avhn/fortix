# fortix

FortiGate SSL VPN profile manager for macOS and Linux: a tray app and a CLI
on top of [openfortivpn](https://github.com/adrienverge/openfortivpn).

- Several VPN profiles, switched with one click or one command, or kept up
  side by side when their routes do not overlap.
- Passwords remembered in the OS keychain for every profile.
- Second factor handled per profile: FortiToken push, a native code prompt, a
  TOTP seed, or a static second password.
- Local network stays reachable while connected; optional "my subnets only"
  routing.
- A small privileged helper is the only part that runs as root.

**Status: early development.** Nothing is usable yet.

## License

MIT, see [LICENSE](LICENSE). fortix runs `openfortivpn` (GPL-3.0) as a
separate program and does not include its code.
