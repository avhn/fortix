# Contributing

Keep changes small, preserve working behavior, and include focused regression
tests. Use the Go version declared in `go.mod`; pinned lint and vulnerability
tools run through the Makefile rather than global installations.

## Local checks

Run one Go test/build operation at a time with bounded compiler concurrency:

```sh
GOMAXPROCS=2 GOFLAGS=-p=2 make check
GOMAXPROCS=2 GOFLAGS=-p=2 make cross-build
# On a macOS host with Xcode Command Line Tools:
GOMAXPROCS=2 GOFLAGS=-p=2 make native-tray
```

`make check` runs formatting checks, pinned golangci-lint, and `go test -race`
serially. `make cross-build` builds darwin/linux for amd64/arm64 with cgo off;
only the native macOS tray command is excluded for Darwin. The adapter
package is built with its non-cgo stub.
Linux includes the tray without cgo. `make native-tray` verifies native macOS
linking. CI checks on macOS and Linux and performs the native tray build on its
macOS runner. Do not treat a cross-build as a test on the target OS.

Add table-driven success and failure cases for changed behavior and fuzz targets
for parsers. Existing fuzz targets run their seed cases under the normal test
gate. For a sustained smoke run, select a single target at a time:

```sh
GOMAXPROCS=2 GOFLAGS=-p=2 go test ./internal/profile -run '^$' -fuzz '^FuzzDecode$' -fuzztime 20s
GOMAXPROCS=2 GOFLAGS=-p=2 go test ./internal/helpercmd -run '^$' -fuzz '^FuzzInstallationOptions$' -fuzztime 20s
```

Scheduled/manual vulnerability checks are available with
`GOMAXPROCS=2 GOFLAGS=-p=2 make vuln`. They are periodic diagnostics, not a
release gate.

Tests must run unprivileged: inject command runners, clocks, dialogs, sockets,
keyrings, and isolated paths. Never connect a unit/integration test to a real
VPN or change the host routing table, DNS, `/etc`, or `/Library`. Native desktop
and real-gateway acceptance require explicit, separately authorized manual
testing. Use `vpn.example.com`, `jane.doe`, `10.20.0.0/16`, and
`corp.example.com` in fixtures and documentation, never real infrastructure or
credentials. Test failures must not print secrets.

## Code and documentation

Executable entry points belong under `cmd/` and only wire internal packages.
Keep root helper code independent of GUI and keychain code. Every Go declaration
needs a useful Go doc comment describing purpose and relevant inputs, outputs,
and failure behavior. Use brief inline comments for non-obvious ownership,
ordering, and security steps. Format with gofmt and the configured goimports.
Avoid unnecessary dependencies and keep public examples self-contained.

Update the README, profile schema reference, and security documentation when a
behavior or boundary changes. State limitations rather than claiming unsupported
features. Use plain hyphens, not typographic em/en dash characters. Follow the
[security reporting guidance](docs/security.md) for vulnerabilities instead of
public issues with exploit details.

## Commits

Commits must be conventional and signed, for example:

```sh
git commit -S -m 'fix(tray): discard obsolete credential replies'
```

Use lowercase `type(scope): summary`, no trailing period, and concise body
lines. Do not add co-author trailers. Do not bypass signature requirements or
publish unverified changes. Run the local checks before submitting changes.
