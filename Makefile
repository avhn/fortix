GOLANGCI_LINT := github.com/golangci/golangci-lint/v2/cmd/golangci-lint@v2.14.0
GOVULNCHECK := golang.org/x/vuln/cmd/govulncheck@v1.1.4

.PHONY: build test fuzz lint vuln fmt-check check cross-build native-tray packaging-test notices-check macos-app macos-dmg

# Bound package compilation even when callers do not supply a resource budget.
export GOMAXPROCS := 2
export GOFLAGS := -p=2

MACOS_VERSION ?= $(shell git describe --tags --match 'v*' --always --dirty)
MACOS_APP ?= dist/Fortix.app
MACOS_DMG ?= dist/fortix_$(patsubst v%,%,$(MACOS_VERSION))_darwin_arm64.dmg

# Native macOS tray code requires cgo; every other target uses pure Go.
CROSS_PACKAGES = $$(go list ./... | grep -vE '/cmd/fortix-tray$$')

build:
	go build ./...

test:
	go test -race ./...

fuzz:
	go test ./internal/profile -run '^$$' -fuzz '^FuzzDecode$$' -parallel 1 -fuzztime 20s

lint:
	go run $(GOLANGCI_LINT) run

vuln:
	go run $(GOVULNCHECK) ./...

fmt-check:
	@test -z "$$(gofmt -l cmd internal)" || { gofmt -l cmd internal; exit 1; }
	go run $(GOLANGCI_LINT) fmt --diff

# Build one target at a time, omitting only the native macOS tray command.
cross-build:
	@set -e; for os in darwin linux; do \
		for arch in amd64 arm64; do \
			echo "Cross-build $$os/$$arch"; \
			if [ "$$os" = darwin ]; then \
				GOOS=$$os GOARCH=$$arch CGO_ENABLED=0 go build $(CROSS_PACKAGES); \
			else \
				GOOS=$$os GOARCH=$$arch CGO_ENABLED=0 go build ./...; \
			fi; \
		done; \
	done

# Link the macOS tray using the runner's native SDK without leaving a binary behind.
native-tray:
	CGO_ENABLED=1 go build -o /dev/null ./cmd/fortix-tray

# Keep prerequisites serial even when the caller enables make's job pool.
check:
	$(MAKE) fmt-check
	$(MAKE) lint
	$(MAKE) test
	$(MAKE) packaging-test
	$(MAKE) notices-check

# Packaging tests use fixtures only and never execute privileged installer commands.
packaging-test:
	bash scripts/test-packaging.sh

# Fail when linked dependency versions or their upstream license texts change.
notices-check:
	bash scripts/generate-notices.sh --check

# Build outputs refuse replacement; choose a fresh path for repeated local builds.
macos-app:
	bash scripts/build-macos-app.sh "$(MACOS_VERSION)" "$(MACOS_APP)"

# Package and verify an already built app without installing or launching it.
macos-dmg:
	bash scripts/build-dmg.sh "$(MACOS_APP)" "$(MACOS_DMG)"
	bash scripts/verify-macos-package.sh "$(MACOS_APP)" "$(MACOS_DMG)"
